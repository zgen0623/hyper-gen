#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/vmacache.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/spinlock.h>
#include <linux/module.h>
#include <linux/export.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/sched/stat.h>
#include <asm/processor.h>
#include <asm/cpu.h>
#include <linux/kvm_host.h>
#include <linux/pci_ids.h>
#include "kvm_cache_regs.h"
#include "x86.h"
#include "irq.h"
#include "mmu.h"
#include "kvm_cache_regs.h"
#include "machine.h"
#include "vpci.h"
#include "vser.h"
#include <uapi/linux/serial_reg.h>
#include <linux/syscalls.h>

//#define PRINTK_TEST
//#define TIMER_TEST
#define SERIAL_BASE_ADDR 0x3f8
#define SERIAL_IRQ_GSI 4
#define NANOSECONDS_PER_SECOND 1000000000LL
#define UART_FIFO_LENGTH    16 
#define UART_IIR_FENF   UART_FCR_R_TRIG_10    /* Fifo enabled, but not functionning */
#define UART_IIR_FE     UART_FCR_R_TRIG_11    /* Fifo enabled */

#define TX_BUF_SIZE PAGE_SIZE

int my_start = 0;
uint64_t my_mark = 0;

typedef int (*tx_fn_t)(void *opaque, char *buf, int len);

static void timer_test(struct kvm *kvm);

typedef struct { 
    /* All fields are private */
    uint8_t *data;
    uint32_t capacity;
    uint32_t head;
    uint32_t num;
} Fifo8;

struct vserial {
    uint16_t divider;
    uint8_t rbr; /* receive register */
    uint8_t thr; /* transmit holding register */
    uint8_t tsr; /* transmit shift register */
    uint8_t ier;
    uint8_t iir; /* read only */
    uint8_t lcr;
    uint8_t mcr;
    uint8_t lsr; /* read only */
    uint8_t msr; /* read only */
    uint8_t scr;
    uint8_t fcr;
    uint8_t fcr_vmstate; /* we can't write directly this value
                            it has side effects */
    /* NOTE: this hidden state is necessary for tx irq generation as
       it can be reset while reading iir */
    int thr_ipending;
    int last_break_enable;
    int it_shift;
    int baudbase;

    /* Time when the last byte was successfully sent out of the tsr */
    uint64_t last_xmit_ts;
    Fifo8 recv_fifo;
    Fifo8 xmit_fifo;
    /* Interrupt trigger level for recv_fifo */
    uint8_t recv_fifo_itl;

	struct hrtimer fifo_timeout_timer;
    int timeout_ipending;           /* timeout interrupt pending state */

    uint64_t char_transmit_time;    /* time to transmit a char in ticks */

	struct kvm_io_device dev;

	struct kvm *kvm;

#if 0
	void *rx_buf;
#endif
	uint8_t *tx_buf;
	int tx_put_idx;
	int tx_get_idx;

	wait_queue_head_t rx_wq_head;
	wait_queue_head_t tx_wq_head;
	int log_fd;
};

//struct file *fget(unsigned int fd);
void attach_to_vser(struct kvm *kvm,
			wait_queue_entry_t *tx_wait,
			wait_queue_entry_t *rx_wait)
{
    struct vserial *vser = kvm->vdevices.vserial;

	kvm_get_kvm(kvm);

	add_wait_queue(&vser->rx_wq_head, rx_wait);
	add_wait_queue(&vser->tx_wq_head, tx_wait);

	printk(">>>%s:%d tx_get_idx=%d tx_put_idx=%d\n",
		__func__, __LINE__, vser->tx_get_idx, vser->tx_put_idx);

	if (vser->tx_get_idx != vser->tx_put_idx)
		wake_up(&vser->tx_wq_head);
}

void deattach_to_vser(struct kvm *kvm,
			wait_queue_entry_t *tx_wait,
			wait_queue_entry_t *rx_wait)
{
    struct vserial *vser = kvm->vdevices.vserial;

	remove_wait_queue(&vser->rx_wq_head, rx_wait);
	remove_wait_queue(&vser->tx_wq_head, tx_wait);

	kvm_put_kvm(kvm);
}

#if 0
void *get_vserial_tx_buf(struct vserial *vser)
{
	return vser->tx_buf;
}

void *get_vserial_rx_buf(struct vserial *vser)
{
	return vser->rx_buf;
}
#endif

static void fifo8_destroy(Fifo8 *fifo)
{   
    kfree(fifo->data);
}

static void fifo8_create(Fifo8 *fifo, uint32_t capacity) 
{
    fifo->data = kzalloc(capacity, GFP_KERNEL);
    fifo->capacity = capacity;
    fifo->head = 0;
    fifo->num = 0;
}

static void fifo8_reset(Fifo8 *fifo) 
{
    fifo->num = 0;
    fifo->head = 0;
}

static void serial_reset(struct vserial *s)
{
    s->rbr = 0;
    s->ier = 0;
    s->iir = UART_IIR_NO_INT;
    s->lcr = 0;
    s->lsr = UART_LSR_TEMT | UART_LSR_THRE;
    s->msr = UART_MSR_DCD | UART_MSR_DSR | UART_MSR_CTS;
    /* Default to 9600 baud, 1 start bit, 8 data bits, 1 stop bit, no parity. */
    s->divider = 0x0C;
    s->mcr = UART_MCR_OUT2;
    s->scr = 0;
    s->char_transmit_time = (NANOSECONDS_PER_SECOND / 9600) * 10;

    s->timeout_ipending = 0;
	hrtimer_cancel(&s->fifo_timeout_timer);

    fifo8_reset(&s->recv_fifo);
    fifo8_reset(&s->xmit_fifo);

	s->last_xmit_ts = ktime_get();

    s->thr_ipending = 0;
    s->last_break_enable = 0;

	kvm_set_irq(s->kvm, KVM_USERSPACE_IRQ_SOURCE_ID,
                    SERIAL_IRQ_GSI, 0, 1);

    s->msr &= ~UART_MSR_ANY_DELTA;

    s->baudbase = 115200;
}

static void serial_update_parameters(struct vserial *s)
{   
    uint32_t speed;
    int data_bits, stop_bits, frame_size;
    
    /* Start bit. */
    frame_size = 1;
    if (s->lcr & 0x08) {
        /* Parity bit. */
        frame_size++;
    }
    
    if (s->lcr & 0x04) {
        stop_bits = 2;
    } else {
        stop_bits = 1;
    }
    
    data_bits = (s->lcr & 0x03) + 5;
    frame_size += data_bits + stop_bits;

    /* Zero divisor should give about 3500 baud */
    speed = (s->divider == 0) ? 3500 : s->baudbase / s->divider;
    s->char_transmit_time =  (NANOSECONDS_PER_SECOND / speed) * frame_size;
}

static bool fifo8_is_empty(Fifo8 *fifo)
{           
    return (fifo->num == 0);
}           
            
static bool fifo8_is_full(Fifo8 *fifo)
{               
    return (fifo->num == fifo->capacity);
} 

static uint8_t fifo8_pop(Fifo8 *fifo)
{
    uint8_t ret;

    if (fifo->num == 0)
		panic(">>>error %s:%d\n", __func__, __LINE__);

    ret = fifo->data[fifo->head++];
    fifo->head %= fifo->capacity;
    fifo->num--;
    return ret;
}

static void fifo8_push(Fifo8 *fifo, uint8_t data)
{
    if (fifo->num == fifo->capacity)
		panic(">>>error %s:%d\n", __func__, __LINE__);

    fifo->data[(fifo->head + fifo->num) % fifo->capacity] = data;
    fifo->num++;
}

static inline void recv_fifo_put(struct vserial *s, uint8_t chr)
{
    /* Receive overruns do not overwrite FIFO contents. */
    if (!fifo8_is_full(&s->recv_fifo)) {
        fifo8_push(&s->recv_fifo, chr);
    } else {
        s->lsr |= UART_LSR_OE;
    }
}
    
static void serial_update_irq(struct vserial *s)
{
    uint8_t tmp_iir = UART_IIR_NO_INT;

    if ((s->ier & UART_IER_RLSI) && (s->lsr & UART_LSR_BRK_ERROR_BITS)) {
        tmp_iir = UART_IIR_RLSI;
    } else if ((s->ier & UART_IER_RDI) && s->timeout_ipending) {
        /* Note that(s->ier & UART_IER_RDI) can mask this interrupt,
         * this is not in the specification but is observed on existing
         * hardware.  */
        tmp_iir = UART_IIR_RX_TIMEOUT;
    } else if ((s->ier & UART_IER_RDI) && (s->lsr & UART_LSR_DR) &&
               (!(s->fcr & UART_FCR_ENABLE_FIFO) ||
                s->recv_fifo.num >= s->recv_fifo_itl)) {
        tmp_iir = UART_IIR_RDI;
    } else if ((s->ier & UART_IER_THRI) && s->thr_ipending) {
        tmp_iir = UART_IIR_THRI;
    } else if ((s->ier & UART_IER_MSI) && (s->msr & UART_MSR_ANY_DELTA)) {
        tmp_iir = UART_IIR_MSI;
    }
    
    s->iir = tmp_iir | (s->iir & 0xF0);
    
    if (tmp_iir != UART_IIR_NO_INT)
		kvm_set_irq(s->kvm, KVM_USERSPACE_IRQ_SOURCE_ID,
                    SERIAL_IRQ_GSI, 1, 1);
    else
		kvm_set_irq(s->kvm, KVM_USERSPACE_IRQ_SOURCE_ID,
                    SERIAL_IRQ_GSI, 0, 1);
} 

int vser_can_receive(struct kvm *kvm)
{
    struct vserial *s = kvm->vdevices.vserial;

    if(s->fcr & UART_FCR_ENABLE_FIFO) {
        if (s->recv_fifo.num < UART_FIFO_LENGTH)
            /*
             * Advertise (fifo.itl - fifo.count) bytes when count < ITL, and 1
             * if above. If UART_FIFO_LENGTH - fifo.count is advertised the
             * effect will be to almost always fill the fifo completely before
             * the guest has a chance to respond, effectively overriding the ITL
             * that the guest has set.
             */
            return (s->recv_fifo.num <= s->recv_fifo_itl) ?
                        s->recv_fifo_itl - s->recv_fifo.num : 1;
        else
            return 0;
    } else
        return !(s->lsr & UART_LSR_DR);
}


static void serial_receive(void *opaque, const uint8_t *buf, int size)
{
    struct vserial *s = opaque;

    if(s->fcr & UART_FCR_ENABLE_FIFO) {
        int i;
        for (i = 0; i < size; i++)
            recv_fifo_put(s, buf[i]);

        s->lsr |= UART_LSR_DR;
        /* call the timeout receive callback in 4 char transmit time */
		hrtimer_start(&s->fifo_timeout_timer, ktime_add_ns(ktime_get(), s->char_transmit_time * 4),
		      HRTIMER_MODE_ABS);
    } else {
        if (s->lsr & UART_LSR_DR)
            s->lsr |= UART_LSR_OE;
        s->rbr = buf[0];
        s->lsr |= UART_LSR_DR;
    }

    serial_update_irq(s);
}

void vser_receive(struct kvm *kvm, const uint8_t *buf, int size)
{
    struct vserial *s = kvm->vdevices.vserial;

	serial_receive(s, buf, size);
}

void vser_xmit(struct kvm *kvm, int fd)
{
    struct vserial *vser = kvm->vdevices.vserial;

	if (vser->tx_get_idx == vser->tx_put_idx)
		return;

	while (1) {
		char c = vser->tx_buf[vser->tx_get_idx];

		sys_write(fd, (const char __user *)&c, 1);

		if (vser->log_fd >= 0)
			sys_write(vser->log_fd, (const char __user *)&c, 1); 

		vser->tx_get_idx =
				(vser->tx_get_idx + 1) % TX_BUF_SIZE;

		if (vser->tx_get_idx == vser->tx_put_idx)
			break;
	}
}

static int vser_tx(struct vserial *vser, uint8_t *buf, int len)
{
	int ret = 0;
//	int fd;
	int i;

#if 0
	if (s->tx_fn) {
		ret = s->tx_fn(s->tx_fn_opaque, (char *)buf, len);
		if (ret <= 0)
			printk("%s:%d ret=%d\n", __func__, __LINE__, ret);
	}
#endif

	for (i = 0; i < len; i++) {
		vser->tx_buf[vser->tx_put_idx] = buf[i];

		vser->tx_put_idx =
			(vser->tx_put_idx + 1) % TX_BUF_SIZE;

		if (vser->tx_put_idx == vser->tx_get_idx)
			vser->tx_get_idx =
				(vser->tx_get_idx + 1) % TX_BUF_SIZE;
	}
  
	if (waitqueue_active(&vser->tx_wq_head))
		wake_up(&vser->tx_wq_head);

	return ret;
}

static void serial_xmit(struct vserial *s)
{
    do {
        if (s->fcr & UART_FCR_ENABLE_FIFO) {
            s->tsr = fifo8_pop(&s->xmit_fifo);
            if (!s->xmit_fifo.num)
                s->lsr |= UART_LSR_THRE;
        } else {
            s->tsr = s->thr;
            s->lsr |= UART_LSR_THRE;
        }

        if ((s->lsr & UART_LSR_THRE) && !s->thr_ipending) {
            s->thr_ipending = 1;
            serial_update_irq(s);
        }

        if (s->mcr & UART_MCR_LOOP) {
            /* in loopback mode, say that we just received a char */
            serial_receive(s, &s->tsr, 1);
        } else {
          //  int rc = qemu_chr_fe_write(&s->chr, &s->tsr, 1);
			int rc = vser_tx(s, &s->tsr, 1);
#if 0
            if (rc <= 0)
                printk(">>>%s:%d\n", __func__, __LINE__);
#endif
        }

        /* Transmit another byte if it is already available. It is only
           possible when FIFO is enabled and not empty. */
    } while (!(s->lsr & UART_LSR_THRE));

	s->last_xmit_ts = ktime_get();
    s->lsr |= UART_LSR_TEMT;
}

static void serial_write_fcr(struct vserial *s, uint8_t val)
{
    /* Set fcr - val only has the bits that are supposed to "stick" */
    s->fcr = val;

    if (val & UART_FCR_ENABLE_FIFO) {
        s->iir |= UART_IIR_FE;
        /* Set recv_fifo trigger Level */
        switch (val & 0xC0) {
        case UART_FCR_R_TRIG_00:
            s->recv_fifo_itl = 1;
            break;
        case UART_FCR_R_TRIG_01:
            s->recv_fifo_itl = 4;
            break;
        case UART_FCR_R_TRIG_10:
            s->recv_fifo_itl = 8;
            break;
        case UART_FCR_R_TRIG_11:
            s->recv_fifo_itl = 14;
            break;
        }
    } else {
        s->iir &= ~UART_IIR_FE;
    }
}



static int vser_write(struct kvm_vcpu *vcpu, struct kvm_io_device *dev,
			       gpa_t addr, int len, const void *buf)
{
	struct vserial *s = container_of(dev, struct vserial, dev);
	uint32_t offset = addr - SERIAL_BASE_ADDR;	
	uint16_t val;

	if (len == 1)
		val = *(uint8_t*)buf;
	else
		val = *(uint16_t*)buf;

	offset &= 7;

    switch(offset) {
    default:
    case 0:
        if (s->lcr & UART_LCR_DLAB) {
            if (len == 1) {
                s->divider = (s->divider & 0xff00) | val;
            } else {
                s->divider = val;
            }
            serial_update_parameters(s);
        } else {
            s->thr = (uint8_t) val;
            if(s->fcr & UART_FCR_ENABLE_FIFO) {
                /* xmit overruns overwrite data, so make space if needed */
                if (fifo8_is_full(&s->xmit_fifo)) {
                    fifo8_pop(&s->xmit_fifo);
                }
                fifo8_push(&s->xmit_fifo, s->thr);
            }
            s->thr_ipending = 0;
            s->lsr &= ~UART_LSR_THRE;
            s->lsr &= ~UART_LSR_TEMT;
            serial_update_irq(s);

            serial_xmit(s);
        }
        break;
    case 1:
        if (s->lcr & UART_LCR_DLAB) {
            s->divider = (s->divider & 0x00ff) | (val << 8);
            serial_update_parameters(s);
        } else {
            uint8_t changed = (s->ier ^ val) & 0x0f;
            s->ier = val & 0x0f;
            /* Turning on the THRE interrupt on IER can trigger the interrupt
             * if LSR.THRE=1, even if it had been masked before by reading IIR.
             * This is not in the datasheet, but Windows relies on it.  It is
             * unclear if THRE has to be resampled every time THRI becomes
             * 1, or only on the rising edge.  Bochs does the latter, and Windows
             * always toggles IER to all zeroes and back to all ones, so do the
             * same.
             *
             * If IER.THRI is zero, thr_ipending is not used.  Set it to zero
             * so that the thr_ipending subsection is not migrated.
             */
            if (changed & UART_IER_THRI) {
                if ((s->ier & UART_IER_THRI) && (s->lsr & UART_LSR_THRE))
                    s->thr_ipending = 1;
                else
                    s->thr_ipending = 0;
            }

            if (changed)
                serial_update_irq(s);
        }
        break;
    case 2:
        /* Did the enable/disable flag change? If so, make sure FIFOs get flushed */
        if ((val ^ s->fcr) & UART_FCR_ENABLE_FIFO)
            val |= UART_FCR_CLEAR_XMIT | UART_FCR_CLEAR_RCVR;

        /* FIFO clear */

        if (val & UART_FCR_CLEAR_RCVR) {
            s->lsr &= ~(UART_LSR_DR | UART_LSR_BI);
           // timer_del(s->fifo_timeout_timer);
			hrtimer_cancel(&s->fifo_timeout_timer);
            s->timeout_ipending = 0;
            fifo8_reset(&s->recv_fifo);
        }

        if (val & UART_FCR_CLEAR_XMIT) {
            s->lsr |= UART_LSR_THRE;
            s->thr_ipending = 1;
            fifo8_reset(&s->xmit_fifo);
        }

        serial_write_fcr(s, val & 0xC9);
        serial_update_irq(s);
        break;
    case 3:
        {
            int break_enable;
            s->lcr = val;
            serial_update_parameters(s);
            break_enable = (val >> 6) & 1;
            if (break_enable != s->last_break_enable) {
                s->last_break_enable = break_enable;
            }
        }
        break;
    case 4:
        {
            s->mcr = val & 0x1f;
            if (val & UART_MCR_LOOP)
                break;
        }
        break;
    case 5:
        break;
    case 6:
        break;
    case 7:
        s->scr = val;
        break;
    }

	return 0;
}

static int vser_read(struct kvm_vcpu *vcpu, struct kvm_io_device *dev,
			      gpa_t addr, int len, void *buf)
{
	struct vserial *s = container_of(dev, struct vserial, dev);
	uint32_t offset = addr - SERIAL_BASE_ADDR;	
	uint8_t val;

    offset &= 7;
    switch(offset) {
    default:
    case 0:
        if (s->lcr & UART_LCR_DLAB) {
            val = s->divider & 0xff;
        } else {
            if(s->fcr & UART_FCR_ENABLE_FIFO) {
                val = fifo8_is_empty(&s->recv_fifo) ?
                            0 : fifo8_pop(&s->recv_fifo);
                
                if (s->recv_fifo.num == 0)
                    s->lsr &= ~(UART_LSR_DR | UART_LSR_BI);
                else
					hrtimer_start(&s->fifo_timeout_timer,
						ktime_add_ns(ktime_get(), s->char_transmit_time * 4),
		      			HRTIMER_MODE_ABS);

                s->timeout_ipending = 0;
            } else {
                val = s->rbr;
                s->lsr &= ~(UART_LSR_DR | UART_LSR_BI);
            }

            serial_update_irq(s);

            if (!(s->mcr & UART_MCR_LOOP)) {
                /* in loopback mode, don't receive any data */
				if (waitqueue_active(&s->rx_wq_head))
					wake_up(&s->rx_wq_head);
			}
        }
        break;
    case 1:
        if (s->lcr & UART_LCR_DLAB) {
            val = (s->divider >> 8) & 0xff;
        } else {
            val = s->ier;
        }
        break;
    case 2:
        val = s->iir;
        if ((val & UART_IIR_ID) == UART_IIR_THRI) {
            s->thr_ipending = 0;
            serial_update_irq(s);
        }
        break;
    case 3:
        val = s->lcr;
        break;
    case 4:
        val = s->mcr;
        break;
    case 5:
        val = s->lsr;
        /* Clear break and overrun interrupts */
        if (s->lsr & (UART_LSR_BI|UART_LSR_OE)) {
            s->lsr &= ~(UART_LSR_BI|UART_LSR_OE);
            serial_update_irq(s);
        }
        break;
    case 6:
        if (s->mcr & UART_MCR_LOOP) {
            /* in loopback, the modem output pins are connected to the
               inputs */
            val = (s->mcr & 0x0c) << 4;
            val |= (s->mcr & 0x02) << 3;
            val |= (s->mcr & 0x01) << 5;
        } else {
            val = s->msr;
            /* Clear delta bits & msr int after read, if they were set */
            if (s->msr & UART_MSR_ANY_DELTA) {
                s->msr &= 0xF0;
                serial_update_irq(s);
            }
        }
        break;
    case 7:
        val = s->scr;
        break;
    }

	*(uint8_t*)buf = val;

	return 0;
}

static const struct kvm_io_device_ops vser_ops = {
	.read     = vser_read,
	.write    = vser_write,
};

static enum hrtimer_restart fifo_timeout_int(struct hrtimer *data)
{
    //SerialState *s = opaque;
	struct vserial *s = container_of(data, struct vserial, fifo_timeout_timer);

    if (s->recv_fifo.num) {
        s->timeout_ipending = 1;
        serial_update_irq(s);
    }

	return HRTIMER_NORESTART;
}

void create_vserial(struct kvm *kvm)
{
    struct vserial *vser;
	struct page *page;
	int ret;

	vser = kzalloc(sizeof(struct vserial), GFP_KERNEL);
	if (!vser) {
		printk(">>>>>error %s:%d\n", __func__, __LINE__);
		return;
	}

	vser->tx_buf = kmalloc(TX_BUF_SIZE, GFP_KERNEL);;
	if (!vser->tx_buf) {
		printk(">>>>>error %s:%d\n", __func__, __LINE__);
		return;
	}

	vser->tx_put_idx = vser->tx_get_idx = 0;

#if 0
	page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (page)
		vser->tx_buf = page_address(page);
	else
		printk(">>>>%s:%d\n", __func__, __LINE__);

	page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (page)
		vser->rx_buf = page_address(page);
	else
		printk(">>>>%s:%d\n", __func__, __LINE__);

	kvm->gen_shm->vser_info.tx_buf_offset = PAGE_SIZE;
	kvm->gen_shm->vser_info.tx_put_idx = 0;
	kvm->gen_shm->vser_info.tx_get_idx = 0;
	kvm->gen_shm->vser_info.rx_buf_offset = PAGE_SIZE + PAGE_SIZE;
	kvm->gen_shm->vser_info.rx_put_idx = 0;
	kvm->gen_shm->vser_info.rx_get_idx = 0;
#endif


	hrtimer_init(&vser->fifo_timeout_timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS);
	vser->fifo_timeout_timer.function = fifo_timeout_int;

    fifo8_create(&vser->recv_fifo, UART_FIFO_LENGTH);
    fifo8_create(&vser->xmit_fifo, UART_FIFO_LENGTH);

	kvm_iodevice_init(&vser->dev, &vser_ops);

	mutex_lock(&kvm->slots_lock);
	ret = kvm_io_bus_register_dev(kvm, KVM_PIO_BUS, SERIAL_BASE_ADDR, 8,
				      &vser->dev);
	if (ret < 0)
		printk(">>>>>error %s:%d\n", __func__, __LINE__);

	mutex_unlock(&kvm->slots_lock);

	init_waitqueue_head(&vser->rx_wq_head);
	init_waitqueue_head(&vser->tx_wq_head);
//	atomic_set(&vser->tx_fd, -1);
//	vser->tx_fd = -1;

//	vser->tx_fn = NULL;
	char buf[32];
	sprintf(buf, "/logs/vm%llu", kvm->id);

	vser->log_fd = 
		sys_open((const char __user *)buf, O_WRONLY|O_CREAT, 0664);

	vser->kvm = kvm;
	kvm->vdevices.vserial = vser;

    serial_reset(vser);


#if 0
	timer_test(kvm);
#endif

#ifdef PRINTK_TEST
	my_start = 1;
	printk(">>>>%s:%d\n", __func__, __LINE__);
	my_start = 0;
	printk(">>>>%s:%d my_mark=%lx\n", __func__, __LINE__, my_mark);
#endif
}

void destroy_vserial(struct kvm *kvm)
{
    struct vserial *vser = kvm->vdevices.vserial;

	if (!vser)
		return;

	if (vser->tx_buf)
		kfree(vser->tx_buf);
#if 0
	if (vser->tx_buf)
		free_page((unsigned long)vser->tx_buf);

	if (vser->rx_buf)
		free_page((unsigned long)vser->tx_buf);
#endif

	hrtimer_cancel(&vser->fifo_timeout_timer);

#if 0
	hrtimer_cancel(&poll_test.poll_timer);
#endif

	mutex_lock(&kvm->slots_lock);
	kvm_io_bus_unregister_dev(kvm, KVM_PIO_BUS, &vser->dev);
	mutex_unlock(&kvm->slots_lock);

    fifo8_destroy(&vser->recv_fifo);
    fifo8_destroy(&vser->xmit_fifo);

	if (vser->log_fd >= 0) {
		sys_fsync(vser->log_fd); 
		sys_close(vser->log_fd); 
	}

	kfree(vser);
}




#if 0
struct my_poll_test {
	struct hrtimer poll_timer;
	struct kvm *kvm;
};

static struct my_poll_test poll_test;
static int poll_cnt = 0;

static enum hrtimer_restart poll_timer_fn(struct hrtimer *data)
{
	struct my_poll_test *test = container_of(data, struct my_poll_test, poll_timer);
	struct kvm *kvm = test->kvm;
	struct gen_shm *shm = kvm->gen_shm;
	struct gen_event *gen_evt = &shm->gen_evt;

	gen_evt->evt_put_idx = (gen_evt->evt_put_idx + 1) % PAGE_SIZE;

	if (gen_evt->evt_put_idx == gen_evt->evt_get_idx)
		gen_evt->evt_get_idx = (gen_evt->evt_get_idx + 1) % PAGE_SIZE;

	//put event here

	printk(">>>>%s:%d get=%d put=%d\n", __func__, __LINE__, gen_evt->evt_get_idx, gen_evt->evt_put_idx);

	wait_queue_head_t *head = &kvm->gen_evt_wait_head;
	if (gen_evt->evt_put_idx != gen_evt->evt_get_idx && waitqueue_active(head))
		wake_up_interruptible_poll(head, POLLIN | POLLRDNORM | POLLRDBAND);

	if (poll_cnt <= 10) {
		hrtimer_add_expires_ns(&test->poll_timer, 1000*1000*1000);
		return HRTIMER_RESTART;
	} else
		return HRTIMER_NORESTART;
}

static void timer_test(struct kvm *kvm)
{
	//poll test
	poll_test.kvm = kvm;

	hrtimer_init(&poll_test.poll_timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS);
	poll_test.poll_timer.function = poll_timer_fn;
	hrtimer_start(&poll_test.poll_timer, ktime_add_ns(ktime_get(), 1000*1000*1000),
		      HRTIMER_MODE_ABS);
}
#endif

