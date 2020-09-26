#include <linux/types.h>
#include <linux/extable.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/binfmts.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/stackprotector.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/delay.h>
#include <linux/ioport.h>
#include <linux/init.h>
#include <linux/initrd.h>
#include <linux/bootmem.h>
#include <linux/acpi.h>
#include <linux/console.h>
#include <linux/nmi.h>
#include <linux/percpu.h>
#include <linux/kmod.h>
#include <linux/vmalloc.h>
#include <linux/kernel_stat.h>
#include <linux/start_kernel.h>
#include <linux/security.h>
#include <linux/smp.h>
#include <linux/profile.h>
#include <linux/rcupdate.h>
#include <linux/moduleparam.h>
#include <linux/kallsyms.h>
#include <linux/writeback.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/cgroup.h>
#include <linux/efi.h>
#include <linux/tick.h>
#include <linux/sched/isolation.h>
#include <linux/interrupt.h>
#include <linux/taskstats_kern.h>
#include <linux/delayacct.h>
#include <linux/unistd.h>
#include <linux/rmap.h>
#include <linux/mempolicy.h>
#include <linux/key.h>
#include <linux/buffer_head.h>
#include <linux/page_ext.h>
#include <linux/debug_locks.h>
#include <linux/debugobjects.h>
#include <linux/lockdep.h>
#include <linux/kmemleak.h>
#include <linux/pid_namespace.h>
#include <linux/device.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/sched/init.h>
#include <linux/signal.h>
#include <linux/idr.h>
#include <linux/kgdb.h>
#include <linux/ftrace.h>
#include <linux/async.h>
#include <linux/sfi.h>
#include <linux/shmem_fs.h>
#include <linux/slab.h>
#include <linux/perf_event.h>
#include <linux/ptrace.h>
#include <linux/pti.h>
#include <linux/blkdev.h>
#include <linux/elevator.h>
#include <linux/sched_clock.h>
#include <linux/sched/task.h>
#include <linux/sched/task_stack.h>
#include <linux/context_tracking.h>
#include <linux/random.h>
#include <linux/list.h>
#include <linux/integrity.h>
#include <linux/proc_ns.h>
#include <linux/io.h>
#include <linux/cache.h>
#include <linux/rodata_test.h>

#include <asm/io.h>
#include <asm/bugs.h>
#include <asm/setup.h>
#include <asm/sections.h>
#include <asm/cacheflush.h>
#include <linux/init_task.h>

#include <uapi/asm-generic/ioctls.h>
#include <uapi/asm-generic/termbits.h>
#include <uapi/linux/kd.h>
#include <uapi/asm-generic/fcntl.h>
#include <hyper_gen/hyper_gen_work.h>
#include <linux/kvm_host.h>
#include <linux/netdevice.h>
#include <net/rtnetlink.h>
#include <linux/hugetlb.h>

#define TTYDEF_IFLAG    (BRKINT | ISTRIP | ICRNL | IMAXBEL | IXON | IXANY)
#define TTYDEF_OFLAG    (OPOST | ONLCR | XTABS)
#define TTYDEF_LFLAG    (ECHO | ICANON | ISIG | IEXTEN | ECHOE|ECHOKE|ECHOCTL)
#define TTYDEF_CFLAG    (CREAD | CS7 | PARENB | HUPCL)
#define TTYDEF_SPEED    (B9600)

#define CTRL(x) (x&037)
#define CEOF        CTRL('d')

#define CEOL       _POSIX_VDISABLE

#define CERASE      0177
#define CINTR       CTRL('c')

#define CSTATUS    _POSIX_VDISABLE

#define CKILL       CTRL('u')
#define CMIN        1
#define CQUIT       034     /* FS, ^\ */
#define CSUSP       CTRL('z')
#define CTIME       0
#define CDSUSP      CTRL('y')
#define CSTART      CTRL('q')
#define CSTOP       CTRL('s')
#define CLNEXT      CTRL('v')
#define CDISCARD    CTRL('o')
#define CWERASE     CTRL('w')
#define CREPRINT    CTRL('r')
#define CEOT        CEOF
/* compat */
#define CBRK        CEOL
#define CRPRNT      CREPRINT
#define CFLUSH      CDISCARD
#define   _POSIX_VDISABLE '\0'

#define CTL(x)      ((x) ^ 0100)    /* Assumes ASCII dialect */
#define CR      CTL('M')    /* carriage return */
#define NL      CTL('J')    /* line feed */
#define BS      CTL('H')    /* back space */
#define DEL     CTL('?')    /* delete */

//typedef int (*tx_fn_t)(void *opaque, char *buf, int len);

struct hyper_gen_poll {
	poll_table table;
	wait_queue_head_t *wqh;
	wait_queue_entry_t wait;
	struct hyper_gen_work work;
	unsigned long mask;
};

enum tty_ctx_type {
	HYPER_GEN,
	VM_GEN,
};

struct hyper_gen_tty_context {
	char rx_buf[128];
	int put_index;

	char vser_rx_buf[128];
	int vser_rx_put_index;
	int vser_rx_get_index;

	int fd;
	enum tty_ctx_type context_type;
	struct termios tp;
	struct kvm *kvm;

	wait_queue_entry_t vser_rx_wait;
	wait_queue_entry_t vser_tx_wait;
	struct hyper_gen_work vser_rx_work;
	struct hyper_gen_work vser_tx_work;
};

struct kvm *find_kvm_by_id(uint64_t kvm_id);
void attach_to_vser(struct kvm *kvm, wait_queue_entry_t *tx_wait, wait_queue_entry_t *rx_wait);
void deattach_to_vser(struct kvm *kvm, wait_queue_entry_t *tx_wait, wait_queue_entry_t *rx_wait);
int vser_can_receive(struct kvm *kvm);
void vser_receive(struct kvm *kvm, const uint8_t *buf, int size);
static void handle_vser_rx(struct hyper_gen_work *work);
void foreach_kvm_call_fn(for_each_kvm_fn_t fn, void *arg);
int hyper_gen_create_vm_from_mgnt(unsigned long image_id);
int hyper_gen_destroy_vm(unsigned long vm_id);
int hyper_gen_flush_eth_dev(struct net_device *dev);
ssize_t __nr_hugepages_store_common(bool obey_mempolicy,
					   struct hstate *h, int nid,
					   unsigned long count, size_t len);
void check_hot_buddy(void);
void hyper_gen_set_nx_huge_pages(const char *val);
void vser_xmit(struct kvm *kvm, int fd);

extern struct rtnl_link_ops br_link_ops;

static struct task_struct *hyper_gen_console_worker;
static struct llist_head hyper_gen_work_list;
static const char *prompt = "hyper-gen:#";

static DEFINE_MUTEX(image_lock);
static LIST_HEAD(image_list);
static uint64_t glb_image_cnt = 1;

int my_task_test = 0;

void hyper_gen_commit_work(struct hyper_gen_work *work)
{
	llist_add(&work->node, &hyper_gen_work_list);
	wake_up_process(hyper_gen_console_worker);
}


static void handle_vser_rx(struct hyper_gen_work *work)
{
	int i;
	int ret;
	struct hyper_gen_tty_context *ctx = work->opaque;

	if (!ctx->kvm)
		return;

	if (ctx->vser_rx_get_index == ctx->vser_rx_put_index)
		return;

	while (1) {
		ret = vser_can_receive(ctx->kvm);
		if (!ret)
			break;

		for (i = 0; i < ret; i++) {
			vser_receive(ctx->kvm, 
				(const uint8_t *)&ctx->vser_rx_buf[ctx->vser_rx_get_index], 1);

			ctx->vser_rx_get_index =
				(ctx->vser_rx_get_index + 1) % sizeof(ctx->vser_rx_buf);

			if (ctx->vser_rx_get_index == ctx->vser_rx_put_index)
				goto out;
		}
	}

out:
	return;
}

static int vser_ready_rx(wait_queue_entry_t *wait, unsigned mode, int sync,
			     void *key)
{
	struct hyper_gen_tty_context *ctx =
		container_of(wait, struct hyper_gen_tty_context, vser_rx_wait);

	if (ctx->vser_rx_put_index == ctx->vser_rx_get_index)
 		return 0;

	if (!test_and_set_bit(WORK_PENDING, &ctx->vser_rx_work.flags))
		hyper_gen_commit_work(&ctx->vser_rx_work);

	return 0;
}

static void handle_vser_tx(struct hyper_gen_work *work)
{
	struct hyper_gen_tty_context *ctx = work->opaque;

	vser_xmit(ctx->kvm, ctx->fd);

	return;
}

static int vser_ready_tx(wait_queue_entry_t *wait, unsigned mode, int sync,
			     void *key)
{
	struct hyper_gen_tty_context *ctx =
		container_of(wait, struct hyper_gen_tty_context, vser_tx_wait);

	if (!test_and_set_bit(WORK_PENDING, &ctx->vser_tx_work.flags))
		hyper_gen_commit_work(&ctx->vser_tx_work);

	return 0;
}

static int start_vm_console(struct hyper_gen_tty_context *ctx, unsigned long vm_id)
{
	//1. find vm with vm_id
	struct kvm *kvm = find_kvm_by_id(vm_id);
	if (!kvm) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		return -1;
	}

	//2. hook fd to vserial tx
	attach_to_vser(kvm, &ctx->vser_tx_wait, &ctx->vser_rx_wait);
	ctx->kvm = kvm;

	ctx->context_type = VM_GEN;

#if 0
	//turn off tty echo
    ctx->tp.c_lflag &= ~ECHO;
	ret = sys_ioctl(ctx->fd, TCSETSW, (const __user unsigned long)&ctx->tp);
	if (0 > ret) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		return -1;
	}
#endif

	return 0;
}

static void stop_vm_console(struct hyper_gen_tty_context *ctx)
{
	//1. dishook fd to vserial tx
	deattach_to_vser(ctx->kvm, &ctx->vser_tx_wait, &ctx->vser_rx_wait);

	ctx->kvm = NULL;
	ctx->context_type = HYPER_GEN;

	ctx->vser_rx_get_index = ctx->vser_rx_put_index = 0;

#if 0
	//2. turn on tty echo 
    ctx->tp.c_lflag |= ECHO;
	ret = sys_ioctl(ctx->fd, TCSETSW, (const __user unsigned long)&ctx->tp);
	if (0 > ret) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		return;
	}
#endif
}



struct hyper_gen_image *find_image_by_id(unsigned long image_id)
{
	struct hyper_gen_image *img;

	mutex_lock(&image_lock);

	list_for_each_entry(img, &image_list, image_list) {
		if (img->id == image_id) {
			mutex_unlock(&image_lock);
			return img;
		}
	}

	mutex_unlock(&image_lock);
	return NULL;
}

static int hyper_gen_create_vm_by_template(unsigned long image_id)
{
	struct hyper_gen_image *img;

	//TODO: implement image_id
	img = find_image_by_id(image_id);
	if (!img)
		return -1;

	if (img->used)
		return -1;

	img->used = true;

	hyper_gen_create_vm_from_mgnt(image_id);

	return 0;
}

static void list_fn(struct kvm *kvm, void *arg)
{
	char tmp[32];
	struct hyper_gen_tty_context *ctx = arg;

	sprintf(tmp, "VMID: %llu\n", kvm->id);
	sys_write(ctx->fd, (const char __user *)tmp, strlen(tmp));
}

static void list_hyper_gen_image(struct hyper_gen_tty_context *ctx)
{
	char tmp[32];
	struct hyper_gen_image *img;

	mutex_lock(&image_lock);

	list_for_each_entry(img, &image_list, image_list) {
		sprintf(tmp, "Image: id->%llu used->%d\n", img->id, img->used);
		sys_write(ctx->fd, (const char __user *)tmp, strlen(tmp));
	}

	mutex_unlock(&image_lock);
}

static bool parse_cmd(struct hyper_gen_tty_context *ctx)
{
	int ret;
	char *val;
	unsigned long vm_id;
	unsigned long image_id;
	char tmp[32];
	char *param;
	char *args = ctx->rx_buf;

	args = skip_spaces(args);
	param = strsep(&args, " ");

	if (!strcmp(param, "vm_console")) {
		val = strsep(&args, " ");
		if (!val)
			goto fail_val;

		ret = kstrtoul(val, 0, &vm_id);
		if (ret)
			goto fail_val;

		ret = start_vm_console(ctx, vm_id);
		if (ret)
			goto fail_val;
	} else if (!strcmp(param, "vm_create")) {
		val = strsep(&args, " ");
		if (!val)
			goto fail_val;

		ret = kstrtoul(val, 0, &image_id);
		if (ret)
			goto fail_val;

		ret = hyper_gen_create_vm_by_template(image_id);
		if (ret)
			goto fail_val;
		return true;
	} else if (!strcmp(param, "vm_destroy")) {
		val = strsep(&args, " ");
		if (!val)
			goto fail_val;

		ret = kstrtoul(val, 0, &vm_id);
		if (ret)
			goto fail_val;

		ret = hyper_gen_destroy_vm(vm_id);
		if (ret)
			goto fail_val;
		return true;
	} else if (!strcmp(param, "vm_list")) {
		foreach_kvm_call_fn(list_fn, ctx);
		return true;
	} else if (!strcmp(param, "image_list")) {
		list_hyper_gen_image(ctx);
		return true;
	} else if (!strcmp(param, "host_reboot")) {
		kernel_restart(NULL);
		return true;
	} else if (!strcmp(param, "host_shutdown")) {
		kernel_power_off();
		return true;
	} else {
		sprintf(tmp, "%s\n", "Invalid Cmd");
		goto fail;
	}

	return false;

fail_val:
	sprintf(tmp, "%s\n", "Invalid Val");
fail:
	sys_write(ctx->fd, (const char __user *)tmp, strlen(tmp));
	return true;
}

static bool dump_to_vm(struct hyper_gen_tty_context *ctx)
{
	//1. find current vserial
	//2. dump ctx->rx_buf to vserial 
	int i;

	for (i = 0; i < ctx->put_index; i++) {
		ctx->vser_rx_buf[ctx->vser_rx_put_index] = ctx->rx_buf[i];

		ctx->vser_rx_put_index =
			(ctx->vser_rx_put_index + 1) % sizeof(ctx->vser_rx_buf);

		if (ctx->vser_rx_put_index == ctx->vser_rx_get_index)
			ctx->vser_rx_get_index =
				(ctx->vser_rx_get_index + 1) % sizeof(ctx->vser_rx_buf);
	}

	handle_vser_rx(&ctx->vser_rx_work);

	return false;
}

static char *tty_put_char(struct hyper_gen_tty_context *ctx, char *bp, char c)
{
	if ((size_t)(bp - ctx->rx_buf) >= sizeof(ctx->rx_buf) - 1) {
		bp = ctx->rx_buf;
		ctx->put_index = 0;
	}

	*bp++ = c;         /* and store it */
	ctx->put_index++;

	return bp;
}

static void handle_tty_rx(struct hyper_gen_work *work)
{
	struct hyper_gen_tty_context *ctx = work->opaque;
	char *bp = ctx->rx_buf + ctx->put_index;
	char key;
	int ret;
	char eol;
	bool need_prompt = true;

	eol = '\0';
	while (eol == '\0') {
		ret = sys_read(ctx->fd, (char __user *)&key, 1);
		if (ret <= 0)
			return;

    	switch (key) {
		case CR:
		case NL:
			if (ctx->context_type == HYPER_GEN) {
				*bp = 0;            /* terminate logname */
			} else if (ctx->context_type == VM_GEN) {
				bp = tty_put_char(ctx, bp, key);
			}
			eol = key;       /* set end-of-line char */
			break;
		case BS:
		case DEL:
			if (bp > ctx->rx_buf) {
				bp--;
				ctx->put_index--;
			}
			break;
		case CTL('D'):
			//1. if in vm context, switch to hyper-gen
			if (ctx->context_type == VM_GEN) {
				stop_vm_console(ctx);
				sys_write(ctx->fd, (const char __user *)"\n", 1);
				sys_write(ctx->fd, (const char __user *)prompt, strlen(prompt));
			}
			break;
		default:
			bp = tty_put_char(ctx, bp, key);
			break;
		}
	}

	if (ctx->context_type == HYPER_GEN) {
		need_prompt = parse_cmd(ctx);
	} else if (ctx->context_type == VM_GEN) {
		need_prompt = dump_to_vm(ctx);
	}

	if (need_prompt)
		sys_write(ctx->fd, (const char __user *)prompt, strlen(prompt));

	ctx->put_index = 0;
}

static int init_tty_ctx(struct hyper_gen_tty_context *ctx, int fd)
{
	int ret = 0;

	ctx->put_index = 0;

	ctx->vser_rx_put_index = 0;
	ctx->vser_rx_get_index = 0;

	ctx->fd = fd; 
	ctx->context_type = HYPER_GEN;
	ctx->kvm = NULL;

	INIT_LIST_HEAD(&ctx->vser_rx_wait.entry);
	init_waitqueue_func_entry(&ctx->vser_rx_wait, vser_ready_rx);

	INIT_LIST_HEAD(&ctx->vser_tx_wait.entry);
	init_waitqueue_func_entry(&ctx->vser_tx_wait, vser_ready_tx);

	ctx->vser_rx_work.flags = 0;
	ctx->vser_rx_work.fn = handle_vser_rx;
	ctx->vser_rx_work.opaque = (void*)ctx;

	ctx->vser_tx_work.flags = 0;
	ctx->vser_tx_work.fn = handle_vser_tx;
	ctx->vser_tx_work.opaque = (void*)ctx;

	ret = sys_ioctl(fd, TCGETS, (const __user unsigned long)&ctx->tp);
	if (0 > ret) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		return -1;
	}

	return 0;
}

static int tty_poll_wakeup(wait_queue_entry_t *wait, unsigned mode, int sync,
			     void *key)
{
	struct hyper_gen_poll *poll = container_of(wait, struct hyper_gen_poll, wait);

 	if (!((unsigned long)key & poll->mask))
 		return 0;

	if (!test_and_set_bit(WORK_PENDING, &poll->work.flags))
		hyper_gen_commit_work(&poll->work);

	return 0;
}

static void tty_poll_hook_func(struct file *file, wait_queue_head_t *wqh,
			    poll_table *pt)
{
	struct hyper_gen_poll *poll;

	poll = container_of(pt, struct hyper_gen_poll, table);
	if (poll->wqh != NULL)
		return;

	//only hook read_wait
	poll->wqh = wqh;

	add_wait_queue(wqh, &poll->wait);
}

static int init_tty_poll_work(int fd)
{
	struct hyper_gen_poll *poll;
	struct file *file;
	unsigned long mask;
	struct hyper_gen_tty_context *ctx;

	poll = kzalloc(sizeof(struct hyper_gen_poll), GFP_KERNEL);
	if (!poll) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		return -1;
	}

	INIT_LIST_HEAD(&poll->wait.entry);
	init_waitqueue_func_entry(&poll->wait, tty_poll_wakeup);
	init_poll_funcptr(&poll->table, tty_poll_hook_func);
	poll->mask = POLLIN;
	poll->wqh = NULL;
	poll->work.flags = 0;
	poll->work.fn = handle_tty_rx;

	ctx = kzalloc(sizeof(struct hyper_gen_tty_context), GFP_KERNEL);
	if (!ctx) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		return -1;
	}

	if (0 > init_tty_ctx(ctx, fd)) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		return -1;
	}

	poll->work.opaque = (void*)ctx;

    file = fget(fd);
    if (!file) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        return -1;
    }

	mask = file->f_op->poll(file, &poll->table);
	if (mask)
		tty_poll_wakeup(&poll->wait, 0, 0, (void *)mask);

	if (mask & POLLERR) {
		printk(">>>%s:%d\n", __func__, __LINE__);
        return -1;
	}

	sys_write(fd, (const char __user *)prompt, strlen(prompt));

	return 0;
}

static void reset_virtual_console(struct termios *tp)
{
    /* Use defaults of <sys/ttydefaults.h> for base settings */
    tp->c_iflag |= TTYDEF_IFLAG;
    tp->c_oflag |= TTYDEF_OFLAG;
    tp->c_lflag |= TTYDEF_LFLAG;

    tp->c_lflag &= ~CBAUD;
    tp->c_cflag |= (B38400 | TTYDEF_CFLAG);

    tp->c_iflag |=  (BRKINT | ICRNL | IMAXBEL);
    tp->c_iflag &= ~(IGNBRK | INLCR | IGNCR | IXOFF | IUCLC | IXANY | ISTRIP);
    tp->c_oflag |=  (OPOST | ONLCR | NL0 | CR0 | TAB0 | BS0 | VT0 | FF0);
    tp->c_oflag &= ~(OLCUC | OCRNL | ONOCR | ONLRET | OFILL | \
                NLDLY|CRDLY|TABDLY|BSDLY|VTDLY|FFDLY);
    tp->c_lflag |=  (ISIG | ICANON | IEXTEN | ECHO|ECHOE|ECHOK|ECHOKE|ECHOCTL);
    tp->c_lflag &= ~(ECHONL|ECHOPRT | NOFLSH | TOSTOP);

    tp->c_cflag |=  (CREAD | CS8 | HUPCL);
    tp->c_cflag &= ~(PARODD | PARENB);

    tp->c_oflag &= ~OFDEL;
    tp->c_lflag &= ~XCASE;

    tp->c_iflag |= IUTF8;       /* Set UTF-8 input flag */

    /* VTIME and VMIN can overlap with VEOF and VEOL since they are
     * only used for non-canonical mode. We just set the at the
     * beginning, so nothing bad should happen.
     */
    tp->c_cc[VTIME]    = 0;
    tp->c_cc[VMIN]     = 1;
    tp->c_cc[VINTR]    = CINTR;
    tp->c_cc[VQUIT]    = CQUIT;
    tp->c_cc[VERASE]   = CERASE; /* ASCII DEL (0177) */
    tp->c_cc[VKILL]    = CKILL;
    tp->c_cc[VEOF]     = CEOF;
    tp->c_cc[VSWTC]    = _POSIX_VDISABLE;
    tp->c_cc[VSTART]   = CSTART;
    tp->c_cc[VSTOP]    = CSTOP;
    tp->c_cc[VSUSP]    = CSUSP;
    tp->c_cc[VEOL]     = _POSIX_VDISABLE;
    tp->c_cc[VREPRINT] = CREPRINT;
    tp->c_cc[VDISCARD] = CDISCARD;
    tp->c_cc[VWERASE]  = CWERASE;
    tp->c_cc[VLNEXT]   = CLNEXT;
    tp->c_cc[VEOL2]    = _POSIX_VDISABLE;
}

static int init_hyper_gen_tty(void)
{
	int kbmode; 
	int ret;
	struct termios lock;
	int fd;
	struct termios tp;

	sys_close(0);
	sys_close(1);
	sys_close(2);

	if ((fd = sys_open((const char __user *) "/dev/tty3", O_RDWR, 0)) < 0) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		return -1;
	}

	ret = sys_ioctl(fd, TCGETS, (const __user unsigned long)&tp);
	if (0 > ret) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		return -1;
	}

	ret = sys_ioctl(fd, KDGKBMODE, (const __user unsigned long)&kbmode);
	if (0 > ret) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		return -1;
	}

	while (1) {
		memset(&lock, 0, sizeof(struct termios));
		if (sys_ioctl(fd, TIOCGLCKTRMIOS, (const __user unsigned long)&lock) < 0)
            break;

		if (!lock.c_iflag && !lock.c_oflag && !lock.c_cflag && !lock.c_lflag)
            break;

		msleep(1000);
	}

    memset(&lock, 0, sizeof(struct termios));
    ret = sys_ioctl(fd, TIOCSLCKTRMIOS, (const __user unsigned long)&lock);
	if (0 > ret) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		return -1;
	}

	reset_virtual_console(&tp);
	ret = sys_ioctl(fd, TCSETSW, (const __user unsigned long)&tp);
	if (0 > ret) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		return -1;
	}

#if 0
    sys_fcntl(fd, F_SETFL,
          sys_fcntl(fd, F_GETFL, 0) & ~O_NONBLOCK);
#else
    sys_fcntl(fd, F_SETFL,
          sys_fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
#endif

	return fd;
}

static int hyper_gen_daemon(void *data)
{
	int fd;

	//init work list
	init_llist_head(&hyper_gen_work_list);

	//suppress console log at first
//	console_loglevel = default_message_loglevel;

	//init tty special for hyper_gen
	fd = init_hyper_gen_tty();
	if (fd < 0) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		do_exit(0);
	}

	//init poll work for tty
	if (0 > init_tty_poll_work(fd)) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		do_exit(0);
	}

	while (1) {
		struct llist_node *node;
		struct hyper_gen_work *work, *work_next;

		set_current_state(TASK_INTERRUPTIBLE);

		node = llist_del_all(&hyper_gen_work_list);
		if (!node)
			schedule();

		node = llist_reverse_order(node);

		smp_wmb();
		llist_for_each_entry_safe(work, work_next, node, node) {
			clear_bit(WORK_PENDING, &work->flags);
			__set_current_state(TASK_RUNNING);
			work->fn(work);
			if (need_resched())
				schedule();
		}

	}

	//never to here
	return 0;
}

static void alloc_vhost_target_file(char *file_dir)
{
	int fd;
	int ret;
	char buf[128];
	char buf_1[128];
	struct hyper_gen_image *image =
		kzalloc(sizeof(struct hyper_gen_image), GFP_KERNEL);

	image->id = glb_image_cnt++;
	image->used = false;

	//1. mkdir -p /sys/kernel/config/target/core/fileio_2/myFile2
	sprintf(buf, "/sys/kernel/config/target/core/fileio_%llu", image->id);
	ret = sys_mkdir(buf, 0777);
	if (ret)
		printk(">>>%s:%d\n", __func__, __LINE__);

	sprintf(buf, "/sys/kernel/config/target/core/fileio_%llu/myFile", image->id);
	ret = sys_mkdir(buf, 0777);
	if (ret)
		printk(">>>%s:%d\n", __func__, __LINE__);


	//2. echo 'fd_dev_name=/home/gen/openSource/guen/rootfs/debootstrap.ext2.raw,fd_dev_size=5116637696' > /sys/kernel/config/target/core/fileio_2/myFile2/control
	sprintf(buf, "/sys/kernel/config/target/core/fileio_%llu/myFile/control", image->id);
	if ((fd = sys_open((const char __user *)buf,
			O_WRONLY, 0)) < 0) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		return;
	}

	sprintf(buf, "%s", file_dir);
	ret = sys_write(fd, buf, strlen(buf));
	if (ret <= 0)
		printk(">>>%s:%d\n", __func__, __LINE__);


	//3. echo 1 > /sys/kernel/config/target/core/fileio_2/myFile2/enable
	sprintf(buf, "/sys/kernel/config/target/core/fileio_%llu/myFile/enable", image->id);
	if ((fd = sys_open((const char __user *)buf,
			O_WRONLY, 0)) < 0) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		return;
	}

	sprintf(buf, "%d", 1);
	ret = sys_write(fd, buf, strlen(buf));
	if (ret <= 0)
		printk(">>>%s:%d\n", __func__, __LINE__);



	//4. mkdir -p /sys/kernel/config/target/vhost/naa.600140554cf3a18e/tpgt_0/lun/lun_0
	sprintf(buf, "/sys/kernel/config/target/vhost/naa.%llu", image->id);
	ret = sys_mkdir(buf, 0777);
	if (ret)
		printk(">>>%s:%d\n", __func__, __LINE__);

	sprintf(buf, "/sys/kernel/config/target/vhost/naa.%llu/tpgt_0", image->id);
	ret = sys_mkdir(buf, 0777);
	if (ret)
		printk(">>>%s:%d\n", __func__, __LINE__);

	sprintf(buf, "/sys/kernel/config/target/vhost/naa.%llu/tpgt_0/lun/lun_0", image->id);
	ret = sys_mkdir(buf, 0777);
	if (ret)
		printk(">>>%s:%d\n", __func__, __LINE__);


	//5. ln -sf /sys/kernel/config/target/core/fileio_2/myFile2 /sys/kernel/config/target/vhost/naa.600140554cf3a18e/tpgt_0/lun/lun_0/123456
	sprintf(buf, "/sys/kernel/config/target/core/fileio_%llu/myFile", image->id);
	sprintf(buf_1, "/sys/kernel/config/target/vhost/naa.%llu/tpgt_0/lun/lun_0/12345", image->id);
	ret = sys_symlinkat(buf, AT_FDCWD, buf_1);
	if (ret)
		printk(">>>%s:%d\n", __func__, __LINE__);


	//6. echo naa.600140554cf3a18e > /sys/kernel/config/target/vhost/naa.600140554cf3a18e/tpgt_0/nexus
	sprintf(buf, "/sys/kernel/config/target/vhost/naa.%llu/tpgt_0/nexus", image->id);
	if ((fd = sys_open((const char __user *)buf,
			O_WRONLY, 0)) < 0) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		return;
	}

	sprintf(buf, "naa.%llu", image->id);
	ret = sys_write(fd, buf, strlen(buf));
	if (ret <= 0)
		printk(">>>%s:%d\n", __func__, __LINE__);

	//7. save image and link
	sprintf(image->naa_id, "naa.%llu", image->id);

	mutex_lock(&image_lock);
	list_add(&image->image_list, &image_list);
	mutex_unlock(&image_lock);
}

static void init_vhost_target_file(void)
{
	int ret;

	ret = sys_mount("sysfs", "/sys", "sysfs", MS_MGC_VAL, NULL);
	if (ret)
		printk(">>>%s:%d\n", __func__, __LINE__);

	ret = sys_mount("configfs", "/sys/kernel/config", "configfs", MS_MGC_VAL, NULL);
	if (ret)
		printk(">>>%s:%d\n", __func__, __LINE__);

	ret = sys_mkdir("/sys/kernel/config/target/vhost", 0777);
	if (ret)
		printk(">>>%s:%d\n", __func__, __LINE__);

	alloc_vhost_target_file("fd_dev_name=/home/gen/openSource/guen/rootfs/debootstrap.ext2.raw,fd_dev_size=5116637696");

	alloc_vhost_target_file("fd_dev_name=/home/gen/openSource/guen/rootfs/debootstrap_1.ext2.raw,fd_dev_size=5116637696");
}

static void init_hyper_gen_bridge(void)
{
	int err;
	struct net_device *dev, *tmp, *phy_eth = NULL;
	struct net_device *br;
	const struct net_device_ops *ops;
	struct netlink_ext_ack extack;

	//ip link set eth0 up. "ip=dhcp" has setup eth0 before.
#if 0
	dev = __dev_get_by_name(&init_net, "eth0");

	if (dev) {
		printk(">>>%s:%d up=%d\n", __func__, __LINE__, dev->flags & IFF_UP);
	}

	if (dev) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		dev_change_flags(dev,
           dev->flags | IFF_UP);
	} else {
		printk(">>>%s:%d\n", __func__, __LINE__);
	}
#endif

	rtnl_lock();

	//find a valid phyical eth
	for_each_netdev_safe(&init_net, dev, tmp) {
		printk(">>>%s:%d dev=%s\n", __func__, __LINE__, dev->name);
		/* Ignore unmoveable devices (i.e. loopback) */
		if (dev->features & NETIF_F_NETNS_LOCAL) {
			printk(">>>%s:%d dev=%s\n", __func__, __LINE__, dev->name);
			continue;
		}

		/* Leave virtual devices for the generic cleanup */
		if (dev->rtnl_link_ops) {
			printk(">>>%s:%d dev=%s\n", __func__, __LINE__, dev->name);
			continue;
		}

		if (!(dev->flags & IFF_UP)) {
			printk(">>>%s:%d dev=%s\n", __func__, __LINE__, dev->name);
			continue;
		}

		phy_eth = dev;
		break;
	}

	if (!phy_eth) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		goto out;
	}


	//1. ip link add br0 type bridge
	br = alloc_netdev_mqs(br_link_ops.priv_size, "br0", NET_NAME_USER,
			       br_link_ops.setup, 1, 1);

	dev_net_set(br, &init_net);
	br->rtnl_link_ops = &br_link_ops;
	br->rtnl_link_state = RTNL_LINK_INITIALIZING;
	br->ifindex = 0;

	err = register_netdevice(br);
	if (err) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		goto out;
	}

	br->rtnl_link_state = RTNL_LINK_INITIALIZED;


	//2. ip addr flush dev eth0
	err = hyper_gen_flush_eth_dev(phy_eth);
	if (err) {
		printk(">>>%s:%d\n", __func__, __LINE__);
		goto out;
	}


	//3. ip link set eth0 up, and promisc on
	dev_change_flags(phy_eth, dev->flags | IFF_UP | IFF_PROMISC);


	//4. ip link set eth0 master br0
	ops = br->netdev_ops;
	if (ops->ndo_add_slave) {
		if (ops->ndo_add_slave(br, phy_eth, &extack))
			printk(">>>>>%s:%d\n",__func__, __LINE__);
	} else {
		printk(">>>>>%s:%d\n",__func__, __LINE__);
	}


	//5. ip link set br0 up
	dev_change_flags(br, dev->flags | IFF_UP);

out:
	rtnl_unlock();
}

void hyper_gen_init(void)
{
	int pid;

	//setup hugepages
	__nr_hugepages_store_common(0, &default_hstate, -1, 2048, 0);

	//setup vhost target file
	init_vhost_target_file();

	//setup bridge
	init_hyper_gen_bridge();

	//launch hyper-gen daemon thread
	pid = kernel_thread(hyper_gen_daemon, NULL, CLONE_FS | CLONE_FILES);
	rcu_read_lock();
	hyper_gen_console_worker = find_task_by_pid_ns(pid, &init_pid_ns);
	rcu_read_unlock();

	check_hot_buddy();
}
