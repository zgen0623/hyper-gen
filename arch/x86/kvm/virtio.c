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
#include "kvm_cache_regs.h"
#include "lapic.h"
#include "trace.h"
#include "x86.h"
#include "irq.h"
#include "mmu.h"
#include "i8254.h"
#include "tss.h"
#include "kvm_cache_regs.h"
#include "cpuid.h"
#include "pmu.h"
#include "hyperv.h"
#include "regs.h"
#include "machine.h"
#include "vpci.h"
#include "virtio.h"
#include <uapi/linux/vhost.h>
#include <uapi/linux/virtio_pci.h>
#include <uapi/linux/virtio_config.h>
#include <linux/pci_ids.h>
#include <uapi/asm-generic/poll.h>

int kvm_ioeventfd(struct kvm *kvm, struct kvm_ioeventfd *args);
void vhost_inject_virq_kvm(uint64_t kvm_id, void *priv);
void *vhost_alloc_irq_entry_kvm(uint64_t kvm_id, int virq);

static int virtio_queue_get_num(VirtIODevice *vdev, int n);
static hwaddr virtio_queue_get_desc_size(VirtIODevice *vdev, int n);
static uint16_t virtio_queue_vector(VirtIODevice *vdev, int n);
static int virtio_set_host_notifier(VirtIODevice *vdev, int n, bool assign);
static void vhost_virtqueue_stop(struct vhost_dev *dev,
                                    struct VirtIODevice *vdev,
                                    struct vhost_virtqueue *vq,
                                    unsigned idx);
static hwaddr virtio_queue_get_desc_addr(VirtIODevice *vdev, int n);
static hwaddr virtio_queue_get_avail_size(VirtIODevice *vdev, int n);
static hwaddr virtio_queue_get_used_size(VirtIODevice *vdev, int n);

static inline bool virtio_host_has_feature(VirtIODevice *vdev,
                                           unsigned int fbit)
{       
    return virtio_has_feature_(vdev->host_features, fbit);
}

static uint16_t virtio_get_queue_index(VirtQueue *vq)
{   
    return vq->queue_index;
}




bool virtio_queue_enabled(VirtIODevice *vdev, int n)
{   
    return virtio_queue_get_desc_addr(vdev, n) != 0;
}  

int virtio_get_num_queues(VirtIODevice *vdev)
{   
    int i;
        
    for (i = 0; i < VIRTIO_QUEUE_MAX; i++) {
        if (!virtio_queue_get_num(vdev, i)) {
            break;
        }
    }   
    
    return i;
}

void vhost_ack_features(struct vhost_dev *hdev, const int *feature_bits,
                        uint64_t features)
{   
    const int *bit = feature_bits;

    while (*bit != VHOST_INVALID_FEATURE_BIT) {
        uint64_t bit_mask = (1ULL << *bit);
        if (features & bit_mask) {
            hdev->acked_features |= bit_mask;
        }
        bit++;
    }   
} 

void vhost_dev_stop_(struct vhost_dev *hdev, VirtIODevice *vdev)
{           
    hdev->started = false;
    hdev->vdev = NULL;
}


void vhost_dev_disable_notifiers(struct vhost_dev *hdev, VirtIODevice *vdev)
{
    int i, r;

    for (i = 0; i < hdev->nvqs; ++i) {
        r = virtio_set_host_notifier(vdev, hdev->vq_index + i,
                                         false);
        if (r < 0)
            printk(">>>>%s:%d vhost VQ %d notifier cleanup failed: %d",
			__func__, __LINE__,  i, -r);
    }                       
}

void vhost_virtqueue_mask(struct vhost_dev *hdev, VirtIODevice *vdev, int n,
                         bool mask)
{                           
    int r;
    struct vhost_vring_file file;
	struct kvm *kvm = vdev->pci_dev.bus->kvm;

    int vector = virtio_queue_vector(vdev, n);
    VirtIOIRQFD *irqfd = &vdev->vector_irqfd[vector];
                         
    if (mask) {
        file.fd = 1;
    } else {
        file.fd = 2;
        file.kvm_id = kvm->id;
        file.virq = irqfd->virq;
    }

    file.index = n - hdev->vq_index;
    r = hdev->ioctl_hook(hdev->opaque, VHOST_SET_VRING_CALL, (uint64_t)&file);
    if (r < 0)
        printk(">>>>>%s:%d vhost_set_vring_call failed\n",
			__func__, __LINE__);
}

static int vhost_dev_set_features(struct vhost_dev *dev)
{
    uint64_t features = dev->acked_features;
    int r;

    r = dev->ioctl_hook(dev->opaque, VHOST_SET_FEATURES, (uint64_t)&features);
    if (r < 0)
        printk(">>>>%s:%d vhost_set_features failed\n",
			__func__, __LINE__);

    return r;
}

static VirtQueue *virtio_get_queue(VirtIODevice *vdev, int n)
{   
    return vdev->vq + n;
}

static hwaddr virtio_queue_get_desc_addr(VirtIODevice *vdev, int n)
{
    return vdev->vq[n].vring.desc;
}

static unsigned int virtio_queue_packed_get_last_avail_idx(VirtIODevice *vdev,
                                                           int n)
{   
    unsigned int avail, used;
    
    avail = vdev->vq[n].last_avail_idx;
    avail |= ((uint16_t)vdev->vq[n].last_avail_wrap_counter) << 15;
    
    used = vdev->vq[n].used_idx;
    used |= ((uint16_t)vdev->vq[n].used_wrap_counter) << 15;
    
    return avail | used << 16;
}
    
static uint16_t virtio_queue_split_get_last_avail_idx(VirtIODevice *vdev,
                                                      int n)
{       
    return vdev->vq[n].last_avail_idx;
}    

static unsigned int virtio_queue_get_last_avail_idx(VirtIODevice *vdev, int n)
{   
    if (virtio_vdev_has_feature(vdev, VIRTIO_F_RING_PACKED)) {
        return virtio_queue_packed_get_last_avail_idx(vdev, n);
    } else {
        return virtio_queue_split_get_last_avail_idx(vdev, n);
    }
}

static int vhost_virtqueue_set_addr(struct vhost_dev *dev,
                                    struct vhost_virtqueue *vq,
                                    unsigned idx)
{
    struct vhost_vring_addr addr = {
        .index = idx,
        .desc_user_addr = (uint64_t)(unsigned long)vq->desc,
        .avail_user_addr = (uint64_t)(unsigned long)vq->avail,
        .used_user_addr = (uint64_t)(unsigned long)vq->used,
        .log_guest_addr = vq->used_phys,
        .flags = 0,
    };

    int r = dev->ioctl_hook(dev->opaque, VHOST_SET_VRING_ADDR, (uint64_t)&addr);
    if (r < 0) {
        printk(">>>>>%s:%d vhost_set_vring_addr failed\n",
			__func__, __LINE__);
        return -1;
    }

    return 0;
}

static uint16_t virtio_queue_vector(VirtIODevice *vdev, int n)
{   
    return n < VIRTIO_QUEUE_MAX ? vdev->vq[n].vector :
        VIRTIO_NO_VECTOR;       
}

static hwaddr virtio_queue_get_avail_addr(VirtIODevice *vdev, int n)
{
    return vdev->vq[n].vring.avail;
} 

static hwaddr virtio_queue_get_used_addr(VirtIODevice *vdev, int n)
{   
    return vdev->vq[n].vring.used;
}

static int vhost_virtqueue_start(struct vhost_dev *dev,
                                struct VirtIODevice *vdev,
                                struct vhost_virtqueue *vq,
                                unsigned idx)
{
	struct gfn_to_hva_cache ghc;
	struct kvm *kvm = vdev->pci_dev.bus->kvm;
    hwaddr s, l, a;
    int r;
    int vhost_vq_index = idx - dev->vq_index;
    struct vhost_vring_file file = {
        .index = vhost_vq_index
    };
    struct vhost_vring_state state = {
        .index = vhost_vq_index
    };
    struct VirtQueue *vvq = virtio_get_queue(vdev, idx);

    a = virtio_queue_get_desc_addr(vdev, idx);
    if (a == 0) {
    	printk(">>>>>%s:%d\n", __func__, __LINE__);
        return 0;
	}

    vq->num = state.num = virtio_queue_get_num(vdev, idx);
    r = dev->ioctl_hook(dev->opaque, VHOST_SET_VRING_NUM, (uint64_t)&state);
    if (r) {
        printk(">>>>>%s:%d vhost_set_vring_num failed\n",
			__func__, __LINE__);
        return -1;
    }

    state.num = virtio_queue_get_last_avail_idx(vdev, idx);
    r = dev->ioctl_hook(dev->opaque, VHOST_SET_VRING_BASE, (uint64_t)&state);
    if (r) {
        printk(">>>>>%s:%d vhost_set_vring_base failed\n",
			__func__, __LINE__);
        return -1;
    }


    vq->desc_size = s = l = virtio_queue_get_desc_size(vdev, idx);
    vq->desc_phys = a;
	if (kvm_gfn_to_hva_cache_init(kvm, &ghc, a, l)) {
        printk(">>>>>%s:%d vhost_set_vring_base failed\n",
			__func__, __LINE__);
        r = -ENOMEM;
        goto out;
    }
    vq->desc = (void *)ghc.hva;


    vq->avail_size = s = l = virtio_queue_get_avail_size(vdev, idx);
    vq->avail_phys = a = virtio_queue_get_avail_addr(vdev, idx);
	if (kvm_gfn_to_hva_cache_init(kvm, &ghc, a, l)) {
        printk(">>>>>%s:%d vhost_set_vring_base failed\n",
			__func__, __LINE__);
        r = -ENOMEM;
        goto out;
    }
    vq->avail = (void *)ghc.hva;


    vq->used_size = s = l = virtio_queue_get_used_size(vdev, idx);
    vq->used_phys = a = virtio_queue_get_used_addr(vdev, idx);
	if (kvm_gfn_to_hva_cache_init(kvm, &ghc, a, l)) {
        printk(">>>>>%s:%d vhost_set_vring_base failed\n",
			__func__, __LINE__);
        r = -ENOMEM;
        goto out;
    }
    vq->used = (void *)ghc.hva;

    r = vhost_virtqueue_set_addr(dev, vq, vhost_vq_index);
    if (r < 0) {
        r = -ENOMEM;
        printk(">>>>>%s:%d\n", __func__, __LINE__);
        goto out;
	}

	//deliver evt_id for guest=>host notify event to vhost side
    file.fd = 1;
    file.evt_id = vvq->evt_id;
    file.kvm_id = kvm->id;
    r = dev->ioctl_hook(dev->opaque, VHOST_SET_VRING_KICK, (uint64_t)&file);
    if (r) {
        printk(">>>>%s:%d vhost_set_vring_kick failed\n",
			__func__, __LINE__);
        goto out;
    }

    /* Clear and discard previous events if any. */
	dev->clear_vq_signaled(dev->opaque, vhost_vq_index);

    if (msix_enabled(&vdev->pci_dev) &&
        virtio_queue_vector(vdev, idx) == VIRTIO_NO_VECTOR) {
        file.fd = 0;
    	r = dev->ioctl_hook(dev->opaque, VHOST_SET_VRING_CALL, (uint64_t)&file);
        if (r) {
        	printk(">>>>>%s:%d vhost_set_vring_base failed\n",
			__func__, __LINE__);
            goto out;
		}
    }

    return 0;

out:
    return r;
}

static void virtio_queue_packed_restore_last_avail_idx(VirtIODevice *vdev,
                                                       int n)
{   
    /* We don't have a reference like avail idx in shared memory */
    return;
}

static uint16_t vring_used_idx(VirtQueue *vq)
{
	void *ptr = (void*)vq->used_hva;
    hwaddr pa = offsetof(VRingUsed, idx);
    return *(uint16_t*)(ptr + pa);
}
    
static void virtio_queue_split_restore_last_avail_idx(VirtIODevice *vdev,
                                                      int n)
{   
    if (vdev->vq[n].vring.desc) {
        vdev->vq[n].last_avail_idx = vring_used_idx(&vdev->vq[n]);
        vdev->vq[n].shadow_avail_idx = vdev->vq[n].last_avail_idx;
    }   
}   
        
static void virtio_queue_restore_last_avail_idx(VirtIODevice *vdev, int n)
{   
    if (virtio_vdev_has_feature(vdev, VIRTIO_F_RING_PACKED)) { 
        virtio_queue_packed_restore_last_avail_idx(vdev, n);
    } else {
        virtio_queue_split_restore_last_avail_idx(vdev, n);
    }   
}

static void virtio_queue_packed_set_last_avail_idx(VirtIODevice *vdev,
                                                   int n, unsigned int idx)
{   
    struct VirtQueue *vq = &vdev->vq[n];
    
    vq->last_avail_idx = vq->shadow_avail_idx = idx & 0x7fff;
    vq->last_avail_wrap_counter =
        vq->shadow_avail_wrap_counter = !!(idx & 0x8000);
    idx >>= 16;
    vq->used_idx = idx & 0x7ffff;
    vq->used_wrap_counter = !!(idx & 0x8000);
}
    
static void virtio_queue_split_set_last_avail_idx(VirtIODevice *vdev,
                                                  int n, unsigned int idx)
{   
    vdev->vq[n].last_avail_idx = idx;
    vdev->vq[n].shadow_avail_idx = idx;
}

static void virtio_queue_set_last_avail_idx(VirtIODevice *vdev, int n,
                                     unsigned int idx)
{       
    if (virtio_vdev_has_feature(vdev, VIRTIO_F_RING_PACKED)) {
        virtio_queue_packed_set_last_avail_idx(vdev, n, idx);
    } else {
        virtio_queue_split_set_last_avail_idx(vdev, n, idx);
    }
}


static void virtio_queue_packed_update_used_idx(VirtIODevice *vdev, int n)
{       
    /* used idx was updated through set_last_avail_idx() */
    return;
}   
    
static void virtio_split_packed_update_used_idx(VirtIODevice *vdev, int n)
{       
    if (vdev->vq[n].vring.desc) {
        vdev->vq[n].used_idx = vring_used_idx(&vdev->vq[n]);
    } 
}       
    
static void virtio_queue_update_used_idx(VirtIODevice *vdev, int n)
{   
    if (virtio_vdev_has_feature(vdev, VIRTIO_F_RING_PACKED)) {
        return virtio_queue_packed_update_used_idx(vdev, n);
    } else {           
        return virtio_split_packed_update_used_idx(vdev, n);
    }                  
}

static void virtio_queue_invalidate_signalled_used(VirtIODevice *vdev, int n)
{
    vdev->vq[n].signalled_used_valid = false;
}

static void vhost_virtqueue_stop(struct vhost_dev *dev,
                                    struct VirtIODevice *vdev,
                                    struct vhost_virtqueue *vq,
                                    unsigned idx)
{
    int r;
    int vhost_vq_index = idx - dev->vq_index;
    struct vhost_vring_state state = {
        .index = vhost_vq_index,
    };

    if (!virtio_queue_get_desc_addr(vdev, idx)) {
        return;
	}

	printk(">>>>>%s:%d \n", __func__, __LINE__);

    r = dev->ioctl_hook(dev->opaque, VHOST_GET_VRING_BASE, (uint64_t)&state);
    if (r < 0) {
		printk(">>>>>%s:%d \n", __func__, __LINE__);
        virtio_queue_restore_last_avail_idx(vdev, idx);
    } else {
		printk(">>>>>%s:%d \n", __func__, __LINE__);
        virtio_queue_set_last_avail_idx(vdev, idx, state.num);
    }

    virtio_queue_invalidate_signalled_used(vdev, idx);
    virtio_queue_update_used_idx(vdev, idx);
}

/* Host notifiers must be enabled at this point. */
int vhost_dev_start(struct vhost_dev *hdev, VirtIODevice *vdev)
{   
    int i, r;
	struct gfn_to_hva_cache ghc;
	struct kvm *kvm = vdev->pci_dev.bus->kvm;

    hdev->started = true;
    hdev->vdev = vdev;
    
    r = vhost_dev_set_features(hdev);
    if (r < 0) {
        goto fail_features;
	}
    
	//set ram memory
	if (!kvm_gfn_to_hva_cache_init(kvm, &ghc, 0, RAM_SIZE)) {
    	int regions_size = offsetof(struct vhost_memory, regions) +
                       1 * sizeof(struct vhost_memory_region);
		struct vhost_memory *mem = kzalloc(regions_size, GFP_KERNEL);
    	struct vhost_memory_region *vmr = mem->regions;

		mem->nregions = 1;

    	vmr->guest_phys_addr = 0;
    	vmr->memory_size     = RAM_SIZE;
    	vmr->userspace_addr  = ghc.hva;
    	vmr->flags_padding   = 0;
	
    	r = hdev->ioctl_hook(hdev->opaque, VHOST_SET_MEM_TABLE, (uint64_t)(void*)mem);
	    if (r < 0) {
        	printk(">>>>>%s:%d error: vhost_set_mem_table failed ret=%d\n",
				__func__, __LINE__, r);
    	}

		kfree(mem);
	} else {
		printk(">>>>>error: fail to get ram hva %s:%d\n", __func__, __LINE__);
	}

  //  printk(">>>>>%s:%d %d %d\n", __func__, __LINE__, hdev->nvqs, hdev->vq_index);

    for (i = 0; i < hdev->nvqs; ++i) {
        r = vhost_virtqueue_start(hdev,
                                  vdev,
                                  hdev->vqs + i,
                                  hdev->vq_index + i);
        if (r < 0) {
        	printk(">>>>>%s:%d\n", __func__, __LINE__);
            goto fail_vq;
        }
    }

    return 0;

fail_vq:
    while (--i >= 0) {
        vhost_virtqueue_stop(hdev,
                             vdev,
                             hdev->vqs + i,
                             hdev->vq_index + i);
    }

fail_features:
    hdev->started = false;
    return r;
}

void event_notifier_set(VirtQueue *vq)
{
	wait_queue_head_t *head = vq->wq_head;

	if (head != NULL) {
		wake_up_poll(head, POLLIN);
	}
}

void *vhost_alloc_notify_evt_(uint64_t evt_id,
			struct wait_queue_entry *entry, uint64_t kvm_id)
{
	struct evt_node *evt, *tmp;
	wait_queue_head_t *head;
	struct kvm *kvm = find_kvm_by_id(kvm_id);

	head = kzalloc(sizeof(wait_queue_head_t), GFP_KERNEL);
	if (!head) {
		printk(">>>>>error %s:%d\n",__func__, __LINE__);
		return NULL;
	}

	init_waitqueue_head(head);
	add_wait_queue(head, entry);

	list_for_each_entry_safe(evt, tmp, &kvm->evt_list, list) {
		if (evt->vq->evt_id == evt_id) {
			evt->vq->wq_head = head;
		}
	}

	printk(">>>>>%s:%d evt_head=%lx\n",__func__, __LINE__, head);

	return head;
}

static int virtio_set_host_notifier(VirtIODevice *vdev, int n, bool assign)
{
	struct kvm *kvm = vdev->pci_dev.bus->kvm;
    static uint64_t evt_id = 1;
	struct evt_node *evt, *tmp;
    VirtQueue *vq = virtio_get_queue(vdev, n);

    if (assign) { 
    	vq->evt_id = evt_id++;

		evt = kzalloc(sizeof(*evt), GFP_KERNEL);
		if (!evt)
			return -ENOMEM;

		evt->vq = vq;
		INIT_LIST_HEAD(&evt->list);

		list_add(&evt->list, &kvm->evt_list);
    } else {                             
		list_for_each_entry_safe(evt, tmp, &kvm->evt_list, list) {
			if (evt->vq->evt_id == vq->evt_id) {
				vq->wq_head = NULL;

				list_del(&evt->list);
				kfree(evt);
			}
		}
    }
        
	vq->host_notifier_enabled = assign;
    
    return 0;
}

int vhost_dev_enable_notifiers(struct vhost_dev *hdev, VirtIODevice *vdev)
{       
    int i, r, e;

    for (i = 0; i < hdev->nvqs; ++i) {
        r = virtio_set_host_notifier(vdev, hdev->vq_index + i,
                                         true);
        if (r < 0) {
            printk(">>>>>%s:%d vhost VQ %d notifier binding failed: %d",
					__func__, __LINE__, i, -r);
            goto fail_vq;
        }
    }

    return 0;
fail_vq:
    while (--i >= 0) {
        e = virtio_set_host_notifier(vdev, hdev->vq_index + i,
                                         false);
        if (e < 0) {
            printk(">>>>>>%s:%d vhost VQ %d notifier cleanup error: %d",
				__func__, __LINE__, i, -r);
        }
    }
    return r;
}

static void msix_unset_notifier_for_vector(PCIDevice *dev, unsigned int vector)
{
    if (msix_is_masked(dev, vector))
        return;

    if (!dev->msix_vector_use_notifier)
    	dev->msix_vector_release_notifier(dev, vector);
}

static void msix_unset_vector_notifiers(PCIDevice *dev)
{       
    int vector;
            
    if ((dev->config[dev->msix_cap + MSIX_CONTROL_OFFSET] &
        (MSIX_ENABLE_MASK | MSIX_MASKALL_MASK)) == MSIX_ENABLE_MASK) {
        for (vector = 0; vector < msix_nr_vectors_allocated(dev); vector++) {
            msix_unset_notifier_for_vector(dev, vector);
        }
    }

    dev->msix_vector_use_notifier = NULL;
    dev->msix_vector_release_notifier = NULL;
    dev->msix_vector_poll_notifier = NULL;
}

static void kvm_virtio_pci_vq_vector_release(VirtIODevice *vdev,
                                             unsigned int vector)
{
    VirtIOIRQFD *irqfd = &vdev->vector_irqfd[vector];
	struct kvm *kvm = vdev->pci_dev.bus->kvm;

    if (--irqfd->users == 0)
        kvm_irqchip_release_virq(kvm, irqfd->virq);
}

static void kvm_virtio_pci_vector_release(VirtIODevice *vdev, int nvqs)
{
    PCIDevice *dev = &vdev->pci_dev;
    unsigned int vector;
    int queue_no;

    for (queue_no = 0; queue_no < nvqs; queue_no++) {
        if (!virtio_queue_get_num(vdev, queue_no))
            break;

        vector = virtio_queue_vector(vdev, queue_no);
        if (vector >= msix_nr_vectors_allocated(dev))
            continue;

        kvm_virtio_pci_vq_vector_release(vdev, vector);
    }
}

static int virtio_pci_set_guest_notifier(VirtIODevice *vdev, int n, bool assign,
                                         bool with_irqfd)
{
    if (!msix_enabled(&vdev->pci_dev) &&
        vdev->guest_notifier_mask)
        vdev->guest_notifier_mask(vdev, n, !assign);

    return 0;
}

static int kvm_virtio_pci_vq_vector_use(VirtIODevice *vdev,
                                        unsigned int queue_no,
                                        unsigned int vector)
{
    VirtIOIRQFD *irqfd = &vdev->vector_irqfd[vector];
	struct kvm *kvm = vdev->pci_dev.bus->kvm;
    int ret;

    if (irqfd->users == 0) {
        ret = kvm_irqchip_add_msi_route(kvm, vector, &vdev->pci_dev);
        if (ret < 0) {
        	printk(">>>>>%s:%d\n", __func__, __LINE__);
            return ret;
        }

        irqfd->virq = ret;
    }

    irqfd->users++;

    return 0;
}

static int kvm_virtio_pci_vector_use(VirtIODevice *vdev, int nvqs)
{
    PCIDevice *dev = &vdev->pci_dev;
    unsigned int vector;
    int ret, queue_no;

    for (queue_no = 0; queue_no < nvqs; queue_no++) {
        if (!virtio_queue_get_num(vdev, queue_no))
            break;

        vector = virtio_queue_vector(vdev, queue_no);
        if (vector >= msix_nr_vectors_allocated(dev))
            continue;

		//add virq(gsi)=>msi mapping entry to kvm
        ret = kvm_virtio_pci_vq_vector_use(vdev, queue_no, vector);
        if (ret < 0)
            goto undo;
    }
    return 0;

undo:
    while (--queue_no >= 0) {
        vector = virtio_queue_vector(vdev, queue_no);
        if (vector >= msix_nr_vectors_allocated(dev))
            continue;

        kvm_virtio_pci_vq_vector_release(vdev, vector);
    }
    return ret;
}

static VirtQueue *virtio_vector_first_queue(VirtIODevice *vdev, uint16_t vector)
{   
    return QLIST_FIRST(&vdev->vector_queues[vector]);
}       
            
static VirtQueue *virtio_vector_next_queue(VirtQueue *vq)
{       
    return QLIST_NEXT(vq, node);
}  

static int virtio_pci_vq_vector_unmask(VirtIODevice *vdev,
                                       unsigned int queue_no,
                                       unsigned int vector,
                                       MSIMessage msg)
{
	struct kvm *kvm = vdev->pci_dev.bus->kvm;
    VirtIOIRQFD *irqfd = &vdev->vector_irqfd[vector];
    int ret = 0;

    if (vdev->vector_irqfd) {
        if (irqfd->msg.data != msg.data || irqfd->msg.address != msg.address) {
            ret = kvm_irqchip_update_msi_route(kvm, irqfd->virq, msg,
                                               &vdev->pci_dev);
            if (ret < 0) {
        		printk(">>>>>%s:%d\n", __func__, __LINE__);
                return ret;
			}

            kvm_irqchip_commit_routes(kvm);
        }
    }

    if (vdev->guest_notifier_mask) {
        vdev->guest_notifier_mask(vdev, queue_no, false);

        /* Test after unmasking to avoid losing events. */
        if (vdev->guest_notifier_pending &&
            vdev->guest_notifier_pending(vdev, queue_no)) {
			//there is irq pending, inject right now
			void *priv = vhost_alloc_irq_entry_kvm(kvm->id, irqfd->virq);
			vhost_inject_virq_kvm(kvm->id, priv);
			kfree(priv);
        }
    }

    return ret;
}

static void virtio_pci_vq_vector_mask(VirtIODevice *vdev,
                                             unsigned int queue_no,
                                             unsigned int vector)
{
    /* If guest supports masking, keep irqfd but mask it.
     * Otherwise, clean it up now.
     */
    if (vdev->guest_notifier_mask)
        vdev->guest_notifier_mask(vdev, queue_no, true);
}

static int virtio_pci_vector_unmask(PCIDevice *dev, unsigned vector,
                                    MSIMessage msg)
{
    VirtIODevice *vdev = container_of(dev, VirtIODevice, pci_dev);
    VirtQueue *vq = virtio_vector_first_queue(vdev, vector);
    int ret, index, unmasked = 0;

    while (vq) {
        index = virtio_get_queue_index(vq);
        if (!virtio_queue_get_num(vdev, index))
            break;

        if (index < vdev->nvqs_with_notifiers) {
            ret = virtio_pci_vq_vector_unmask(vdev, index, vector, msg);
            if (ret < 0) {
        		printk(">>>>>%s:%d\n", __func__, __LINE__);
                goto undo;
            }
            ++unmasked;
        }

        vq = virtio_vector_next_queue(vq);
    }

    return 0;

undo:
    vq = virtio_vector_first_queue(vdev, vector);
    while (vq && unmasked >= 0) {
        index = virtio_get_queue_index(vq);
        if (index < vdev->nvqs_with_notifiers) {
            virtio_pci_vq_vector_mask(vdev, index, vector);
            --unmasked;
        }
        vq = virtio_vector_next_queue(vq);
    }
    return ret;
}

static void virtio_pci_vector_mask(PCIDevice *dev, unsigned vector)
{
    VirtIODevice *vdev = container_of(dev, VirtIODevice, pci_dev);
    VirtQueue *vq = virtio_vector_first_queue(vdev, vector);
    int index;

    while (vq) {
        index = virtio_get_queue_index(vq);
        if (!virtio_queue_get_num(vdev, index))
            break;

        if (index < vdev->nvqs_with_notifiers)
            virtio_pci_vq_vector_mask(vdev, index, vector);

        vq = virtio_vector_next_queue(vq);
    }
}

static void virtio_pci_vector_poll(PCIDevice *dev,
                                   unsigned int vector_start,
                                   unsigned int vector_end)
{
    VirtIODevice *vdev = container_of(dev, VirtIODevice, pci_dev);
    int queue_no;
    unsigned int vector;

    for (queue_no = 0; queue_no < vdev->nvqs_with_notifiers; queue_no++) {
        if (!virtio_queue_get_num(vdev, queue_no))
            break;

        vector = virtio_queue_vector(vdev, queue_no);
        if (vector < vector_start || vector >= vector_end ||
            !msix_is_masked(dev, vector))
            continue;

        if (vdev->guest_notifier_pending)
            if (vdev->guest_notifier_pending(vdev, queue_no))
                msix_set_pending(dev, vector);
    }
}

int virtio_pci_set_guest_notifiers(VirtIODevice *vdev, int nvqs, bool assign)
{
    int r, n;
    bool with_irqfd = msix_enabled(&vdev->pci_dev);

    nvqs = MIN(nvqs, VIRTIO_QUEUE_MAX);
    vdev->nvqs_with_notifiers = nvqs;

    /* Must unset vector notifier while guest notifier is still assigned */
    if ((vdev->vector_irqfd || vdev->guest_notifier_mask) && !assign) {
        msix_unset_vector_notifiers(&vdev->pci_dev);
        if (vdev->vector_irqfd) {
            kvm_virtio_pci_vector_release(vdev, nvqs);
            kfree(vdev->vector_irqfd);
            vdev->vector_irqfd = NULL;
        }
    }

    for (n = 0; n < nvqs; n++) {
        if (!virtio_queue_get_num(vdev, n))
            break;

        r = virtio_pci_set_guest_notifier(vdev, n, assign, with_irqfd);
        if (r < 0) {
        	printk(">>>>>%s:%d\n", __func__, __LINE__);
            goto assign_error;
		}
    }

    /* Must set vector notifier after guest notifier has been assigned */
    if ((with_irqfd || vdev->guest_notifier_mask) && assign) {
        if (with_irqfd) {
            vdev->vector_irqfd =
                kzalloc(sizeof(*vdev->vector_irqfd) *
                          msix_nr_vectors_allocated(&vdev->pci_dev), GFP_KERNEL);

			//add virq(gsi)=>msi mapping entry to kvm
            r = kvm_virtio_pci_vector_use(vdev, nvqs);
            if (r < 0) {
        		printk(">>>>>%s:%d\n", __func__, __LINE__);
                goto assign_error;
            }
        }

        r = msix_set_vector_notifiers(&vdev->pci_dev,
                                      virtio_pci_vector_unmask,
                                      virtio_pci_vector_mask,
                                      virtio_pci_vector_poll);
        if (r < 0) {
        	printk(">>>>>%s:%d\n", __func__, __LINE__);
            goto notifiers_error;
        }
    }

    return 0;

notifiers_error:
    if (with_irqfd)
        kvm_virtio_pci_vector_release(vdev, nvqs);

assign_error:
    /* We get here on assignment failure. Recover by undoing for VQs 0 .. n. */
    while (--n >= 0)
        virtio_pci_set_guest_notifier(vdev, n, !assign, with_irqfd);

    return r;
}


static int vhost_virtqueue_init(struct vhost_dev *dev,
                                struct vhost_virtqueue *vq, int n)
{       
    int r;
    int vhost_vq_index = n - dev->vq_index;
    struct vhost_vring_file file = {
        .index = vhost_vq_index,
    };  
        
    file.fd = 1;
    r = dev->ioctl_hook(dev->opaque, VHOST_SET_VRING_CALL, (uint64_t)&file);
    if (r < 0) {
        printk(">>>>%s:%d error: vhost_set_vring_call failed\n",
			__func__, __LINE__);
        goto fail_call;
    }   
        
    vq->dev = dev;

    return 0;
        
fail_call:
    return r;
}

static int vhost_virtqueue_set_busyloop_timeout(struct vhost_dev *dev,
                                                int n, uint32_t timeout)
{
    int vhost_vq_index = n - dev->vq_index;
    struct vhost_vring_state state = {
        .index = vhost_vq_index,
        .num = timeout,
    };
    int r;

    r = dev->ioctl_hook(dev->opaque, VHOST_SET_VRING_BUSYLOOP_TIMEOUT, (uint64_t)&state);
    if (r) {
        printk(">>>>>>>%s:%d vhost_set_vring_busyloop_timeout failed\n",
			__func__, __LINE__);
        return r;
    }

    return 0;
}

void vhost_dev_cleanup_(struct vhost_dev *hdev)
{
    hdev->release_hook(hdev->opaque);

    memset(hdev, 0, sizeof(struct vhost_dev));
}

int vhost_dev_init_(struct vhost_dev *hdev, void *opaque,
                   uint32_t busyloop_timeout)
{
    uint64_t features;
    int i, r, n_initialized_vqs = 0;

    hdev->vdev = NULL;
	hdev->opaque = opaque;

    r = hdev->ioctl_hook(hdev->opaque, VHOST_SET_OWNER, 0);
    if (r < 0) {
        printk(">>>>>>%s:%d error: vhost_set_owner failed\n",
			__func__, __LINE__);
        goto fail;
    }

    r = hdev->ioctl_hook(hdev->opaque, VHOST_GET_FEATURES, (uint64_t)&features);
    if (r < 0) {
        printk(">>>>>>%s:%d error: vhost_get_features failed\n",
			__func__, __LINE__);
        goto fail;
    }

    for (i = 0; i < hdev->nvqs; ++i, ++n_initialized_vqs) {
        r = vhost_virtqueue_init(hdev, hdev->vqs + i, hdev->vq_index + i);
        if (r < 0) {
        	printk(">>>>>%s:%d\n", __func__, __LINE__);
            goto fail;
        }
    }

    if (busyloop_timeout) {
        for (i = 0; i < hdev->nvqs; ++i) {
            r = vhost_virtqueue_set_busyloop_timeout(hdev, hdev->vq_index + i,
                                                     busyloop_timeout);
            if (r < 0) {
                goto fail_busyloop;
            }
        }
    }
    hdev->features = features;

    hdev->started = false;

    return 0;

fail_busyloop:
    while (--i >= 0) {
        vhost_virtqueue_set_busyloop_timeout(hdev, hdev->vq_index + i, 0);
    }
fail:
    hdev->nvqs = n_initialized_vqs;
    vhost_dev_cleanup_(hdev);
    return r;
}

VirtQueue *virtio_add_queue(VirtIODevice *vdev, int queue_size,
                            VirtIOHandleOutput handle_output)
{   
    int i;
    
    for (i = 0; i < VIRTIO_QUEUE_MAX; i++)
        if (vdev->vq[i].vring.num == 0)
            break;

    if (i == VIRTIO_QUEUE_MAX || queue_size > VIRTQUEUE_MAX_SIZE) {
		printk(">>>>error: %s:%d\n", __func__, __LINE__);
		return NULL;
	}
    
    vdev->vq[i].vring.num = queue_size;
    vdev->vq[i].vring.num_default = queue_size;
    vdev->vq[i].vring.align = VIRTIO_PCI_VRING_ALIGN;
    vdev->vq[i].handle_output = handle_output;
    vdev->vq[i].used_elems = kzalloc(sizeof(VirtQueueElement) *
                                       queue_size, GFP_KERNEL);

    return &vdev->vq[i];
}

void virtio_del_queue(VirtIODevice *vdev, int n)
{
    if (n < 0 || n >= VIRTIO_QUEUE_MAX)
		return;
    
    vdev->vq[n].vring.num = 0;
    vdev->vq[n].vring.num_default = 0;
    vdev->vq[n].handle_output = NULL;
    kfree(vdev->vq[n].used_elems);
}

void virtio_init(VirtIODevice *vdev, const char *name,
                 uint16_t device_id, size_t config_size)
{
    int i;
    int nvectors = vdev->nvectors;

    if (nvectors)
        vdev->vector_queues =
            kzalloc(sizeof(*vdev->vector_queues) * nvectors, GFP_KERNEL);

    vdev->start_on_kick = false;
    vdev->device_id = device_id;
    vdev->status = 0;
    atomic_set(&vdev->isr_val, 0);
    vdev->queue_sel = 0;
    vdev->config_vector = VIRTIO_NO_VECTOR;
    vdev->vq = kzalloc(sizeof(VirtQueue) * VIRTIO_QUEUE_MAX, GFP_KERNEL);
    vdev->broken = false;

    for (i = 0; i < VIRTIO_QUEUE_MAX; i++) {
        vdev->vq[i].vector = VIRTIO_NO_VECTOR;
        vdev->vq[i].vdev = vdev;
        vdev->vq[i].queue_index = i;
        vdev->vq[i].host_notifier_enabled = false;
    }

    vdev->name = (char*)name;
    vdev->config_len = config_size;
    if (vdev->config_len) {
        vdev->config = kzalloc(config_size, GFP_KERNEL);
    } else {
        vdev->config = NULL;
    }
}

void virtio_cleanup_(VirtIODevice *vdev)
{
    kfree(vdev->config);
    kfree(vdev->vector_queues);
    kfree(vdev->vq);
}

uint64_t vhost_get_features(struct vhost_dev *hdev, const int *feature_bits,
                            uint64_t features)
{
    const int *bit = feature_bits;

    while (*bit != VHOST_INVALID_FEATURE_BIT) {
        uint64_t bit_mask = (1ULL << *bit);

        if (!(hdev->features & bit_mask))
            features &= ~bit_mask;

        bit++;
    }   

    return features; 
} 

bool vhost_virtqueue_pending(struct vhost_dev *hdev, int n)
{   
    int ret = 0;
    
    //return atomic_read_and_clear(&vq->notified);
    
    return ret;
}  

static void virtio_pci_realize(VirtIODevice *vdev)
{                              
    vdev->legacy_io_bar_idx  = 0;
    vdev->msix_bar_idx       = 1;
    vdev->modern_mem_bar_idx = 4;

    vdev->common.offset = MODERN_BAR_COMMON_OFFSET;
    vdev->common.size = REGION_SIZE;
    vdev->common.type = VIRTIO_PCI_CAP_COMMON_CFG;

    vdev->isr.offset = MODERN_BAR_ISR_OFFSET;
    vdev->isr.size = REGION_SIZE;
    vdev->isr.type = VIRTIO_PCI_CAP_ISR_CFG;

    vdev->device.offset = MODERN_BAR_DEVICE_OFFSET;
    vdev->device.size = REGION_SIZE;
    vdev->device.type = VIRTIO_PCI_CAP_DEVICE_CFG;

    vdev->notify.offset = MODERN_BAR_NOTIFY_OFFSET;
    vdev->notify.size = virtio_pci_queue_mem_mult(vdev) * VIRTIO_QUEUE_MAX;
    vdev->notify.type = VIRTIO_PCI_CAP_NOTIFY_CFG;
}

static int virtio_pci_add_mem_cap(VirtIODevice *vdev,
                                   struct virtio_pci_cap *cap)
{
    PCIDevice *dev = &vdev->pci_dev;
    int offset;

    offset = pci_add_capability(dev, PCI_CAP_ID_VNDR, 0,
                                cap->cap_len);
	if (offset < 0)
		return offset;

    memcpy(dev->config + offset + PCI_CAP_FLAGS, &cap->cap_len,
           cap->cap_len - PCI_CAP_FLAGS);

    return offset;
}

static void virtio_pci_modern_mem_region_map(VirtIODevice *vdev,
                                             VirtIOPCIRegion *region,
                                             struct virtio_pci_cap *cap)
{
    cap->cfg_type = region->type;
    cap->bar = vdev->modern_mem_bar_idx;
    cap->offset = cpu_to_le32(region->offset);
    cap->length = cpu_to_le32(region->size);
    virtio_pci_add_mem_cap(vdev, cap);
}

static uint32_t virtio_pci_common_read(VirtIODevice *vdev, hwaddr offset,
                                       unsigned size)
{
    uint32_t val = 0;
    int i;

    switch (offset) {
    case VIRTIO_PCI_COMMON_DFSELECT:
        val = vdev->dfselect;
        break;
    case VIRTIO_PCI_COMMON_DF:
        if (vdev->dfselect <= 1) {
            val = (vdev->host_features & ~vdev->legacy_features) >>
                (32 * vdev->dfselect);
        }
        break;
    case VIRTIO_PCI_COMMON_GFSELECT:
        val = vdev->gfselect;
        break;
    case VIRTIO_PCI_COMMON_GF:
        if (vdev->gfselect < ARRAY_SIZE(vdev->pci_guest_features)) {
            val = vdev->pci_guest_features[vdev->gfselect];
        }
        break;
    case VIRTIO_PCI_COMMON_MSIX:
        val = vdev->config_vector;
        break;
    case VIRTIO_PCI_COMMON_NUMQ:
        for (i = 0; i < VIRTIO_QUEUE_MAX; ++i) {
            if (virtio_queue_get_num(vdev, i)) {
                val = i + 1;
            }
        }
        break;
    case VIRTIO_PCI_COMMON_STATUS:
        val = vdev->status;
        break;
    case VIRTIO_PCI_COMMON_CFGGENERATION:
        val = vdev->generation;
        break;
    case VIRTIO_PCI_COMMON_Q_SELECT:
        val = vdev->queue_sel;
        break;
    case VIRTIO_PCI_COMMON_Q_SIZE:
        val = virtio_queue_get_num(vdev, vdev->queue_sel);
        break;
    case VIRTIO_PCI_COMMON_Q_MSIX:
        val = virtio_queue_vector(vdev, vdev->queue_sel);
        break;
    case VIRTIO_PCI_COMMON_Q_ENABLE:
        val = vdev->vq[vdev->queue_sel].vq_config_buf.enabled;
        break;
    case VIRTIO_PCI_COMMON_Q_NOFF:
        /* Simply map queues in order */
        val = vdev->queue_sel;
        break;
    case VIRTIO_PCI_COMMON_Q_DESCLO:
        val = vdev->vq[vdev->queue_sel].vq_config_buf.desc[0];
        break;
    case VIRTIO_PCI_COMMON_Q_DESCHI:
        val = vdev->vq[vdev->queue_sel].vq_config_buf.desc[1];
        break;
    case VIRTIO_PCI_COMMON_Q_AVAILLO:
        val = vdev->vq[vdev->queue_sel].vq_config_buf.avail[0];
        break;
    case VIRTIO_PCI_COMMON_Q_AVAILHI:
        val = vdev->vq[vdev->queue_sel].vq_config_buf.avail[1];
        break;
    case VIRTIO_PCI_COMMON_Q_USEDLO:
        val = vdev->vq[vdev->queue_sel].vq_config_buf.used[0];
        break;
    case VIRTIO_PCI_COMMON_Q_USEDHI:
        val = vdev->vq[vdev->queue_sel].vq_config_buf.used[1];
        break;
    default:
        val = 0;
    }

    return val;
}

static int virtio_pci_isr_read(void *opaque, hwaddr offset,
                                    unsigned size)
{
    VirtIODevice *vdev = opaque;
    int val = atomic_xchg(&vdev->isr_val, 0);

    pci_irq_deassert(&vdev->pci_dev);

    return val;
}

static uint8_t virtio_config_readb(VirtIODevice *vdev, uint32_t addr)
{       
    uint8_t val = 0;
    
    if (addr + sizeof(val) > vdev->config_len)
        return (uint32_t)-1;
    
    if (vdev->get_config)
    	vdev->get_config(vdev, vdev->config);

    val = *(uint8_t*)(vdev->config + addr);

    return val;                     
}

static uint16_t virtio_config_readw(VirtIODevice *vdev, uint32_t addr)
{   
    uint16_t val = 0;

    if (addr + sizeof(val) > vdev->config_len)
        return (uint32_t)-1;

    if (vdev->get_config)
    	vdev->get_config(vdev, vdev->config);

    val = *(uint16_t*)(vdev->config + addr);

    return val;
}

static uint32_t virtio_config_readl(VirtIODevice *vdev, uint32_t addr)
{
    uint32_t val = 0;

    if (addr + sizeof(val) > vdev->config_len)
        return (uint32_t)-1;

    if (vdev->get_config)
    	vdev->get_config(vdev, vdev->config);

    val = *(uint32_t*)(vdev->config + addr);

    return val;
}

static void virtio_pci_device_read(VirtIODevice *vdev, hwaddr addr,
                                       const void *val, unsigned size)
{

    switch (size) {
    case 1:
        *(uint8_t*)val = virtio_config_readb(vdev, addr);
        break;
    case 2:
        *(uint16_t*)val = virtio_config_readw(vdev, addr);
        break;
    case 4:
        *(uint32_t*)val = virtio_config_readl(vdev, addr);
        break;
    }
}

static void _modern_bar_read(VirtIODevice *vdev, hwaddr offset,
                                    const void *val, unsigned len)
{
    if (offset >= MODERN_BAR_COMMON_OFFSET &&
		offset < MODERN_BAR_ISR_OFFSET) {
		//read common region
		*(uint32_t*)val = virtio_pci_common_read(vdev, offset, len);
	} else if (offset >= MODERN_BAR_ISR_OFFSET &&
		offset < MODERN_BAR_DEVICE_OFFSET) {
		//read isr region
		*(int*)val = virtio_pci_isr_read(vdev,
								offset - MODERN_BAR_ISR_OFFSET, len);
	} else if (offset >= MODERN_BAR_DEVICE_OFFSET &&
		offset < MODERN_BAR_NOTIFY_OFFSET) {
		//read device private region
		virtio_pci_device_read(vdev,
							offset - MODERN_BAR_DEVICE_OFFSET, val, len);
	} else if (offset >= MODERN_BAR_NOTIFY_OFFSET) {
		//read notify region
		*(uint64_t*)val = 0;
	}
}

static int modern_bar_read(struct kvm_vcpu *vcpu, struct kvm_io_device *dev,
			      gpa_t addr, int len, void *val)
{
	PCIIORegion *r = container_of(dev, PCIIORegion, dev);
	PCIDevice *pci_dev = r->pci_dev;
	VirtIODevice *vdev = container_of(pci_dev, VirtIODevice, pci_dev);
	uint32_t offset = addr - r->addr;	

//	printk(">>>>>%s:%d\n", __func__, __LINE__);

	_modern_bar_read(vdev, offset, val, len);

	return 0;
}

static int virtio_validate_features(VirtIODevice *vdev)
{
    if (virtio_host_has_feature(vdev, VIRTIO_F_IOMMU_PLATFORM) &&
        !virtio_vdev_has_feature(vdev, VIRTIO_F_IOMMU_PLATFORM)) {
        printk(">>>>>%s:%d\n", __func__, __LINE__);
        return -EFAULT;
    }

    if (vdev->validate_features) {
        return vdev->validate_features(vdev);
    } else {
        return 0;
    }
}

static void virtio_set_started(VirtIODevice *vdev, bool started)
{           
    if (started)
        vdev->start_on_kick = false;
}

int virtio_set_status(VirtIODevice *vdev, uint8_t val)
{
    if (virtio_vdev_has_feature(vdev, VIRTIO_F_VERSION_1)) {
        if (!(vdev->status & VIRTIO_CONFIG_S_FEATURES_OK) &&
            val & VIRTIO_CONFIG_S_FEATURES_OK) {
            int ret = virtio_validate_features(vdev);
            if (ret)
                return ret;
        }
    }   
    
    if ((vdev->status & VIRTIO_CONFIG_S_DRIVER_OK) != 
        (val & VIRTIO_CONFIG_S_DRIVER_OK))
        virtio_set_started(vdev, val & VIRTIO_CONFIG_S_DRIVER_OK);

    if (vdev->set_status)
        vdev->set_status(vdev, val);

    vdev->status = val;

    return 0;
}

static void virtio_pci_notify(VirtIODevice *vdev, uint16_t vector)
{
    if (msix_enabled(&vdev->pci_dev))
        msix_notify(&vdev->pci_dev, vector);
    else {
        pci_set_irq(&vdev->pci_dev, atomic_read(&vdev->isr_val) & 1);
    }
}

void virtio_notify_vector(VirtIODevice *vdev, uint16_t vector)
{
    if (unlikely(vdev->broken))
        return;

    virtio_pci_notify(vdev, vector);
}

static void virtio_queue_set_vector(VirtIODevice *vdev, int n, uint16_t vector)
{
    VirtQueue *vq = &vdev->vq[n];

    if (n < VIRTIO_QUEUE_MAX) {
        if (vdev->vector_queues &&
            vdev->vq[n].vector != VIRTIO_NO_VECTOR) {
            QLIST_REMOVE(vq, node);
        }

        vdev->vq[n].vector = vector;

        if (vdev->vector_queues &&
            vector != VIRTIO_NO_VECTOR) {
            QLIST_INSERT_HEAD(&vdev->vector_queues[vector], vq, node);
        }
    }
}

static void virtio_reset(VirtIODevice *vdev)
{
    int i;

    virtio_set_status(vdev, 0);

    if (vdev->reset)
        vdev->reset(vdev);

    vdev->start_on_kick = false;
    vdev->broken = false;
    vdev->guest_features = 0;
    vdev->queue_sel = 0;
    vdev->status = 0;
    atomic_set(&vdev->isr_val, 0);
    vdev->config_vector = VIRTIO_NO_VECTOR;
    virtio_notify_vector(vdev, vdev->config_vector);

    for(i = 0; i < VIRTIO_QUEUE_MAX; i++) {
        vdev->vq[i].vring.desc = 0;
        vdev->vq[i].vring.avail = 0;
        vdev->vq[i].vring.used = 0;
        vdev->vq[i].last_avail_idx = 0;
        vdev->vq[i].shadow_avail_idx = 0;
        vdev->vq[i].used_idx = 0;
        vdev->vq[i].last_avail_wrap_counter = true;
        vdev->vq[i].shadow_avail_wrap_counter = true;
        vdev->vq[i].used_wrap_counter = true;
        virtio_queue_set_vector(vdev, i, VIRTIO_NO_VECTOR);
        vdev->vq[i].signalled_used = 0;
        vdev->vq[i].signalled_used_valid = false;
        vdev->vq[i].notification = true;
        vdev->vq[i].vring.num = vdev->vq[i].vring.num_default;
        vdev->vq[i].inuse = 0;
    }
}

void virtio_pci_reset(VirtIODevice *vdev)
{
    int i;

    virtio_reset(vdev);
    msix_unuse_all_vectors(&vdev->pci_dev);

    for (i = 0; i < VIRTIO_QUEUE_MAX; i++) {
        vdev->vq[i].vq_config_buf.enabled = 0;
        vdev->vq[i].vq_config_buf.num = 0;
        vdev->vq[i].vq_config_buf.desc[0] = vdev->vq[i].vq_config_buf.desc[1] = 0;
        vdev->vq[i].vq_config_buf.avail[0] = vdev->vq[i].vq_config_buf.avail[1] = 0;
        vdev->vq[i].vq_config_buf.used[0] = vdev->vq[i].vq_config_buf.used[1] = 0;
    }
}

static void virtio_queue_set_num(VirtIODevice *vdev, int n, int num)
{       
    /* Don't allow guest to flip queue between existent and
     * nonexistent states, or to set it to an invalid size.
     */
    if (!!num != !!vdev->vq[n].vring.num ||
        num > VIRTQUEUE_MAX_SIZE || num < 0)
        return;        

    vdev->vq[n].vring.num = num;
}

static hwaddr virtio_queue_get_desc_size(VirtIODevice *vdev, int n)
{   
    return sizeof(VRingDesc) * vdev->vq[n].vring.num;
}

static hwaddr virtio_queue_get_used_size(VirtIODevice *vdev, int n)
{
    int s;
    
    if (virtio_vdev_has_feature(vdev, VIRTIO_F_RING_PACKED))
        return sizeof(struct VRingPackedDescEvent);
    
    s = virtio_vdev_has_feature(vdev, VIRTIO_RING_F_EVENT_IDX) ? 2 : 0;

    return offsetof(VRingUsed, ring) +
        sizeof(VRingUsedElem) * vdev->vq[n].vring.num + s;
}

static hwaddr virtio_queue_get_avail_size(VirtIODevice *vdev, int n)
{
    int s;

    if (virtio_vdev_has_feature(vdev, VIRTIO_F_RING_PACKED))
        return sizeof(struct VRingPackedDescEvent);

    s = virtio_vdev_has_feature(vdev, VIRTIO_RING_F_EVENT_IDX) ? 2 : 0;

    return offsetof(VRingAvail, ring) +
        sizeof(uint16_t) * vdev->vq[n].vring.num + s;
}

static void virtio_init_vq_region_hva(VirtIODevice *vdev, int n)
{
	struct kvm *kvm = vdev->pci_dev.bus->kvm;
    VirtQueue *vq = &vdev->vq[n];
    VRing *vr = &vq->vring;
	struct gfn_to_hva_cache ghc;
	hwaddr len;

	len = virtio_queue_get_desc_size(vdev, n);
	if (kvm_gfn_to_hva_cache_init(kvm, &ghc, vr->desc, len))
		printk(">>>>>error: fail to map vring desc %s:%d\n", __func__, __LINE__);
	else
		vq->desc_hva = ghc.hva;

	len = virtio_queue_get_avail_size(vdev, n);
	if (kvm_gfn_to_hva_cache_init(kvm, &ghc, vr->avail, len))
		printk(">>>>>error: fail to map vring desc %s:%d\n", __func__, __LINE__);
	else
		vq->avail_hva = ghc.hva;

	len = virtio_queue_get_used_size(vdev, n);
	if (kvm_gfn_to_hva_cache_init(kvm, &ghc, vr->used, len))
		printk(">>>>>error: fail to map vring desc %s:%d\n", __func__, __LINE__);
	else
		vq->used_hva = ghc.hva;
}


static void virtio_queue_set_rings(VirtIODevice *vdev, int n, hwaddr desc_gpa,
                            hwaddr avail_gpa, hwaddr used_gpa)
{       
    if (!vdev->vq[n].vring.num)
        return;        

    vdev->vq[n].vring.desc = desc_gpa;
    vdev->vq[n].vring.avail = avail_gpa;
    vdev->vq[n].vring.used = used_gpa;

	virtio_init_vq_region_hva(vdev, n);
}

static int virtio_set_features_nocheck(VirtIODevice *vdev, uint64_t val)
{
    bool bad = (val & ~(vdev->host_features)) != 0;

    val &= vdev->host_features;
    if (vdev->set_features)
        vdev->set_features(vdev, val);

    vdev->guest_features = val;

    return bad ? -1 : 0;
}

static inline bool virtio_device_started(VirtIODevice *vdev, uint8_t status)
{           
    return status & VIRTIO_CONFIG_S_DRIVER_OK;
}

static int virtio_set_features(VirtIODevice *vdev, uint64_t val)
{   
    int ret;
    if (vdev->status & VIRTIO_CONFIG_S_FEATURES_OK)
        return -EINVAL;

    ret = virtio_set_features_nocheck(vdev, val);
    if (!ret) {
        if (!virtio_device_started(vdev, vdev->status) &&
            !virtio_vdev_has_feature(vdev, VIRTIO_F_VERSION_1))
            vdev->start_on_kick = true;
    }   
    return ret;
}

static void virtio_pci_common_write(VirtIODevice *vdev, hwaddr offset,
                                    uint64_t val, unsigned size)
{
    switch (offset) {
    case VIRTIO_PCI_COMMON_DFSELECT:
        vdev->dfselect = val;
        break;
    case VIRTIO_PCI_COMMON_GFSELECT:
        vdev->gfselect = val;
        break;
    case VIRTIO_PCI_COMMON_GF:
        if (vdev->gfselect < ARRAY_SIZE(vdev->pci_guest_features)) {
            vdev->pci_guest_features[vdev->gfselect] = val;
            virtio_set_features(vdev,
                                (((uint64_t)vdev->pci_guest_features[1]) << 32) |
                                vdev->pci_guest_features[0]);
        }
        break;
    case VIRTIO_PCI_COMMON_MSIX:
        msix_vector_unuse(&vdev->pci_dev, vdev->config_vector);
        /* Make it possible for guest to discover an error took place. */
        if (msix_vector_use(&vdev->pci_dev, val) < 0) {
            val = VIRTIO_NO_VECTOR;
        }
        vdev->config_vector = val;
        break;
    case VIRTIO_PCI_COMMON_STATUS:
        virtio_set_status(vdev, val & 0xFF);

        if (vdev->status == 0)
            virtio_pci_reset(vdev);

        break;
    case VIRTIO_PCI_COMMON_Q_SELECT:
        if (val < VIRTIO_QUEUE_MAX) {
            vdev->queue_sel = val;
        }
        break;
    case VIRTIO_PCI_COMMON_Q_SIZE:
        vdev->vq[vdev->queue_sel].vq_config_buf.num = val;
        break;
    case VIRTIO_PCI_COMMON_Q_MSIX:
        msix_vector_unuse(&vdev->pci_dev,
                          virtio_queue_vector(vdev, vdev->queue_sel));
        /* Make it possible for guest to discover an error took place. */
        if (msix_vector_use(&vdev->pci_dev, val) < 0) {
            val = VIRTIO_NO_VECTOR;
        }
        virtio_queue_set_vector(vdev, vdev->queue_sel, val);
        break;
    case VIRTIO_PCI_COMMON_Q_ENABLE:
        virtio_queue_set_num(vdev, vdev->queue_sel,
                             vdev->vq[vdev->queue_sel].vq_config_buf.num);
        virtio_queue_set_rings(vdev, vdev->queue_sel,
                       ((uint64_t)vdev->vq[vdev->queue_sel].vq_config_buf.desc[1]) << 32 |
                       vdev->vq[vdev->queue_sel].vq_config_buf.desc[0],
                       ((uint64_t)vdev->vq[vdev->queue_sel].vq_config_buf.avail[1]) << 32 |
                       vdev->vq[vdev->queue_sel].vq_config_buf.avail[0],
                       ((uint64_t)vdev->vq[vdev->queue_sel].vq_config_buf.used[1]) << 32 |
                       vdev->vq[vdev->queue_sel].vq_config_buf.used[0]);
        vdev->vq[vdev->queue_sel].vq_config_buf.enabled = 1;
        break;
    case VIRTIO_PCI_COMMON_Q_DESCLO:
        vdev->vq[vdev->queue_sel].vq_config_buf.desc[0] = val;
        break;
    case VIRTIO_PCI_COMMON_Q_DESCHI:
        vdev->vq[vdev->queue_sel].vq_config_buf.desc[1] = val;
        break;
    case VIRTIO_PCI_COMMON_Q_AVAILLO:
        vdev->vq[vdev->queue_sel].vq_config_buf.avail[0] = val;
        break;
    case VIRTIO_PCI_COMMON_Q_AVAILHI:
        vdev->vq[vdev->queue_sel].vq_config_buf.avail[1] = val;
        break;
    case VIRTIO_PCI_COMMON_Q_USEDLO:
        vdev->vq[vdev->queue_sel].vq_config_buf.used[0] = val;
        break;
    case VIRTIO_PCI_COMMON_Q_USEDHI:
        vdev->vq[vdev->queue_sel].vq_config_buf.used[1] = val;
        break;
    default:
        break;
    }
}

static void virtio_config_writeb(VirtIODevice *vdev,
                                 uint32_t addr, uint32_t data)
{       
    uint8_t val = data;
    
    if (addr + sizeof(val) > vdev->config_len)
        return;

    *(uint8_t*)(vdev->config + addr) = val;

    if (vdev->set_config)
        vdev->set_config(vdev, vdev->config); 
}

static void virtio_config_writew(VirtIODevice *vdev,
                                 uint32_t addr, uint32_t data)
{       
    uint16_t val = data;
    
    if (addr + sizeof(val) > vdev->config_len) {
        return;
	}

	*(uint16_t*)(vdev->config + addr) = val;

    if (vdev->set_config)
        vdev->set_config(vdev, vdev->config); 
}

static void virtio_config_writel(VirtIODevice *vdev,
                                 uint32_t addr, uint32_t data)
{
    uint32_t val = data;

    if (addr + sizeof(val) > vdev->config_len) {
        return;
	}

	*(uint32_t*)(vdev->config + addr) = val;

    if (vdev->set_config)
        vdev->set_config(vdev, vdev->config);
}

static void virtio_pci_device_write(VirtIODevice *vdev, hwaddr addr,
                                    uint64_t val, unsigned size)
{
    switch (size) {
    case 1:
        virtio_config_writeb(vdev, addr, val);
        break;
    case 2:
        virtio_config_writew(vdev, addr, val);
        break;
    case 4:
        virtio_config_writel(vdev, addr, val);
        break;
    }
}

void event_notifier_set(VirtQueue *vq);

static void virtio_queue_notify(VirtIODevice *vdev, int n)
{                                   
    VirtQueue *vq = &vdev->vq[n];
    
    if (unlikely(!vq->vring.desc || vdev->broken)) {
        return;
	}

#if 0
	if (0 == strncmp(vdev->pci_dev.name,"vhost-net", 9)) {
		printk(">>>>%s:%d [%d] %d\n",__func__, __LINE__, n, vq->host_notifier_enabled);
	}
#endif

    if (vq->host_notifier_enabled) {
        event_notifier_set(vq);
    } else if (vq->handle_output) {
        vq->handle_output(vdev, vq);

        if (unlikely(vdev->start_on_kick))
            virtio_set_started(vdev, true);
    }
}

static void virtio_pci_notify_write(VirtIODevice *vdev, hwaddr addr,
                                    uint64_t val, unsigned size)
{
    unsigned queue = addr / virtio_pci_queue_mem_mult(vdev);

    if (queue < VIRTIO_QUEUE_MAX)
        virtio_queue_notify(vdev, queue);
}


static void _modern_bar_write(VirtIODevice *vdev, hwaddr offset,
                                    const void *val, unsigned len)
{
    if (offset >= MODERN_BAR_COMMON_OFFSET &&
			offset < MODERN_BAR_ISR_OFFSET) {
		virtio_pci_common_write(vdev, offset, *(uint64_t*)val, len);
	} else if (offset >= MODERN_BAR_ISR_OFFSET &&
			offset < MODERN_BAR_DEVICE_OFFSET) {
		//do nothing
	} else if (offset >= MODERN_BAR_DEVICE_OFFSET &&
			offset < MODERN_BAR_NOTIFY_OFFSET) {
		virtio_pci_device_write(vdev, offset - MODERN_BAR_DEVICE_OFFSET,
                                    *(uint64_t*)val, len);
	} else if (offset >= MODERN_BAR_NOTIFY_OFFSET) {
		virtio_pci_notify_write(vdev, offset - MODERN_BAR_NOTIFY_OFFSET,
                                    *(uint64_t*)val, len);
	}
}

static int modern_bar_write(struct kvm_vcpu *vcpu, struct kvm_io_device *dev,
			       gpa_t addr, int len, const void *val)
{
	PCIIORegion *r = container_of(dev, PCIIORegion, dev);
	PCIDevice *pci_dev = r->pci_dev;
	VirtIODevice *vdev = container_of(pci_dev, VirtIODevice, pci_dev);
	uint32_t offset = addr - r->addr;	

//	printk(">>>>>%s:%d\n", __func__, __LINE__);

	_modern_bar_write(vdev, offset, val, len);

	return 0;
}

static struct kvm_io_device_ops modern_bar_ops = {
	.read     = modern_bar_read,
	.write    = modern_bar_write,
};

static inline hwaddr vring_align(hwaddr addr,
                                             unsigned long align)
{
    return ALIGN_UP(addr, align);
}


static void virtio_queue_update_rings(VirtIODevice *vdev, int n)
{
    VRing *vring = &vdev->vq[n].vring;

    if (!vring->num || !vring->desc || !vring->align)
        return;

    vring->avail = vring->desc + vring->num * sizeof(VRingDesc);
    vring->used = vring_align(vring->avail +
                              offsetof(VRingAvail, ring[vring->num]),
                              vring->align);

	virtio_init_vq_region_hva(vdev, n);
}

static void virtio_queue_set_addr(VirtIODevice *vdev, int n, hwaddr addr)
{       
    if (!vdev->vq[n].vring.num)
        return;

    vdev->vq[n].vring.desc = addr;
    virtio_queue_update_rings(vdev, n);
}

static uint32_t virtio_get_vdev_bad_features(VirtIODevice *vdev)
{
    if (vdev->bad_features != NULL) {
        return vdev->bad_features(vdev);     
    } else {
        return 0;
    }
}

static void virtio_ioport_write(VirtIODevice *vdev, uint32_t addr, uint32_t val)
{
    hwaddr pa;

    switch (addr) {
    case VIRTIO_PCI_GUEST_FEATURES:
        if (val & (1 << VIRTIO_F_BAD_FEATURE))
            val = virtio_get_vdev_bad_features(vdev);

        virtio_set_features(vdev, val);
        break;
    case VIRTIO_PCI_QUEUE_PFN:
        pa = (hwaddr)val << VIRTIO_PCI_QUEUE_ADDR_SHIFT;
        if (pa == 0)
            virtio_pci_reset(vdev);
        else
            virtio_queue_set_addr(vdev, vdev->queue_sel, pa);
        break;
    case VIRTIO_PCI_QUEUE_SEL:
        if (val < VIRTIO_QUEUE_MAX)
            vdev->queue_sel = val;
        break;
    case VIRTIO_PCI_QUEUE_NOTIFY:
        if (val < VIRTIO_QUEUE_MAX)
            virtio_queue_notify(vdev, val);
        break;
    case VIRTIO_PCI_STATUS:
        virtio_set_status(vdev, val & 0xFF);

        if (vdev->status == 0)
            virtio_pci_reset(vdev);

        if (val == (VIRTIO_CONFIG_S_ACKNOWLEDGE | VIRTIO_CONFIG_S_DRIVER))
            pci_default_write_config(&vdev->pci_dev, PCI_COMMAND,
                                     vdev->pci_dev.config[PCI_COMMAND] |
                                     PCI_COMMAND_MASTER, 1);
        break;
    case VIRTIO_MSI_CONFIG_VECTOR:
        msix_vector_unuse(&vdev->pci_dev, vdev->config_vector);
        /* Make it possible for guest to discover an error took place. */
        if (msix_vector_use(&vdev->pci_dev, val) < 0)
            val = VIRTIO_NO_VECTOR;

        vdev->config_vector = val;
        break;
    case VIRTIO_MSI_QUEUE_VECTOR:
        msix_vector_unuse(&vdev->pci_dev,
                          virtio_queue_vector(vdev, vdev->queue_sel));
        /* Make it possible for guest to discover an error took place. */
        if (msix_vector_use(&vdev->pci_dev, val) < 0)
            val = VIRTIO_NO_VECTOR;

        virtio_queue_set_vector(vdev, vdev->queue_sel, val);
        break;
    default:
        break;
    }
}

static int legacy_bar_write(struct kvm_vcpu *vcpu, struct kvm_io_device *dev,
			       gpa_t addr, int len, const void *val)
{
	PCIIORegion *r = container_of(dev, PCIIORegion, dev);
	PCIDevice *pci_dev = r->pci_dev;
	VirtIODevice *vdev = container_of(pci_dev, VirtIODevice, pci_dev);
	uint32_t offset = addr - r->addr;	

    uint32_t config_size = VIRTIO_PCI_CONFIG_SIZE(pci_dev);

    if (offset < config_size) {
        virtio_ioport_write(vdev, offset, *(uint32_t*)val);
        return 0;
    }

    offset -= config_size;
    /*
     * Virtio-PCI is odd. Ioports are LE but config space is target native
     * endian.
     */
    switch (len) {
    case 1:
        virtio_config_writeb(vdev, offset, *(uint8_t*)val);
        break;
    case 2:
        virtio_config_writew(vdev, offset, *(uint16_t*)val);
        break;
    case 4:
        virtio_config_writel(vdev, offset, *(uint32_t*)val);
        break;
    }

	return 0;
}

static hwaddr virtio_queue_get_addr(VirtIODevice *vdev, int n)
{       
    return vdev->vq[n].vring.desc;
}

static int virtio_queue_get_num(VirtIODevice *vdev, int n)
{       
    return vdev->vq[n].vring.num;
} 

static uint32_t virtio_ioport_read(VirtIODevice *vdev, uint32_t addr)
{
    uint32_t ret = 0xFFFFFFFF;

    switch (addr) {
    case VIRTIO_PCI_HOST_FEATURES:
        ret = vdev->host_features;
        break;
    case VIRTIO_PCI_GUEST_FEATURES:
        ret = vdev->guest_features;
        break;
    case VIRTIO_PCI_QUEUE_PFN:
        ret = virtio_queue_get_addr(vdev, vdev->queue_sel)
              >> VIRTIO_PCI_QUEUE_ADDR_SHIFT;
        break;
    case VIRTIO_PCI_QUEUE_NUM:
        ret = virtio_queue_get_num(vdev, vdev->queue_sel);
        break;
    case VIRTIO_PCI_QUEUE_SEL:
        ret = vdev->queue_sel;
        break;
    case VIRTIO_PCI_STATUS:
        ret = vdev->status;
        break;
    case VIRTIO_PCI_ISR:
        /* reading from the ISR also clears it. */
        ret = atomic_xchg(&vdev->isr_val, 0);
        pci_irq_deassert(&vdev->pci_dev);
        break;
    case VIRTIO_MSI_CONFIG_VECTOR:
        ret = vdev->config_vector;
        break;
    case VIRTIO_MSI_QUEUE_VECTOR:
        ret = virtio_queue_vector(vdev, vdev->queue_sel);
        break;
    default:
        break;
    }

    return ret;
}

static int legacy_bar_read(struct kvm_vcpu *vcpu, struct kvm_io_device *dev,
			      gpa_t addr, int len, void *val)
{
	PCIIORegion *r = container_of(dev, PCIIORegion, dev);
	PCIDevice *pci_dev = r->pci_dev;
	VirtIODevice *vdev = container_of(pci_dev, VirtIODevice, pci_dev);
	uint32_t offset = addr - r->addr;	

	uint32_t config_size = VIRTIO_PCI_CONFIG_SIZE(pci_dev);

    if (offset < config_size) {
        *(uint32_t*)val = virtio_ioport_read(vdev, offset);
		return 0;
	}

    offset -= config_size;
    
    switch (len) {
    case 1: 
        *(uint8_t*)val = virtio_config_readb(vdev, offset);
        break;
    case 2: 
        *(uint16_t*)val = virtio_config_readw(vdev, offset);
        break;
    case 4: 
        *(uint32_t*)val = virtio_config_readl(vdev, offset);
        break;
    }

	return 0;
}

static struct kvm_io_device_ops legacy_bar_ops = {
	.read     = legacy_bar_read,
	.write    = legacy_bar_write,
};


static int virtio_address_space_lookup(VirtIODevice *vdev,
                                                 hwaddr *off, int len)
{   
    int i;
    VirtIOPCIRegion *reg;
    
    for (i = 0; i < ARRAY_SIZE(vdev->regs); ++i) {
        reg = &vdev->regs[i];
        if (*off >= reg->offset &&
            *off + len <= reg->offset + reg->size) {
            *off -= reg->offset;
            return 0;
        }
    }
    
    return -1;
}

static void virtio_address_space_read(VirtIODevice *vdev, hwaddr addr,
                          uint8_t *buf, int len)
{
	int ret;
    uint64_t val;

    addr &= ~(len - 1);

    ret = virtio_address_space_lookup(vdev, &addr, len);
    if (0 > ret) {
        return;
	}

	_modern_bar_read(vdev, addr, &val, len);

    switch (len) {
    case 1:
        pci_set_byte(buf, val);
        break;
    case 2:
        pci_set_word(buf, val);
        break;
    case 4:
        pci_set_long(buf, val);
        break;
    default:
        /* As length is under guest control, handle illegal values. */
        break;
    }
}

static uint32_t virtio_read_config(PCIDevice *pci_dev,
                                   uint32_t address, int len)
{
    VirtIODevice *vdev = (VirtIODevice*)pci_dev;
    struct virtio_pci_cfg_cap *cfg;

    if (vdev->config_cap &&
        ranges_overlap(address, len,
			vdev->config_cap + offsetof(struct virtio_pci_cfg_cap, pci_cfg_data),
                       sizeof cfg->pci_cfg_data)) {
        uint32_t off;
        uint32_t len;

        cfg = (void *)(pci_dev->config + vdev->config_cap);
        off = cfg->cap.offset;
        len = cfg->cap.length;

        if (len == 1 || len == 2 || len == 4)
            virtio_address_space_read(vdev, off, cfg->pci_cfg_data, len);
    }

    return pci_default_read_config(pci_dev, address, len);
}


static void virtio_address_space_write(VirtIODevice *vdev, hwaddr addr,
                                const uint8_t *buf, int len)
{
	int ret;
    uint64_t val;

    addr &= ~(len - 1);

    ret = virtio_address_space_lookup(vdev, &addr, len);
    if (0 > ret)
        return;

    switch (len) {
    case 1:
        val = pci_get_byte(buf);
        break;
    case 2:
        val = pci_get_word(buf);
        break;
    case 4:
        val = pci_get_long(buf);
        break;
    default:
        /* As length is under guest control, handle illegal values. */
        return;
    }

	_modern_bar_write(vdev, addr, &val, len);
}


static void virtio_write_config(PCIDevice *pci_dev, uint32_t address,
                                uint32_t val, int len)
{
    VirtIODevice *vdev = (VirtIODevice *)pci_dev;
    struct virtio_pci_cfg_cap *cfg;

    pci_default_write_config(pci_dev, address, val, len);

    if (range_covers_byte(address, len, PCI_COMMAND) &&
        !(pci_dev->config[PCI_COMMAND] & PCI_COMMAND_MASTER))
        virtio_set_status(vdev, vdev->status & ~VIRTIO_CONFIG_S_DRIVER_OK);

    //The following is to access vdev config apace without modern/legacy bar
    if (vdev->config_cap &&
        ranges_overlap(address, len,
			vdev->config_cap + offsetof(struct virtio_pci_cfg_cap, pci_cfg_data),
                       sizeof cfg->pci_cfg_data)) {
        uint32_t off;  
        uint32_t len;  
        
        cfg = (void *)(pci_dev->config + vdev->config_cap);
        off = cfg->cap.offset;
        len = cfg->cap.length;
        
        if (len == 1 || len == 2 || len == 4)
            virtio_address_space_write(vdev, off, cfg->pci_cfg_data, len);
    }   
} 

/* This is called by virtio-bus just after the device is plugged. */
static void virtio_pci_device_plugged(VirtIODevice *vdev)
{
    int err;
    uint8_t *config;
    uint32_t size;
    struct virtio_pci_cap cap = {
        .cap_len = sizeof cap,
    };
    struct virtio_pci_notify_cap notify = {
            .cap.cap_len = sizeof notify,
            .notify_off_multiplier =
                cpu_to_le32(virtio_pci_queue_mem_mult(vdev)),
    };
    struct virtio_pci_cfg_cap cfg = {
            .cap.cap_len = sizeof cfg,
            .cap.cfg_type = VIRTIO_PCI_CAP_PCI_CFG,
    };
    struct virtio_pci_cfg_cap *cfg_mask;
    bool legacy = virtio_pci_legacy();
    bool modern = virtio_pci_modern();

    config = vdev->pci_dev.config;

    //INTX line is 1
    config[PCI_INTERRUPT_PIN] = 1;

    //The following is for legacy mode
    if (legacy) {
        pci_set_word(config + PCI_SUBSYSTEM_ID, vdev->device_id);
    } else {
        /* pure virtio-1.0 */
        pci_set_word(config + PCI_VENDOR_ID,
                     PCI_VENDOR_ID_REDHAT_QUMRANET);
        pci_set_word(config + PCI_DEVICE_ID,
                     0x1040 + vdev->device_id);
		pci_set_byte(config + PCI_REVISION_ID, 1);
    }

    //The following is for modern mode
    if (modern) {
		//setup related pci config list
        virtio_pci_modern_mem_region_map(vdev, &vdev->common, &cap);
        virtio_pci_modern_mem_region_map(vdev, &vdev->isr, &cap);
        virtio_pci_modern_mem_region_map(vdev, &vdev->device, &cap);
        virtio_pci_modern_mem_region_map(vdev, &vdev->notify, &notify.cap);

        pci_register_bar(&vdev->pci_dev, vdev->modern_mem_bar_idx,
                         PCI_BASE_ADDRESS_SPACE_MEMORY |
                         PCI_BASE_ADDRESS_MEM_PREFETCH |
                         PCI_BASE_ADDRESS_MEM_TYPE_64,
                         pow2ceil(vdev->notify.offset + vdev->notify.size),
						 &modern_bar_ops, KVM_MMIO_BUS);

        vdev->config_cap = virtio_pci_add_mem_cap(vdev, &cfg.cap);

        cfg_mask = (void *)(vdev->pci_dev.wmask + vdev->config_cap);
        pci_set_byte(&cfg_mask->cap.bar, ~0x0);
        pci_set_long((uint8_t *)&cfg_mask->cap.offset, ~0x0);
        pci_set_long((uint8_t *)&cfg_mask->cap.length, ~0x0);
        pci_set_long(cfg_mask->pci_cfg_data, ~0x0);
    }

    //setup msi
    err = msix_init_exclusive_bar(&vdev->pci_dev, vdev->nvectors,
                                          vdev->msix_bar_idx);
    if (err) {
        printk(">>>>%s:%d error: unable to init msix vectors to %x\n",
                         __func__, __LINE__, vdev->nvectors);
        vdev->nvectors = 0;
    }

    if (legacy) {
        size = VIRTIO_PCI_REGION_SIZE(&vdev->pci_dev)
            + vdev->config_len;
        size = pow2ceil(size);

        pci_register_bar(&vdev->pci_dev, vdev->legacy_io_bar_idx,
                         PCI_BASE_ADDRESS_SPACE_IO, size, &legacy_bar_ops, KVM_PIO_BUS);
    }

    //hook config r/w callback
    vdev->pci_dev.config_write = virtio_write_config;
    vdev->pci_dev.config_read = virtio_read_config;
}

void virtio_device_realize(VirtIODevice *vdev)
{   
    if (virtio_pci_modern())   
        virtio_add_feature(&vdev->host_features, VIRTIO_F_VERSION_1);
                                
    virtio_add_feature(&vdev->host_features, VIRTIO_F_BAD_FEATURE);
    
    /* Get the features of the plugged device. */
    vdev->host_features = vdev->get_features(vdev, vdev->host_features);
    
    virtio_pci_realize(vdev);

    virtio_pci_device_plugged(vdev);
}


