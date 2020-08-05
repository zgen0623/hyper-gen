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
#include "vblk.h"
#include <uapi/linux/virtio_config.h>
#include <uapi/linux/virtio_ring.h>
#include <uapi/linux/virtio_scsi.h>
#include <uapi/linux/vhost.h>
#include <uapi/linux/virtio_ids.h>
#include <linux/pci_ids.h>

long my_vhost_scsi_ioctl(void *opaque,
		 unsigned int ioctl,
		 unsigned long arg);
int my_vhost_scsi_release(void *priv);
void *my_vhost_scsi_open(void);

static int kernel_feature_bits[] = {
    VIRTIO_F_NOTIFY_ON_EMPTY,
    VIRTIO_RING_F_INDIRECT_DESC,
    VIRTIO_RING_F_EVENT_IDX,
    VIRTIO_SCSI_F_HOTPLUG,
    VHOST_INVALID_FEATURE_BIT
};

static void virtio_scsi_get_config(VirtIODevice *vdev,
                                   uint8_t *config)
{       
    VirtIOSCSIConfig *scsiconf = (VirtIOSCSIConfig *)config;
    VHostSCSI *vs = (VHostSCSI *)(vdev);

    scsiconf->num_queues = vs->conf.num_queues;
    scsiconf->seg_max = 128 - 2;
    scsiconf->max_sectors = vs->conf.max_sectors;
    scsiconf->cmd_per_lun = vs->conf.cmd_per_lun;
    scsiconf->event_info_size = sizeof(VirtIOSCSIEvent);
    scsiconf->sense_size = vs->sense_size;
    scsiconf->cdb_size = vs->cdb_size;
    scsiconf->max_channel = VIRTIO_SCSI_MAX_CHANNEL;
    scsiconf->max_target = VIRTIO_SCSI_MAX_TARGET;
    scsiconf->max_lun = VIRTIO_SCSI_MAX_LUN;
}

static uint64_t vhost_scsi_common_get_features(VirtIODevice *vdev, uint64_t features)
{   
    VHostSCSI *vs = (VHostSCSI *)(vdev);
        
    return vhost_get_features(&vs->dev, vs->feature_bits, features);
} 

static void vhost_scsi_common_set_config(VirtIODevice *vdev, const uint8_t *config)
{   
    VirtIOSCSIConfig *scsiconf = (VirtIOSCSIConfig *)config;
    VHostSCSI *vs = (VHostSCSI *)(vdev);

    if (scsiconf->sense_size != vs->sense_size ||
        scsiconf->cdb_size != vs->cdb_size) {
        printk(">>>>error vhost-scsi does not support changing the sense data and "
                     "CDB sizes\n");
    }
} 

static bool vhost_scsi_guest_notifier_pending(VirtIODevice *vdev, int idx)
{
    VHostSCSI *vs = (VHostSCSI *)vdev;
    return vhost_virtqueue_pending(&vs->dev, idx);
} 




static int vhost_scsi_common_start(VHostSCSI *vs)
{
    int ret, i;
    VirtIODevice *vdev = (VirtIODevice *)vs;

	/* add notify region access =>evt_id mapping to kvm,
	 * for guest=>host notify event
	 */
    ret = vhost_dev_enable_notifiers(&vs->dev, vdev);
    if (ret < 0) {
        printk(">>>>>%s:%d\n", __func__, __LINE__);
        return ret;
    }

	//add virq(gsi)=>msi mapping entry to kvm for host=>guest irq injection
    ret = virtio_pci_set_guest_notifiers(vdev, vs->dev.nvqs, true);
    if (ret < 0) {
        printk(">>>>%s:%d Error binding guest notifier\n",
			__func__, __LINE__);
        goto err_host_notifiers;
    }

    vs->dev.acked_features = vdev->guest_features;

    ret = vhost_dev_start(&vs->dev, vdev);
    if (ret < 0) {
        printk(">>>>>%s:%d\n", __func__, __LINE__);
        goto err_guest_notifiers;
    }

	//deliver virq(gsi) for host=>guest irq injection to vhost 
    for (i = 0; i < vs->dev.nvqs; i++)
        vhost_virtqueue_mask(&vs->dev, vdev, vs->dev.vq_index + i, false);

    return ret;

err_guest_notifiers:
    virtio_pci_set_guest_notifiers(vdev, vs->dev.nvqs, false);
err_host_notifiers:
    vhost_dev_disable_notifiers(&vs->dev, vdev);
    return ret;
}

static int vhost_scsi_set_endpoint(VHostSCSI *vs)
{   
	struct vhost_dev *dev = &vs->dev;
    struct vhost_scsi_target backend;
    int ret;

    memset(&backend, 0, sizeof(backend));
    strlcpy(backend.vhost_wwpn, vs->conf.wwpn, sizeof(backend.vhost_wwpn));

    ret = my_vhost_scsi_ioctl(dev->opaque, VHOST_SCSI_SET_ENDPOINT, (unsigned long)&backend);
    if (ret < 0) {
        printk(">>>>>error: %s:%d ret=%d\n", __func__, __LINE__, ret);
        return -1;
    }
    return 0;
}

static void vhost_scsi_common_stop(VHostSCSI *vs)
{
    VirtIODevice *vdev = (VirtIODevice *)vs;
    int ret = 0;

    vhost_dev_stop_(&vs->dev, vdev);

    ret = virtio_pci_set_guest_notifiers(vdev, vs->dev.nvqs, false);
    if (ret < 0) {
       printk(">>>>%s:%d vhost guest notifier cleanup failed: %d",
			 __func__, __LINE__, ret);
    }

    vhost_dev_disable_notifiers(&vs->dev, vdev);
}

static int vhost_scsi_start(VHostSCSI *vs)
{
    int ret, abi_version;
	struct vhost_dev *dev = &vs->dev;

    ret = my_vhost_scsi_ioctl(dev->opaque, VHOST_SCSI_GET_ABI_VERSION, (uint64_t)&abi_version);
    if (ret < 0) {
        return -1;
    }
    if (abi_version > VHOST_SCSI_ABI_VERSION) {
        printk(">>>>vhost-scsi: The running tcm_vhost kernel abi_version:"
                     " %d is greater than vhost_scsi userspace supports: %d,"
                     " please upgrade your version of QEMU", abi_version,
                     VHOST_SCSI_ABI_VERSION);
        return -1;
    }

    ret = vhost_scsi_common_start(vs);
    if (ret < 0) {
        return ret;
    }

    ret = vhost_scsi_set_endpoint(vs);
    if (ret < 0) {
        printk(">>>>>%s:%d Error setting vhost-scsi endpoint\n",
			__func__, __LINE__);
        vhost_scsi_common_stop(vs);
    }

    return ret;
}

static void vhost_scsi_clear_endpoint(VHostSCSI *vs)
{
	struct vhost_dev *dev = &vs->dev;
    struct vhost_scsi_target backend;

    memset(&backend, 0, sizeof(backend));
    strlcpy(backend.vhost_wwpn, vs->conf.wwpn, sizeof(backend.vhost_wwpn));

    my_vhost_scsi_ioctl(dev->opaque, VHOST_SCSI_CLEAR_ENDPOINT, (uint64_t)&backend);
} 

static void vhost_scsi_stop(VHostSCSI *vs)
{
    vhost_scsi_clear_endpoint(vs);
    vhost_scsi_common_stop(vs);
}

static void vhost_scsi_set_status(VirtIODevice *vdev, uint8_t val)
{   
    VHostSCSI *vs = (VHostSCSI *)vdev;
    bool start = (val & VIRTIO_CONFIG_S_DRIVER_OK);
	int ret;
    
    if (vs->dev.started == start)
        return;
    
    if (start) {
        ret = vhost_scsi_start(vs);
        if (ret < 0)
            printk(">>>>>error: unable to start vhost-scsi: %d\n", -ret);
    } else {
        vhost_scsi_stop(vs);
    }
}

static void virtio_scsi_common_realize(VirtIODevice *vdev,
                                VirtIOHandleOutput ctrl,
                                VirtIOHandleOutput evt,
                                VirtIOHandleOutput cmd)
{
    VHostSCSI *vs = (VHostSCSI *)vdev;
    int i;

    virtio_init(vdev, "virtio-scsi", VIRTIO_ID_SCSI,
                sizeof(VirtIOSCSIConfig));

    if (vs->conf.num_queues == 0 ||
            vs->conf.num_queues > VIRTIO_QUEUE_MAX - 2) {
        return;
    }

    vs->sense_size = VIRTIO_SCSI_SENSE_DEFAULT_SIZE;
    vs->cdb_size = VIRTIO_SCSI_CDB_DEFAULT_SIZE;

    //create cmd vq
    for (i = 0; i < vs->conf.num_queues; i++)
        virtio_add_queue(vdev, vs->conf.virtqueue_size, cmd);

    //create control vq
    virtio_add_queue(vdev, vs->conf.virtqueue_size, ctrl);
    //create event vq
    virtio_add_queue(vdev, vs->conf.virtqueue_size, evt);
}

static void vhost_dummy_handle_output(VirtIODevice *vdev, VirtQueue *vq)
{
}

static void vhost_scsi_realize(VirtIODevice *vdev)
{
    VHostSCSI *vs = (VHostSCSI *)vdev;
    int ret;
	void *vhost_priv;

    if (!vs->conf.wwpn) {
        printk(">>>>>%s:%d\n", __func__, __LINE__);
        return;
	}

	vhost_priv = my_vhost_scsi_open();

    virtio_scsi_common_realize(vdev,
                               vhost_dummy_handle_output,
                               vhost_dummy_handle_output,
                               vhost_dummy_handle_output);

    vs->dev.nvqs = VHOST_SCSI_VQ_NUM_FIXED + vs->conf.num_queues;
    vs->dev.vqs = kzalloc(sizeof(struct vhost_virtqueue) * vs->dev.nvqs, GFP_KERNEL);
    vs->dev.vq_index = 0;
    vs->dev.backend_features = 0;
	vs->dev.ioctl_hook = my_vhost_scsi_ioctl;
	vs->dev.release_hook = my_vhost_scsi_release;

    ret = vhost_dev_init_(&vs->dev, vhost_priv, 0);
    if (ret < 0) {
        printk(">>>>>%s:%d\n", __func__, __LINE__);
        goto free_vqs;
    }

    return;

 free_vqs:
    kfree(vs->dev.vqs);
    my_vhost_scsi_release(vhost_priv);
    return;
}

static void vhost_scsi_unrealize(VirtIODevice *vdev)
{
	int i;
    VHostSCSI *vs = (VHostSCSI *)vdev;

	virtio_set_status(vdev, 0);

	for (i = 0; i < VHOST_SCSI_VQ_NUM_FIXED + vs->conf.num_queues; i++)
		virtio_del_queue(vdev, i);

	virtio_cleanup_(vdev);

    kfree(vs->dev.vqs);
    my_vhost_scsi_release(vs->dev.opaque);
}


void create_vblk(struct kvm *kvm)
{
	struct virt_pci_bridge *bridge = kvm->vdevices.vbridge;
	struct virt_pci_bus *bus = bridge->bus;
	PCIDevice *pci_dev;
    VirtIODevice *vdev;
    VHostSCSI *vs;

	//create instance
	vs = kzalloc(sizeof(VHostSCSI), GFP_KERNEL);
	if (!vs) {
		printk(">>>>>error %s:%d\n", __func__, __LINE__);
		return;
	}

	vdev = &vs->parent_obj;
	pci_dev = &vdev->pci_dev;

	//init instance
    pci_dev->devfn = -1;
    pci_dev->cap_present = QEMU_PCI_CAP_SERR
                        | QEMU_PCIE_LNKSTA_DLLLA
                        | QEMU_PCIE_EXTCAP_INIT;

    vdev->flags = VIRTIO_PCI_FLAG_MIGRATE_EXTRA |
                    VIRTIO_PCI_FLAG_INIT_DEVERR |
                    VIRTIO_PCI_FLAG_INIT_LNKCTL |
                    VIRTIO_PCI_FLAG_INIT_PM |
                    VIRTIO_PCI_FLAG_INIT_FLR;

    vdev->host_features = (1UL << VIRTIO_RING_F_INDIRECT_DESC) |
                        (1UL << VIRTIO_RING_F_EVENT_IDX) |
                        (1UL << VIRTIO_F_NOTIFY_ON_EMPTY) |
                        (1UL << VIRTIO_F_ANY_LAYOUT);

    vdev->legacy_features |= VIRTIO_LEGACY_FEATURES;

    vdev->get_config = virtio_scsi_get_config;
    vdev->set_config = vhost_scsi_common_set_config;
    vdev->get_features = vhost_scsi_common_get_features;
    vdev->set_status = vhost_scsi_set_status;
    vdev->guest_notifier_pending = vhost_scsi_guest_notifier_pending;

    vs->conf.cmd_per_lun = 128;
    vs->conf.max_sectors = 0xffff;
    vs->conf.virtqueue_size = 128;
    vs->conf.num_queues = 1;
    vs->conf.wwpn = (char*)"naa.600140554cf3a18e";
    vs->feature_bits = kernel_feature_bits;

    vdev->nvectors = vs->conf.num_queues + 3;

    //realize instance
    do_pci_register_device(pci_dev, bus,
                               "vhost-scsi", NULL, NULL,
                                PCI_VENDOR_ID_REDHAT_QUMRANET, PCI_DEVICE_ID_VIRTIO_SCSI,
                                PCI_CLASS_STORAGE_SCSI, 0);

    vhost_scsi_realize(vdev);

    //Setup modern/legacy/msix bar and relevant cap_list in pci config space
    virtio_device_realize(vdev);

    //reset
    virtio_pci_reset(vdev);

	kvm->vdevices.vblock = vs;
}

void destroy_vblk(struct kvm *kvm)
{
	PCIDevice *pci_dev;
    VirtIODevice *vdev;
    VHostSCSI *vs;

	vs = kvm->vdevices.vblock;
	vdev = &vs->parent_obj;
	pci_dev = &vdev->pci_dev;

	//1. destroy pci
	//2. destroy vdev
	//3. destroy vs
    do_pci_unregister_device(pci_dev);

    vhost_scsi_unrealize(vdev);

	kfree(vs);
}

