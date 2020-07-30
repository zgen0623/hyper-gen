#ifndef ARCH_X86_KVM_VBLK_H
#define ARCH_X86_KVM_VBLK_H

#include "virtio.h"

#define VIRTIO_SCSI_CDB_DEFAULT_SIZE   32
#define VIRTIO_SCSI_SENSE_DEFAULT_SIZE 96
#define MSIX_CAP_LENGTH 12

#define VIRTIO_SCSI_MAX_CHANNEL 0
#define VIRTIO_SCSI_MAX_TARGET  255
#define VIRTIO_SCSI_MAX_LUN     16383

typedef struct virtio_scsi_cmd_req VirtIOSCSICmdReq;
typedef struct virtio_scsi_cmd_resp VirtIOSCSICmdResp;
typedef struct virtio_scsi_ctrl_tmf_req VirtIOSCSICtrlTMFReq;
typedef struct virtio_scsi_ctrl_tmf_resp VirtIOSCSICtrlTMFResp;
typedef struct virtio_scsi_ctrl_an_req VirtIOSCSICtrlANReq;
typedef struct virtio_scsi_ctrl_an_resp VirtIOSCSICtrlANResp;
typedef struct virtio_scsi_event VirtIOSCSIEvent;
typedef struct virtio_scsi_config VirtIOSCSIConfig;


enum vhost_scsi_vq_list {
    VHOST_SCSI_VQ_CONTROL = 0,
    VHOST_SCSI_VQ_EVENT = 1,
    VHOST_SCSI_VQ_NUM_FIXED = 2,
}; 

typedef struct VirtIOSCSIConf {
    uint32_t num_queues;
    uint32_t virtqueue_size;
    uint32_t max_sectors;
    uint32_t cmd_per_lun;
    char *wwpn;
}VirtIOSCSIConf; 

typedef struct VHostSCSI {
    VirtIODevice parent_obj;
    
    struct vhost_dev dev;
    const int *feature_bits;
    
    //fields for VirtIO
    VirtIOSCSIConf conf;
    
    uint32_t sense_size;
    uint32_t cdb_size;
} VHostSCSI; 

void create_vblk(struct kvm *kvm);
void detroy_vblk(struct kvm *kvm);
MSIMessage msix_get_message(PCIDevice *dev, unsigned vector);

bool msi_enabled(const PCIDevice *dev);

MSIMessage msi_get_message(PCIDevice *dev, unsigned int vector);

bool msix_is_masked(PCIDevice *dev, unsigned int vector);
void destroy_vblk(struct kvm *kvm);





#endif

