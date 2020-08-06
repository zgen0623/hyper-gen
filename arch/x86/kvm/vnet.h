#ifndef ARCH_X86_KVM_VNET_H
#define ARCH_X86_KVM_VNET_H

#include "virtio.h"
#include <uapi/linux/if_ether.h>

#define MAC_TABLE_ENTRIES    64
#define MAX_QUEUE_NUM 256

#define VIRTIO_NET_HDR_F_RSC_INFO  4 /* rsc_ext data in csum_ fields */
#define VIRTIO_NET_F_RSC_EXT       61

#define MAX_VLAN    (1 << 12)   /* Per 802.1Q definition */

#define PCI_DEVICE_ID_VIRTIO_NET         0x1000

#define VIRTIO_NET_RX_QUEUE_DEFAULT_SIZE 256
#define VIRTIO_NET_TX_QUEUE_DEFAULT_SIZE 256

#define VIRTIO_NET_RX_QUEUE_MIN_SIZE VIRTIO_NET_RX_QUEUE_DEFAULT_SIZE
#define VIRTIO_NET_TX_QUEUE_MIN_SIZE VIRTIO_NET_TX_QUEUE_DEFAULT_SIZE

#define SPEED_UNKNOWN       -1

#define sizeof_field(type, field) sizeof(((type *)0UL)->field)

#define endof(container, field) \
    (offsetof(container, field) + sizeof_field(container, field))

#define VIRTIO_NET_F_SPEED_DUPLEX 63    /* Device set linkspeed and duplex */

#define DUPLEX_UNKNOWN      0xff

/*  
 * Mark a descriptor as available or used in packed ring.
 * Notice: they are defined as shifts instead of shifted values.
 */
#define VRING_PACKED_DESC_F_AVAIL   7
#define VRING_PACKED_DESC_F_USED    15

/* Enable events in packed ring. */
#define VRING_PACKED_EVENT_FLAG_ENABLE  0x0
/* Disable events in packed ring. */
#define VRING_PACKED_EVENT_FLAG_DISABLE 0x1

enum {
    VIRTQUEUE_READ_DESC_ERROR = -1,
    VIRTQUEUE_READ_DESC_DONE = 0,   /* end of chain */
    VIRTQUEUE_READ_DESC_MORE = 1,   /* more buffers in chain */
};

typedef struct VirtIONet VirtIONet;
typedef struct NetClientState NetClientState;

typedef struct virtio_net_conf {
    uint16_t rx_queue_size;
    uint16_t tx_queue_size;
    uint16_t mtu;
    int32_t speed;
    char *duplex_str;
    uint8_t duplex;
} virtio_net_conf;

typedef struct MACAddr MACAddr;

struct MACAddr {
    uint8_t a[6];
};

struct NetClientState {
    void *tap_priv;
    bool has_ufo;
    bool enabled;
    unsigned host_vnet_hdr_len;
    int link_down;
    struct vhost_virtqueue vqs[2];
    struct vhost_dev dev;
 //   QTAILQ_ENTRY(NetClientState) next;
};

struct VirtIONet {
    VirtIODevice parent_obj;
    uint8_t mac[ETH_ALEN];
    uint16_t status;
    /* RSC Chains - temporary storage of coalesced data,
       all these data are lost in case of migration */
    uint32_t has_vnet_hdr;
    uint64_t host_features;
    uint8_t vhost_started;
    virtio_net_conf net_conf;
    MACAddr macaddr;
    int multiqueue;
    uint16_t max_queues;
    uint16_t curr_queues;
    size_t config_size;
    uint64_t curr_guest_offloads;
    /* used on saved state restore phase to preserve the curr_guest_offloads */
    NetClientState *my_sub_ncs[MAX_QUEUE_NUM];
    bool nic_deleted;
};



void create_vnet(struct kvm *kvm);
void destroy_vnet(struct kvm *kvm);













#endif
