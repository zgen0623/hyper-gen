#ifndef ARCH_X86_KVM_VNET_H
#define ARCH_X86_KVM_VNET_H

#include "virtio.h"
#include <uapi/linux/if_ether.h>

#define MAX_QUEUE_NUM 256

#define VIRTIO_NET_RX_QUEUE_DEFAULT_SIZE 256
#define VIRTIO_NET_TX_QUEUE_DEFAULT_SIZE 256

#define SPEED_UNKNOWN       -1

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
    char *netclient_name;
    uint64_t curr_guest_offloads;
    /* used on saved state restore phase to preserve the curr_guest_offloads */
    NetClientState *my_sub_ncs[MAX_QUEUE_NUM];
    bool nic_deleted;
};
















#endif
