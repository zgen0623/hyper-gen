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
#include "vnet.h"
#include <uapi/linux/virtio_config.h>
#include <uapi/linux/virtio_ring.h>
#include <uapi/linux/virtio_scsi.h>
#include <uapi/linux/vhost.h>
#include <uapi/linux/virtio_ids.h>
#include <uapi/linux/virtio_net.h>
#include <linux/pci_ids.h>
#include <uapi/linux/if.h>



#define IFNAME "tap0"
#define NETDEV_NAME "my-tap"
#define NET_QUEUE_NUM 2
#define MAX_TAP_QUEUES 1024



void *my_tun_chr_open(void);
int my_set_if(void *tap_priv, struct ifreq *ifr);
int my_tun_chr_close(void *tap_priv);


static void realize_vdev_net_instance(VirtIODevice* vdev)
{   
    Error *errp;
    
    virtio_net_set_netclient_name((VirtIONet *)vdev, "virtio-net-pci",
                                  "virtio-net-pci");
    
    virtio_net_device_realize(vdev, &errp);
    
    virtio_device_realize(vdev);
}

static void *tap_open(char *ifname, int ifname_size, int *vnet_hdr,
             int mq_required)
{
    struct ifreq ifr;
    int ret;
	void *tap_priv;
    int len = sizeof(struct virtio_net_hdr);
    unsigned int features;

	tap_priv = my_tun_chr_open();
    if (!tap_priv) {
		printk(">>>>>%s:%d\n",__func__, __LINE__);
        return NULL;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

	features = IFF_TUN | IFF_TAP | TUN_FEATURES;

    if (features & IFF_ONE_QUEUE)
        ifr.ifr_flags |= IFF_ONE_QUEUE;

    if (*vnet_hdr) {
        *vnet_hdr = 1;
        ifr.ifr_flags |= IFF_VNET_HDR;
    }

    if (mq_required)
        ifr.ifr_flags |= IFF_MULTI_QUEUE;

    if (ifname[0] != '\0')
        strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
    else
        strlcpy(ifr.ifr_name, "tap%d", IFNAMSIZ);

	ret = my_set_if(tap_priv, &ifr);
    if (ret != 0) {
        if (ifname[0] != '\0') {
			printk(">>>>>%s:%d\n",__func__, __LINE__);
        } else {
			printk(">>>>>%s:%d\n",__func__, __LINE__);
        }
		my_tun_chr_close(tap_priv);
        return NULL;
    }

    strlcpy(ifname, ifr.ifr_name, ifname_size);

    return tap_priv;
}

int my_set_offload(void *tap_priv, unsigned offload);

static void tap_fd_set_offload(void *tap, int csum, int tso4,
                        int tso6, int ecn, int ufo)
{   
    unsigned int offload = 0;
    
    /* Check if our kernel supports TUNSETOFFLOAD */ 
    if (my_set_offload(tap, 0) != 0) {
		printk(">>>>>%s:%d\n", __func__, __LINE__);
        return;
	}
    
    if (csum) { 
        offload |= TUN_F_CSUM;
        if (tso4)
            offload |= TUN_F_TSO4;
        if (tso6)
            offload |= TUN_F_TSO6;
        if ((tso4 || tso6) && ecn)
            offload |= TUN_F_TSO_ECN;
        if (ufo)
            offload |= TUN_F_UFO;
    }
    
    if (my_set_offload(tap, offload) != 0) {
        offload &= ~TUN_F_UFO;
        if (my_set_offload(tap, offload) != 0)
            printk(">>>>>%s:%d\n",__func__, __LINE__);
    }   
}

int my_get_hdrsz(void *tap_priv, int *size);
int my_set_hdrsz(void *tap_priv, int *size);
int my_set_sndbuf(void *tap_priv, int *size);

static NetClientState *net_tap_init(VirtIONet *n,
                                 void *tap_priv,
                                 int vnet_hdr)
{
    NetClientState *nc;
   	int sndbuf = INT_MAX;

    nc = kzalloc(sizeof(NetClientState), GPF_KERNEL);

 //   QTAILQ_INSERT_TAIL(&net_clients, nc, next);
    n->my_sub_ncs[n->max_queues++] = nc;

    nc->tap_priv = tap_priv;
    nc->host_vnet_hdr_len = vnet_hdr ? sizeof(struct virtio_net_hdr) : 0;
    nc->has_ufo = (0 > my_set_offload(nc->tap_priv, TUN_F_CSUM | TUN_F_UFO)) ? 0 : 1;
    nc->enabled = true;
    tap_fd_set_offload(nc->tap_priv, 0, 0, 0, 0, 0);

	if (my_set_hdrsz(nc->tap_priv, &nc->host_vnet_hdr_len) < 0)
		printk(">>>>>%s:%d\n", __func__, __LINE__);

	my_set_sndbuf(nc->tap_priv, &sndbuf);

    return nc;
}

void *my_vhost_net_open(void):

static bool qemu_has_vnet_hdr(NetClientState *nc)
{   
    return !!nc->host_vnet_hdr_len;
}

static void vhost_net_init(NetClientState *nc)
{       
    int r; 
    uint64_t features = 0;
    struct vhost_dev *dev = &nc->dev;
 //   int vhostfd;
    void *vhost_priv;
    
//    vhostfd = open("/dev/vhost-net", O_RDWR);
	vhost_priv = my_vhost_net_open();
    if (!vhost_priv) {
		printk(">>>>>%s:%d\n", __func__, __LINE__);
        return;
    }
    
    dev->max_queues = 1;
    dev->nvqs = 2;
    dev->vqs = nc->vqs;

    dev->backend_features = qemu_has_vnet_hdr(nc)
           ? 0 : (1ULL << VHOST_NET_F_VIRTIO_NET_HDR);
    dev->protocol_features = 0;

    r = vhost_dev_init_(dev, vhost_priv, 0);
    if (r < 0) {
        goto fail;
    }

    if (!qemu_has_vnet_hdr_len(nc,
                               sizeof(struct virtio_net_hdr_mrg_rxbuf))) {
        dev->features &= ~(1ULL << VIRTIO_NET_F_MRG_RXBUF);
    }

    if (~dev->features & dev->backend_features) {
            fprintf(stderr, "vhost lacks feature mask %" PRIu64
                   " for backend\n",
                   (uint64_t)(~dev->features & dev->backend_features));
            goto fail;
    }

    vhost_net_ack_features(nc, features);

    return;

fail:
    vhost_dev_cleanup(&nc->dev);
    return;
}

static void my_net_client_init(int mq_num)
{   
    int vnet_hdr = 1, i = 0;
    char ifname[128];
    NetClientState *nc;
	void *tap_priv;

    pstrcpy(ifname, sizeof ifname, IFNAME);

    for (i = 0; i < mq_num; i++) {
        tap_priv = tap_open(ifname, sizeof(ifname), &vnet_hdr, 0, mq_num > 1);
        if (tap_priv == -1) {
            printk(">>>>>%s:%d\n",__func__, __LINE__);
            return;
        }

        nc = net_tap_init(n, tap_priv, vnet_hdr);

        vhost_net_init(nc);
    }

	return;
}

static void virtio_net_get_config(VirtIODevice *vdev, uint8_t *config)
{   
    VirtIONet *n = (VirtIONet *)(vdev);
    struct virtio_net_config netcfg;
    
    netcfg.status = n->status;
    netcfg.max_virtqueue_pairs = n->max_queues;
    netcfg.mtu = n->net_conf.mtu;
    memcpy(netcfg.mac, n->mac, ETH_ALEN);
    netcfg.speed = n->net_conf.speed;
    netcfg.duplex = n->net_conf.duplex;

    memcpy(config, &netcfg, n->config_size);
}

static void virtio_net_set_config(VirtIODevice *vdev, const uint8_t *config)
{   
    VirtIONet *n = (VirtIONet *)(vdev);
    struct virtio_net_config netcfg = {};
    
    memcpy(&netcfg, config, n->config_size);
    
    if (!virtio_vdev_has_feature(vdev, VIRTIO_NET_F_CTRL_MAC_ADDR) &&
        !virtio_vdev_has_feature(vdev, VIRTIO_F_VERSION_1) &&
        memcmp(netcfg.mac, n->mac, ETH_ALEN)) {
        memcpy(n->mac, netcfg.mac, ETH_ALEN);
    }
}

static const int kernel_feature_bits[] = {
    VIRTIO_F_NOTIFY_ON_EMPTY,
    VIRTIO_RING_F_INDIRECT_DESC,
    VIRTIO_RING_F_EVENT_IDX,
    VIRTIO_NET_F_MRG_RXBUF,
    VIRTIO_F_VERSION_1,
    VIRTIO_NET_F_MTU,
    VIRTIO_F_IOMMU_PLATFORM,
    VIRTIO_F_RING_PACKED,
    VHOST_INVALID_FEATURE_BIT
};

static uint64_t virtio_net_get_features(VirtIODevice *vdev, uint64_t features)
{   
    VirtIONet *n = (VirtIONet *)(vdev);
    NetClientState *nc = n->my_sub_ncs[0];
    
    /* Firstly sync all virtio-net possible supported features */
    features |= n->host_features;
    
    virtio_add_feature(&features, VIRTIO_NET_F_MAC);
    
    if (!n->has_vnet_hdr) {
        virtio_clear_feature(&features, VIRTIO_NET_F_CSUM);
        virtio_clear_feature(&features, VIRTIO_NET_F_HOST_TSO4);
        virtio_clear_feature(&features, VIRTIO_NET_F_HOST_TSO6);
        virtio_clear_feature(&features, VIRTIO_NET_F_HOST_ECN);

        virtio_clear_feature(&features, VIRTIO_NET_F_GUEST_CSUM);
        virtio_clear_feature(&features, VIRTIO_NET_F_GUEST_TSO4);
        virtio_clear_feature(&features, VIRTIO_NET_F_GUEST_TSO6);
        virtio_clear_feature(&features, VIRTIO_NET_F_GUEST_ECN);
    }

    if (!n->has_vnet_hdr || !n->my_sub_ncs[0]->has_ufo) {
        virtio_clear_feature(&features, VIRTIO_NET_F_GUEST_UFO);
        virtio_clear_feature(&features, VIRTIO_NET_F_HOST_UFO);
    }

    features = vhost_get_features(&nc->dev,
				vhost_net_get_feature_bits(), features);
    vdev->backend_features = features;

    if (n->host_features & 1ULL << VIRTIO_NET_F_MTU)
        features |= (1ULL << VIRTIO_NET_F_MTU);

    return features;
}

static void virtio_net_set_features(VirtIODevice *vdev, uint64_t features)
{
    VirtIONet *n = (VirtIONet *)(vdev);
    int i;

//    fprintf(stderr, ">>>>>>>%s:%d from_guest=%lx backend=%lx %s\n",
 //       __func__, __LINE__, features, vdev->backend_features, vdev->name);
    //from_guest=130efffa7 backend=179ffffe7
    if (!virtio_has_feature(vdev->backend_features, VIRTIO_NET_F_MTU))
        features &= ~(1ULL << VIRTIO_NET_F_MTU);

    virtio_net_set_multiqueue(n, virtio_has_feature(features, VIRTIO_NET_F_MQ));

    virtio_net_set_hdr_len(n, virtio_has_feature(features,
                                                  VIRTIO_NET_F_MRG_RXBUF),
                               virtio_has_feature(features,
                                                  VIRTIO_F_VERSION_1));
    
    if (n->has_vnet_hdr) {
        n->curr_guest_offloads =
            virtio_net_guest_offloads_by_features(features);
        virtio_net_apply_guest_offloads(n);
    }                   

    for (i = 0;  i < n->max_queues; i++) {
        NetClientState *nc = n->my_sub_ncs[i];

        vhost_net_ack_features(nc, features);
    }

    return;
}


static uint64_t virtio_net_bad_features(VirtIODevice *vdev)
{   
    uint64_t features = 0;
    
    /* Linux kernel 2.6.25.  It understood MAC (as everyone must),
     * but also these: */
    virtio_add_feature(&features, VIRTIO_NET_F_MAC);
    virtio_add_feature(&features, VIRTIO_NET_F_CSUM);
    virtio_add_feature(&features, VIRTIO_NET_F_HOST_TSO4);
    virtio_add_feature(&features, VIRTIO_NET_F_HOST_TSO6);
    virtio_add_feature(&features, VIRTIO_NET_F_HOST_ECN);
    
    return features; 
}

void create_vnet(struct kvm *kvm)
{
    PCIDevice *pci_dev;
    VirtIODevice* vdev;
    VirtIONet *n;

    //1. create instance
    vdev = kzalloc(sizeof(VirtIONet), GFP_KERNEL);
    pci_dev = &vdev->pci_dev;
    n = (VirtIONet *)vdev;

    //2. init instance
    pci_dev->devfn = -1;
    pci_dev->cap_present = QEMU_PCI_CAP_SERR
                        | QEMU_PCIE_LNKSTA_DLLLA
                        | QEMU_PCIE_EXTCAP_INIT;

    vdev->flags = VIRTIO_PCI_FLAG_MIGRATE_EXTRA |
                    VIRTIO_PCI_FLAG_INIT_DEVERR |
                    VIRTIO_PCI_FLAG_INIT_LNKCTL |
                    VIRTIO_PCI_FLAG_INIT_PM |
                    VIRTIO_PCI_FLAG_INIT_FLR;

    vdev->nvectors = NET_QUEUE_NUM * 2 + 2;

    vdev->host_features = (1UL << VIRTIO_RING_F_INDIRECT_DESC) |
                        (1UL << VIRTIO_RING_F_EVENT_IDX) |
                        (1UL << VIRTIO_F_NOTIFY_ON_EMPTY) |
                        (1UL << VIRTIO_F_ANY_LAYOUT);

    vdev->legacy_features = VIRTIO_LEGACY_FEATURES |
                            (0x1 << VIRTIO_NET_F_GSO);

    vdev->get_config = virtio_net_get_config;
    vdev->set_config = virtio_net_set_config;
    vdev->get_features = virtio_net_get_features;
    vdev->set_features = virtio_net_set_features;
    vdev->bad_features = virtio_net_bad_features;
    vdev->reset = virtio_net_reset;
    vdev->set_status = virtio_net_set_status;
    vdev->guest_notifier_mask = virtio_net_guest_notifier_mask;
    vdev->guest_notifier_pending = virtio_net_guest_notifier_pending;

    n->net_conf.rx_queue_size = VIRTIO_NET_RX_QUEUE_DEFAULT_SIZE;
    n->net_conf.tx_queue_size = VIRTIO_NET_TX_QUEUE_DEFAULT_SIZE;
    n->net_conf.speed = SPEED_UNKNOWN;

    n->config_size = sizeof(struct virtio_net_config);

    n->host_features = (1UL << VIRTIO_NET_F_CSUM) |
                        (1UL << VIRTIO_NET_F_GUEST_CSUM) |
                        (1UL << VIRTIO_NET_F_GSO) |
                        (1UL << VIRTIO_NET_F_GUEST_TSO4) |
                        (1UL << VIRTIO_NET_F_GUEST_TSO6) |
                        (1UL << VIRTIO_NET_F_GUEST_ECN) |
                        (1UL << VIRTIO_NET_F_GUEST_UFO) |
                        (1UL << VIRTIO_NET_F_GUEST_ANNOUNCE) |
                        (1UL << VIRTIO_NET_F_HOST_TSO4) |
                        (1UL << VIRTIO_NET_F_HOST_TSO6) |
                        (1UL << VIRTIO_NET_F_HOST_ECN) |
                        (1UL << VIRTIO_NET_F_HOST_UFO) |
                        (1UL << VIRTIO_NET_F_MRG_RXBUF) |
                        (1UL << VIRTIO_NET_F_STATUS) |
                        (1UL << VIRTIO_NET_F_CTRL_VQ) |
                        (1UL << VIRTIO_NET_F_CTRL_RX) |
                        (1UL << VIRTIO_NET_F_CTRL_VLAN) |
                        (1UL << VIRTIO_NET_F_CTRL_RX_EXTRA) |
                        (1UL << VIRTIO_NET_F_CTRL_MAC_ADDR) |
                        (1UL << VIRTIO_NET_F_CTRL_GUEST_OFFLOADS);

    if (NET_QUEUE_NUM > 1)
        n->host_features |= (1UL << VIRTIO_NET_F_MQ);

    my_net_client_init(n, NET_QUEUE_NUM);


    //3. realize instance
    do_pci_register_device(pci_dev,
                               "vhost-net", -1, NULL, NULL,
                                PCI_VENDOR_ID_REDHAT_QUMRANET, PCI_DEVICE_ID_VIRTIO_NET,
                                PCI_CLASS_NETWORK_ETHERNET, VIRTIO_PCI_ABI_VERSION);

    realize_vdev_net_instance(vdev);

    //4. reset
    virtio_pci_reset(vdev);
}

void destroy_vnet(struct kvm *kvm)
{

}
