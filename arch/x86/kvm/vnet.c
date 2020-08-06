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
#include <linux/log2.h>
#include <linux/string.h>
#include <uapi/linux/if_tun.h>
#include <uapi/linux/virtio_pci.h>



#define IFNAME "tap0"
#define NETDEV_NAME "my-tap"
#define NET_QUEUE_NUM 2
#define MAX_TAP_QUEUES 1024


#define TUN_FEATURES (IFF_NO_PI | IFF_ONE_QUEUE | IFF_VNET_HDR | \
              IFF_MULTI_QUEUE | IFF_NAPI | IFF_NAPI_FRAGS)




bool vm_running(struct kvm *vm);
static void virtio_net_apply_guest_offloads(VirtIONet *n);
static int virtqueue_packed_read_next_desc(VirtQueue *vq,
                                           VRingPackedDesc *desc,
                                           uint64_t hva,
                                           unsigned int max,
                                           unsigned int *next,
                                           bool indirect);
static void virtio_net_set_hdr_len(VirtIONet *n, int mergeable_rx_bufs,
                                       int version_1);
static uint64_t virtio_net_guest_offloads_by_features(uint32_t features);
static void virtio_net_set_status(struct VirtIODevice *vdev, uint8_t status);
static void virtio_net_handle_ctrl(VirtIODevice *vdev, VirtQueue *vq);
static void virtio_net_set_queues(VirtIONet *n);
void *my_tun_chr_open(void);
int my_set_if(void *tap_priv, struct ifreq *ifr);
int my_tun_chr_close(void *tap_priv);
void my_vhost_net_clear_signaled(void *opaque, int vq_idx);

long my_vhost_net_ioctl(void *priv, unsigned int ioctl,
			    unsigned long arg);
void *my_vhost_net_open(void);
int my_vhost_net_release(void *priv);

int my_get_hdrsz(void *tap_priv, int *size);
int my_set_hdrsz(void *tap_priv, int *size);
int my_set_sndbuf(void *tap_priv, int *size);
int my_set_offload(void *tap_priv, unsigned offload);
int my_tun_set_queue(void *priv, struct ifreq *ifr);
static void virtio_net_add_queue(VirtIONet *n, int index);

#if 0
static VirtIOFeature feature_sizes[] = {
    {.flags = 1ULL << VIRTIO_NET_F_MAC,
     .end = endof(struct virtio_net_config, mac)},
    {.flags = 1ULL << VIRTIO_NET_F_STATUS,
     .end = endof(struct virtio_net_config, status)},
    {.flags = 1ULL << VIRTIO_NET_F_MQ,
     .end = endof(struct virtio_net_config, max_virtqueue_pairs)},
    {.flags = 1ULL << VIRTIO_NET_F_MTU,
     .end = endof(struct virtio_net_config, mtu)},
    {.flags = 1ULL << VIRTIO_NET_F_SPEED_DUPLEX,
     .end = endof(struct virtio_net_config, duplex)},
    {}
};

static size_t virtio_feature_get_config_size(VirtIOFeature *feature_sizes,
                                      uint64_t host_features)
{   
    size_t config_size = 0;
    int i;
                                                    
    for (i = 0; feature_sizes[i].flags != 0; i++)
        if (host_features & feature_sizes[i].flags)
            config_size = MAX(feature_sizes[i].end, config_size);
    
    return config_size;
}
#endif


static void virtio_net_set_config_size(VirtIONet *n, uint64_t host_features)
{
    virtio_add_feature(&host_features, VIRTIO_NET_F_MAC);

#if 0
    n->config_size =
		virtio_feature_get_config_size(feature_sizes,
                                       host_features);
#endif
}

static int mac_table[256] = {0};

static void qemu_macaddr_set_used(MACAddr *macaddr)
{
    int index;

    for (index = 0x56; index < 0xFF; index++) {
        if (macaddr->a[5] == index) {
            mac_table[index]++;
        }
    }
}

static int qemu_macaddr_get_free(void)
{
    int index;

    for (index = 0x56; index < 0xFF; index++) {
        if (mac_table[index] == 0) {
            return index;
        }
    }

    return -1;
}  

static void qemu_macaddr_default_if_unset(MACAddr *macaddr)
{                                   
    static const MACAddr zero = { .a = { 0,0,0,0,0,0 } };
    static const MACAddr base = { .a = { 0x52, 0x54, 0x00, 0x12, 0x34, 0 } };
        
    if (memcmp(macaddr, &zero, sizeof(zero)) != 0) {
        if (memcmp(macaddr->a, &base.a, (sizeof(base.a) - 1)) != 0) {
            return;
        } else {
            qemu_macaddr_set_used(macaddr);
            return;
        }
    }
    
    macaddr->a[0] = 0x52;
    macaddr->a[1] = 0x54;
    macaddr->a[2] = 0x00;
    macaddr->a[3] = 0x12;
    macaddr->a[4] = 0x34;
    macaddr->a[5] = qemu_macaddr_get_free();
    qemu_macaddr_set_used(macaddr);
}

static void peer_test_vnet_hdr(VirtIONet *n)
{       
    NetClientState *nc = n->my_sub_ncs[0];
    if (!nc)
        return;

    n->has_vnet_hdr = !!nc->host_vnet_hdr_len;
} 

static void virtio_net_device_realize(VirtIODevice *vdev)
{
    int i;
    VirtIONet *n = (VirtIONet *)(vdev);
        
    n->net_conf.duplex = DUPLEX_UNKNOWN;            

    virtio_net_set_config_size(n, n->host_features);

    virtio_init(vdev, "virtio-net", VIRTIO_ID_NET, n->config_size);

    if (n->net_conf.rx_queue_size < VIRTIO_NET_RX_QUEUE_MIN_SIZE ||
        n->net_conf.rx_queue_size > VIRTQUEUE_MAX_SIZE ||
        !is_power_of_2(n->net_conf.rx_queue_size)) {
		printk(">>>>>%s:%d\n",__func__, __LINE__);
        virtio_cleanup_(vdev);
        return;
    }
    
    if (n->net_conf.tx_queue_size < VIRTIO_NET_TX_QUEUE_MIN_SIZE ||
        n->net_conf.tx_queue_size > VIRTQUEUE_MAX_SIZE ||
        !is_power_of_2(n->net_conf.tx_queue_size)) {
		printk(">>>>>%s:%d\n",__func__, __LINE__);
        virtio_cleanup_(vdev);
        return;
    }

    if (n->max_queues * 2 + 1 > VIRTIO_QUEUE_MAX) {
		printk(">>>>>%s:%d\n",__func__, __LINE__);
        virtio_cleanup_(vdev);
        return;
    }

    n->curr_queues = 1;

    n->net_conf.tx_queue_size = MIN(VIRTIO_NET_TX_QUEUE_DEFAULT_SIZE,
                                    n->net_conf.tx_queue_size);

    for (i = 0; i < n->max_queues; i++)
        virtio_net_add_queue(n, i);

    //create control vq
    virtio_add_queue(vdev, 64, virtio_net_handle_ctrl);
 //   virtio_add_queue(vdev, 64, NULL);

    qemu_macaddr_default_if_unset(&n->macaddr);
    memcpy(&n->mac[0], &n->macaddr, sizeof(n->mac));

    n->status = VIRTIO_NET_S_LINK_UP;

    peer_test_vnet_hdr(n);

	//printk(">>>>>%s:%d\n", __func__, __LINE__);
    virtio_net_set_hdr_len(n, 0, 0);
}

static void realize_vdev_net_instance(VirtIODevice* vdev)
{   
    virtio_net_device_realize(vdev);
    
    virtio_device_realize(vdev);
}

static void *tap_open(char *ifname, int ifname_size, int *vnet_hdr,
             int mq_required)
{
    struct ifreq ifr;
    int ret;
	void *tap_priv;
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

    if (ifname[0] != '\0') {
        strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
    } else {
        strlcpy(ifr.ifr_name, "tap%d", IFNAMSIZ);
	}

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

static void tap_set_offload(void *tap, int csum, int tso4,
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

static NetClientState *net_tap_init(VirtIONet *n,
                                 void *tap_priv,
                                 int vnet_hdr)
{
    NetClientState *nc;
   	int sndbuf = INT_MAX;

    nc = kzalloc(sizeof(NetClientState), GFP_KERNEL);

    n->my_sub_ncs[n->max_queues++] = nc;

    nc->tap_priv = tap_priv;
    nc->host_vnet_hdr_len = vnet_hdr ? sizeof(struct virtio_net_hdr) : 0;
    nc->has_ufo = (0 > my_set_offload(nc->tap_priv, TUN_F_CSUM | TUN_F_UFO)) ? 0 : 1;
    nc->enabled = true;
    tap_set_offload(nc->tap_priv, 0, 0, 0, 0, 0);

	if (0 > my_set_hdrsz(nc->tap_priv, &nc->host_vnet_hdr_len))
		printk(">>>>>%s:%d\n", __func__, __LINE__);

	my_set_sndbuf(nc->tap_priv, &sndbuf);

    return nc;
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

static void vhost_net_ack_features(NetClientState *nc, uint64_t features)
{
    nc->dev.acked_features = nc->dev.backend_features;
    vhost_ack_features(&nc->dev, kernel_feature_bits, features);
}

static void vhost_net_init(NetClientState *nc)
{       
    int r; 
    uint64_t features = 0;
    struct vhost_dev *dev = &nc->dev;
    void *vhost_priv;
    
	vhost_priv = my_vhost_net_open();
    if (!vhost_priv) {
		printk(">>>>>%s:%d\n", __func__, __LINE__);
        return;
    }
    
    dev->max_queues = 1;
    dev->nvqs = 2;
    dev->vqs = nc->vqs;

    dev->backend_features = !!nc->host_vnet_hdr_len
           ? 0 : (1ULL << VHOST_NET_F_VIRTIO_NET_HDR);
    dev->protocol_features = 0;
	dev->ioctl_hook = my_vhost_net_ioctl;
	dev->release_hook = my_vhost_net_release;
	dev->clear_vq_signaled = my_vhost_net_clear_signaled;

    r = vhost_dev_init_(dev, vhost_priv, 0);
    if (r < 0)
        goto fail;

    if (~dev->features & dev->backend_features) {
		printk(">>>>>%s:%d\n", __func__, __LINE__);
        goto fail;
    }

    vhost_net_ack_features(nc, features);

    return;

fail:
    vhost_dev_cleanup_(&nc->dev);
    return;
}

static void my_net_client_init(VirtIONet *n, int mq_num)
{   
    int vnet_hdr = 1, i = 0;
    char ifname[128];
    NetClientState *nc;
	void *tap_priv;

    strlcpy(ifname, IFNAME, sizeof ifname);

    for (i = 0; i < mq_num; i++) {
        tap_priv = tap_open(ifname, sizeof(ifname), &vnet_hdr, mq_num > 1);
        if (!tap_priv) {
            printk(">>>>>%s:%d\n",__func__, __LINE__);
            return;
        }
        //printk(">>>>>%s:%d tap_priv=%lx\n",__func__, __LINE__, tap_priv);

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
				kernel_feature_bits, features);
    vdev->backend_features = features;

    if (n->host_features & 1ULL << VIRTIO_NET_F_MTU)
        features |= (1ULL << VIRTIO_NET_F_MTU);

    return features;
}

static void virtio_net_del_queue(VirtIONet *n, int index)
{
    VirtIODevice *vdev = (VirtIODevice *)(n);
    
    virtio_del_queue(vdev, index * 2);
    virtio_del_queue(vdev, index * 2 + 1);
}

static void virtio_net_add_queue(VirtIONet *n, int index)
{
    VirtIODevice *vdev = (VirtIODevice *)(n);

    virtio_add_queue(vdev, n->net_conf.rx_queue_size,
                                           NULL);

    virtio_add_queue(vdev, n->net_conf.tx_queue_size,
                             NULL);
}

static void vring_packed_desc_read_flags(uint16_t *flags,
                                         uint64_t desc_hva,
                                         int i)
{
	*flags = *(uint16_t*)(desc_hva +
					i * sizeof(VRingPackedDesc) +
                    offsetof(VRingPackedDesc, flags));
}

static inline bool is_desc_avail(uint16_t flags, bool wrap_counter)
{
    bool avail, used;

    avail = !!(flags & (1 << VRING_PACKED_DESC_F_AVAIL));
    used = !!(flags & (1 << VRING_PACKED_DESC_F_USED));
    return (avail != used) && (avail == wrap_counter);
}

static int virtio_queue_packed_empty_rcu(VirtQueue *vq)
{
    struct VRingPackedDesc desc;

    if (unlikely(!vq->vring.desc))
        return 1;

    vring_packed_desc_read_flags(&desc.flags,
				vq->desc_hva, vq->last_avail_idx);

    return !is_desc_avail(desc.flags, vq->last_avail_wrap_counter);
}

static void vring_packed_desc_read(VirtIODevice *vdev,
                                   VRingPackedDesc *desc,
                                   uint64_t desc_hva,
                                   int i, bool strict_order)
{
    hwaddr off = i * sizeof(VRingPackedDesc);

    vring_packed_desc_read_flags(&desc->flags, desc_hva, i);

    if (strict_order) {
        /* Make sure flags is read before the rest fields. */
        smp_rmb();
	}


	desc->addr = *(uint64_t*)(desc_hva +
					off + offsetof(VRingPackedDesc, addr));
	desc->id = *(uint16_t*)(desc_hva +
					off + offsetof(VRingPackedDesc, id));
	desc->len = *(uint32_t*)(desc_hva +
					off + offsetof(VRingPackedDesc, len));
}

static bool virtqueue_map_desc(VirtIODevice *vdev, unsigned int *p_num_sg,
                               hwaddr *addr, struct iovec *iov,
                               unsigned int max_num_sg, bool is_write,
                               hwaddr pa, size_t sz)
{
    bool ok = false;
    unsigned num_sg = *p_num_sg;
	struct kvm *kvm = vdev->pci_dev.bus->kvm;
	struct gfn_to_hva_cache ghc;

    if (!sz) {
        printk(">>>>>%s:%d\n", __func__, __LINE__);
        goto out;
    }

    if (num_sg == max_num_sg) {
    	printk(">>>>>%s:%d\n", __func__, __LINE__);
        goto out;
    }

	if (kvm_gfn_to_hva_cache_init(kvm, &ghc, pa, sz)) {
      	printk(">>>>>%s:%d\n", __func__, __LINE__);
        goto out;
	}

//    printk(">>>>>%s:%d %lx %lx %d\n", __func__, __LINE__, iov, addr, num_sg);

#if 0
	iov[num_sg].iov_base = (void*)ghc.hva;
    iov[num_sg].iov_len = sz;
    addr[num_sg] = pa;

    num_sg++;
#endif

    ok = true;

out:
    *p_num_sg = num_sg;
    return ok;
}

static int virtqueue_packed_read_next_desc(VirtQueue *vq,
                                           VRingPackedDesc *desc,
                                           uint64_t hva,
                                           unsigned int max,
                                           unsigned int *next,
                                           bool indirect)
{
    /* If this descriptor says it doesn't chain, we're done. */
    if (!indirect && !(desc->flags & VRING_DESC_F_NEXT))
        return VIRTQUEUE_READ_DESC_DONE;

    ++*next;
    if (*next == max) {
        if (indirect) {
            return VIRTQUEUE_READ_DESC_DONE;
        } else {
            (*next) -= vq->vring.num;
        }
    }

    vring_packed_desc_read(vq->vdev, desc, hva, *next, false);

    return VIRTQUEUE_READ_DESC_MORE;
}

static void *virtqueue_alloc_element(unsigned out_num, unsigned in_num)
{
    VirtQueueElement *elem;

    size_t in_addr_ofs = ALIGN_UP(sizeof(VirtQueueElement), __alignof__(elem->in_addr[0]));
    size_t out_addr_ofs = in_addr_ofs + in_num * sizeof(elem->in_addr[0]);
    size_t out_addr_end = out_addr_ofs + out_num * sizeof(elem->out_addr[0]);
    size_t in_sg_ofs = ALIGN_UP(out_addr_end, __alignof__(elem->in_sg[0]));
    size_t out_sg_ofs = in_sg_ofs + in_num * sizeof(elem->in_sg[0]);
    size_t out_sg_end = out_sg_ofs + out_num * sizeof(elem->out_sg[0]);

    elem = kzalloc(out_sg_end, GFP_KERNEL);

    elem->out_num = out_num;
    elem->in_num = in_num;
    elem->in_addr = (void *)elem + in_addr_ofs;
    elem->out_addr = (void *)elem + out_addr_ofs;
    elem->in_sg = (void *)elem + in_sg_ofs;
    elem->out_sg = (void *)elem + out_sg_ofs;

    return elem;
}


static void *virtqueue_packed_pop(VirtQueue *vq)
{
    unsigned int i, max;
    VirtIODevice *vdev = vq->vdev;
	struct kvm *kvm = vdev->pci_dev.bus->kvm;
    VirtQueueElement *elem = NULL;
    unsigned out_num, in_num, elem_entries;

    VRingPackedDesc desc;
    uint16_t id;
    int rc;
	bool indirect_flag = false;
	uint64_t hva;
	struct gfn_to_hva_cache ghc;
	hwaddr *addr = kmalloc(sizeof(hwaddr) * VIRTQUEUE_MAX_SIZE, GFP_KERNEL);
	struct iovec *iov = kmalloc(sizeof(struct iovec) * VIRTQUEUE_MAX_SIZE, GFP_KERNEL);

    if (virtio_queue_packed_empty_rcu(vq))
        goto done;

    /* When we start there are none of either input nor output. */
    out_num = in_num = elem_entries = 0;

    max = vq->vring.num;

    if (vq->inuse >= vq->vring.num) {
        printk(">>>>>%s:%d\n", __func__, __LINE__);
        goto done;
    }

    i = vq->last_avail_idx;

	hva = vq->desc_hva;
    vring_packed_desc_read(vdev, &desc, hva, i, true);

    id = desc.id;
    if (desc.flags & VRING_DESC_F_INDIRECT) {
        if (desc.len % sizeof(VRingPackedDesc)) {
        	printk(">>>>>%s:%d\n", __func__, __LINE__);
            goto done;
        }

		indirect_flag = true;

		if (kvm_gfn_to_hva_cache_init(kvm, &ghc, desc.addr, desc.len)) {
			printk(">>>>>%s:%d\n",__func__,__LINE__);
			goto done;
		}
		hva = ghc.hva;

        max = desc.len / sizeof(VRingPackedDesc);
        i = 0;

        vring_packed_desc_read(vdev, &desc, hva, i, false);
    }

    /* Collect all the descriptors */
    do {
        bool map_ok;

        if (desc.flags & VRING_DESC_F_WRITE) {
            map_ok = virtqueue_map_desc(vdev, &in_num, addr + out_num,
                                        iov + out_num,
                                        VIRTQUEUE_MAX_SIZE - out_num, true,
                                        desc.addr, desc.len);
        } else {
            if (in_num) {
                printk(">>>>Incorrect order for descriptors %s:%d\n",
					__func__, __LINE__);
                goto err_undo_map;
            }
            map_ok = virtqueue_map_desc(vdev, &out_num, addr,
										iov,
                                        VIRTQUEUE_MAX_SIZE, false,
                                        desc.addr, desc.len);
        }


        if (!map_ok)
            goto err_undo_map;


        /* If we've got too many, that implies a descriptor loop. */
        if (++elem_entries > max) {
            printk(">>>>Looped descriptor %s:%d\n", __func__, __LINE__);
            goto err_undo_map;
        }

        rc = virtqueue_packed_read_next_desc(vq, &desc, hva, max, &i,
                                             indirect_flag);
    } while (rc == VIRTQUEUE_READ_DESC_MORE);


    /* Now copy what we have collected and mapped */
    elem = virtqueue_alloc_element(out_num, in_num);
    for (i = 0; i < out_num; i++) {
        elem->out_addr[i] = addr[i];
        elem->out_sg[i] = iov[i];
    }

    for (i = 0; i < in_num; i++) {
        elem->in_addr[i] = addr[out_num + i];
        elem->in_sg[i] = iov[out_num + i];
    }

    elem->index = id;
    elem->ndescs = indirect_flag ? 1 : elem_entries;
    vq->last_avail_idx += elem->ndescs;
    vq->inuse += elem->ndescs;

    if (vq->last_avail_idx >= vq->vring.num) {
        vq->last_avail_idx -= vq->vring.num;
        vq->last_avail_wrap_counter ^= 1;
    }

    vq->shadow_avail_idx = vq->last_avail_idx;
    vq->shadow_avail_wrap_counter = vq->last_avail_wrap_counter;

done:
err_undo_map:
	kfree(iov);
	kfree(addr);
    return elem;
}

/* Called within rcu_read_lock().  */
static inline uint16_t vring_avail_idx(VirtQueue *vq)
{
//    VRingMemoryRegionCaches *caches = vring_get_region_caches(vq);
    hwaddr pa = offsetof(VRingAvail, idx);

    vq->shadow_avail_idx = *(uint16_t*)(vq->avail_hva + pa);

//virtio_lduw_phys_cached(vq->vdev, &caches->avail, pa);

    return vq->shadow_avail_idx;
}

/* Called within rcu_read_lock().  */
static inline uint16_t vring_avail_ring(VirtQueue *vq, int i)
{
//    VRingMemoryRegionCaches *caches = vring_get_region_caches(vq);
    hwaddr pa = offsetof(VRingAvail, ring[i]);

    return *(uint16_t*)(vq->avail_hva + pa);

    //return virtio_lduw_phys_cached(vq->vdev, &caches->avail, pa);
}


static int virtio_queue_empty_rcu(VirtQueue *vq)
{
    if (unlikely(vq->vdev->broken))
        return 1;

    if (unlikely(!vq->vring.avail))
        return 1;

    if (vq->shadow_avail_idx != vq->last_avail_idx)
        return 0;

    return vring_avail_idx(vq) == vq->last_avail_idx;
}

/* Called within rcu_read_lock().  */
static inline void vring_set_avail_event(VirtQueue *vq, uint16_t val)
{
//    VRingMemoryRegionCaches *caches;
    hwaddr pa;
    if (!vq->notification)
        return;

//    caches = vring_get_region_caches(vq);
    pa = offsetof(VRingUsed, ring[vq->vring.num]);

	*(uint16_t*)(vq->used_hva + pa) = val;
    //virtio_stw_phys_cached(vq->vdev, &caches->used, pa, val);
//    address_space_cache_invalidate(&caches->used, pa, sizeof(val));
}



static bool virtqueue_get_head(VirtQueue *vq, unsigned int idx,
                               unsigned int *head)
{
    /* Grab the next descriptor number they're advertising, and increment
     * the index we've seen. */
    *head = vring_avail_ring(vq, idx % vq->vring.num);

    /* If their number is silly, that's a fatal mistake. */
    if (*head >= vq->vring.num) {
        printk(">>>>%s:%d\n", __func__, __LINE__);
        return false;
    }

    return true;
}

static void vring_split_desc_read(VirtIODevice *vdev, VRingDesc *desc,
                                  uint64_t desc_hva, int i)
{
	memcpy(desc, (void*)(desc_hva + i * sizeof(VRingDesc)),
			sizeof(VRingDesc));
#if 0
    virtio_tswap64s(vdev, &desc->addr);
    virtio_tswap32s(vdev, &desc->len);
    virtio_tswap16s(vdev, &desc->flags);
    virtio_tswap16s(vdev, &desc->next);
#endif
}

static int virtqueue_split_read_next_desc(VirtIODevice *vdev, VRingDesc *desc,
                                          uint64_t desc_hva,
                                          unsigned int max, unsigned int *next)
{
    /* If this descriptor says it doesn't chain, we're done. */
    if (!(desc->flags & VRING_DESC_F_NEXT))
        return VIRTQUEUE_READ_DESC_DONE;

    /* Check they're not leading us off end of descriptors. */
    *next = desc->next;
    /* Make sure compiler knows to grab that: we don't want it changing! */
    smp_wmb();

    if (*next >= max) {
        printk(">>>%s:%d\n", __func__, __LINE__);
        return VIRTQUEUE_READ_DESC_ERROR;
    }

    vring_split_desc_read(vdev, desc, desc_hva, *next);

    return VIRTQUEUE_READ_DESC_MORE;
}

static void *virtqueue_split_pop(VirtQueue *vq)
{
    unsigned int i, head, max;
    VirtIODevice *vdev = vq->vdev;
	struct kvm *kvm = vdev->pci_dev.bus->kvm;
    VirtQueueElement *elem = NULL;
    unsigned out_num, in_num, elem_entries;
    VRingDesc desc;
    int rc;
	uint64_t desc_hva;
	struct gfn_to_hva_cache ghc;

	hwaddr *addr = kmalloc(sizeof(hwaddr) * VIRTQUEUE_MAX_SIZE, GFP_KERNEL);
	struct iovec *iov = kmalloc(sizeof(struct iovec) * VIRTQUEUE_MAX_SIZE, GFP_KERNEL);

    if (virtio_queue_empty_rcu(vq))
        goto done;

    /* Needed after virtio_queue_empty(), see comment in
     * virtqueue_num_heads(). */
    smp_rmb();

    /* When we start there are none of either input nor output. */
    out_num = in_num = elem_entries = 0;

    max = vq->vring.num;

    if (vq->inuse >= vq->vring.num) {
        printk(">>>>Virtqueue size exceeded %s:%d\n", __func__, __LINE__);
        goto done;
    }

    if (!virtqueue_get_head(vq, vq->last_avail_idx++, &head))
        goto done;

    if (virtio_vdev_has_feature(vdev, VIRTIO_RING_F_EVENT_IDX))
        vring_set_avail_event(vq, vq->last_avail_idx);

    i = head;

	desc_hva = vq->desc_hva;

    vring_split_desc_read(vdev, &desc, desc_hva, i);
    if (desc.flags & VRING_DESC_F_INDIRECT) {
        if (!desc.len || (desc.len % sizeof(VRingDesc))) {
            printk(">>>>Invalid size for indirect buffer table %s:%d\n",
				__func__, __LINE__);
            goto done;
        }

		if (kvm_gfn_to_hva_cache_init(kvm, &ghc, desc.addr, desc.len)) {
            printk(">>>>Cannot map indirect buffer %s:%d\n", __func__, __LINE__);
            goto done;
        }
		desc_hva = ghc.hva;

        max = desc.len / sizeof(VRingDesc);
        i = 0;
        vring_split_desc_read(vdev, &desc, desc_hva, i);
    }


    /* Collect all the descriptors */
    do {
        bool map_ok;

        if (desc.flags & VRING_DESC_F_WRITE) {
    		map_ok = false;
    		if (desc.len &&
					in_num < VIRTQUEUE_MAX_SIZE - out_num &&
					!kvm_gfn_to_hva_cache_init(kvm, &ghc, desc.addr, desc.len)) {
				iov[out_num + in_num].iov_base = (void*)ghc.hva;
    			iov[out_num + in_num].iov_len = desc.len;
    			addr[out_num + in_num] = desc.addr;
    			in_num++;
    			map_ok = true;
    		}
        } else {
            if (in_num) {
                printk(">>>Incorrect order for descriptors %s:%d\n", __func__, __LINE__);
                goto err_undo_map;
            }

    		map_ok = false;
    		if (desc.len &&
					out_num < VIRTQUEUE_MAX_SIZE &&
					!kvm_gfn_to_hva_cache_init(kvm, &ghc, desc.addr, desc.len)) {
				iov[out_num].iov_base = (void*)ghc.hva;
    			iov[out_num].iov_len = desc.len;
    			addr[out_num] = desc.addr;
    			out_num++;
    			map_ok = true;
    		}
        }

        if (!map_ok)
            goto err_undo_map;

        /* If we've got too many, that implies a descriptor loop. */
        if (++elem_entries > max) {
            printk(">>>>Looped descriptor %s:%d\n", __func__, __LINE__);
            goto err_undo_map;
        }

        rc = virtqueue_split_read_next_desc(vdev, &desc, desc_hva, max, &i);
    } while (rc == VIRTQUEUE_READ_DESC_MORE);


    if (rc == VIRTQUEUE_READ_DESC_ERROR)
        goto err_undo_map;

    /* Now copy what we have collected and mapped */
    elem = virtqueue_alloc_element(out_num, in_num);

    elem->index = head;
    elem->ndescs = 1;

    for (i = 0; i < out_num; i++) {
        elem->out_addr[i] = addr[i];
        elem->out_sg[i] = iov[i];
    }

    for (i = 0; i < in_num; i++) {
        elem->in_addr[i] = addr[out_num + i];
        elem->in_sg[i] = iov[out_num + i];
    }

    vq->inuse++;


done:
err_undo_map:
	kfree(iov);
	kfree(addr);
    return elem;
}


static void *virtqueue_pop(VirtQueue *vq)
{
    if (unlikely(vq->vdev->broken))
        return NULL;

    if (virtio_vdev_has_feature(vq->vdev, VIRTIO_F_RING_PACKED)) {
        return virtqueue_packed_pop(vq);
    } else {
        return virtqueue_split_pop(vq);
    }
}

static void virtqueue_detach_element(VirtQueue *vq, const VirtQueueElement *elem,
                              unsigned int len)
{           
    vq->inuse -= elem->ndescs;
}


static size_t iov_to_buf_full(const struct iovec *iov, const unsigned int iov_cnt,
                       size_t offset, void *buf, size_t bytes)
{
    size_t done;
    unsigned int i;
    for (i = 0, done = 0; (offset || done < bytes) && i < iov_cnt; i++) {
        if (offset < iov[i].iov_len) {
            size_t len = MIN(iov[i].iov_len - offset, bytes - done);
            memcpy(buf + done, iov[i].iov_base + offset, len);
            done += len;
            offset = 0;
        } else {
            offset -= iov[i].iov_len;
        }
    }   

    return done;
}


static inline size_t
iov_to_buf(const struct iovec *iov, const unsigned int iov_cnt,
           size_t offset, void *buf, size_t bytes)
{
    if (__builtin_constant_p(bytes) && iov_cnt &&
        offset <= iov[0].iov_len && bytes <= iov[0].iov_len - offset) {
        memcpy(buf, iov[0].iov_base + offset, bytes);
        return bytes;
    } else {
        return iov_to_buf_full(iov, iov_cnt, offset, buf, bytes);
    }   
}

static size_t iov_discard_front(struct iovec **iov, unsigned int *iov_cnt,
                         size_t bytes)
{       
    size_t total = 0;
    struct iovec *cur;
            
    for (cur = *iov; *iov_cnt > 0; cur++) {
        if (cur->iov_len > bytes) {
            cur->iov_base += bytes;
            cur->iov_len -= bytes;
            total += bytes;
            break; 
        } 
            
        bytes -= cur->iov_len;
        total += cur->iov_len;
        *iov_cnt -= 1;
    }

    *iov = cur;
    return total;
}

static size_t iov_from_buf_full(const struct iovec *iov, unsigned int iov_cnt,
                         size_t offset, const void *buf, size_t bytes)
{   
    size_t done;
    unsigned int i;
    for (i = 0, done = 0; (offset || done < bytes) && i < iov_cnt; i++) {
        if (offset < iov[i].iov_len) {
            size_t len = MIN(iov[i].iov_len - offset, bytes - done);
            memcpy(iov[i].iov_base + offset, buf + done, len);
            done += len;
            offset = 0;
        } else {
            offset -= iov[i].iov_len;
        }
    }
    return done;
}

static inline size_t
iov_from_buf(const struct iovec *iov, unsigned int iov_cnt,
             size_t offset, const void *buf, size_t bytes)
{
    if (__builtin_constant_p(bytes) && iov_cnt &&
        offset <= iov[0].iov_len && bytes <= iov[0].iov_len - offset) {
        memcpy(iov[0].iov_base + offset, buf, bytes);
        return bytes;
    } else {
        return iov_from_buf_full(iov, iov_cnt, offset, buf, bytes);
    }
}

static void virtqueue_packed_fill(VirtQueue *vq, const VirtQueueElement *elem,
                                  unsigned int len, unsigned int idx)
{
    vq->used_elems[idx].index = elem->index;
    vq->used_elems[idx].len = len;
    vq->used_elems[idx].ndescs = elem->ndescs;
}

static inline void vring_used_write(VirtQueue *vq, VRingUsedElem *uelem,
                                    int i)
{
    //VRingMemoryRegionCaches *caches = vring_get_region_caches(vq);
    hwaddr pa = offsetof(VRingUsed, ring[i]);
  //  virtio_tswap32s(vq->vdev, &uelem->id);
   // virtio_tswap32s(vq->vdev, &uelem->len);
	memcpy((void*)(vq->used_hva + pa), uelem, sizeof(VRingUsedElem));
//    address_space_write_cached(&caches->used, pa, uelem, sizeof(VRingUsedElem));
 //   address_space_cache_invalidate(&caches->used, pa, sizeof(VRingUsedElem));
}


static void virtqueue_split_fill(VirtQueue *vq, const VirtQueueElement *elem,
                    unsigned int len, unsigned int idx)
{
    VRingUsedElem uelem;

    if (unlikely(!vq->vring.used))
        return;

    idx = (idx + vq->used_idx) % vq->vring.num;

    uelem.id = elem->index;
    uelem.len = len;
    vring_used_write(vq, &uelem, idx);
}


/* Called within rcu_read_lock().  */
static void virtqueue_fill(VirtQueue *vq, const VirtQueueElement *elem,
                    unsigned int len, unsigned int idx)
{
    if (unlikely(vq->vdev->broken))
        return;

    if (virtio_vdev_has_feature(vq->vdev, VIRTIO_F_RING_PACKED)) {
        virtqueue_packed_fill(vq, elem, len, idx);
    } else {
        virtqueue_split_fill(vq, elem, len, idx);
    }
}

static void vring_packed_desc_write_data(VirtIODevice *vdev,
                                         VRingPackedDesc *desc,
                                         uint64_t desc_hva,
                                         int i)
{
    hwaddr off_id = i * sizeof(VRingPackedDesc) +
                    offsetof(VRingPackedDesc, id);
    hwaddr off_len = i * sizeof(VRingPackedDesc) +
                    offsetof(VRingPackedDesc, len);

	*(uint16_t*)(desc_hva + off_id) = desc->id;
	*(uint32_t*)(desc_hva + off_len) = desc->len;
#if 0
    virtio_tswap32s(vdev, &desc->len);
    virtio_tswap16s(vdev, &desc->id);
    address_space_write_cached(cache, off_id, &desc->id, sizeof(desc->id));
    address_space_cache_invalidate(cache, off_id, sizeof(desc->id));
    address_space_write_cached(cache, off_len, &desc->len, sizeof(desc->len));
    address_space_cache_invalidate(cache, off_len, sizeof(desc->len));
#endif
}

static void vring_packed_desc_write_flags(VirtIODevice *vdev,
                                          VRingPackedDesc *desc,
                                          uint64_t desc_hva,
                                          int i)
{
    hwaddr off = i * sizeof(VRingPackedDesc) + offsetof(VRingPackedDesc, flags);

	*(uint32_t*)(desc_hva + off) = desc->flags;
#if 0
    virtio_tswap16s(vdev, &desc->flags);
    address_space_write_cached(cache, off, &desc->flags, sizeof(desc->flags));
    address_space_cache_invalidate(cache, off, sizeof(desc->flags));
#endif
}

static void vring_packed_desc_write(VirtIODevice *vdev,
                                    VRingPackedDesc *desc,
                                    uint64_t desc_hva,
                                    int i, bool strict_order)
{
    vring_packed_desc_write_data(vdev, desc, desc_hva, i);
    if (strict_order) {
        /* Make sure data is wrote before flags. */
        smp_wmb();
    }
    vring_packed_desc_write_flags(vdev, desc, desc_hva, i);
}



static void virtqueue_packed_fill_desc(VirtQueue *vq,
                                       const VirtQueueElement *elem,
                                       unsigned int idx,
                                       bool strict_order)
{
    uint16_t head;
//    VRingMemoryRegionCaches *caches;
    VRingPackedDesc desc = {
        .id = elem->index,
        .len = elem->len,
    };
    bool wrap_counter = vq->used_wrap_counter;

    if (unlikely(!vq->vring.desc))
        return;

    head = vq->used_idx + idx;
    if (head >= vq->vring.num) {
        head -= vq->vring.num;
        wrap_counter ^= 1;
    }

    if (wrap_counter) {
        desc.flags |= (1 << VRING_PACKED_DESC_F_AVAIL);
        desc.flags |= (1 << VRING_PACKED_DESC_F_USED);
    } else {
        desc.flags &= ~(1 << VRING_PACKED_DESC_F_AVAIL);
        desc.flags &= ~(1 << VRING_PACKED_DESC_F_USED);
    }

  //  caches = vring_get_region_caches(vq);
    vring_packed_desc_write(vq->vdev, &desc, vq->desc_hva, head, strict_order);
}

static void virtqueue_packed_flush(VirtQueue *vq, unsigned int count)
{
    unsigned int i, ndescs = 0;

    if (unlikely(!vq->vring.desc))
        return;

    for (i = 1; i < count; i++) {
        virtqueue_packed_fill_desc(vq, &vq->used_elems[i], i, false);
        ndescs += vq->used_elems[i].ndescs;
    }

    virtqueue_packed_fill_desc(vq, &vq->used_elems[0], 0, true);
    ndescs += vq->used_elems[0].ndescs;

    vq->inuse -= ndescs;
    vq->used_idx += ndescs;
    if (vq->used_idx >= vq->vring.num) {
        vq->used_idx -= vq->vring.num;
        vq->used_wrap_counter ^= 1;
    }
}

/* Called within rcu_read_lock().  */
static inline void vring_used_idx_set(VirtQueue *vq, uint16_t val)
{
//    VRingMemoryRegionCaches *caches = vring_get_region_caches(vq);
    hwaddr pa = offsetof(VRingUsed, idx);
//    virtio_stw_phys_cached(vq->vdev, &caches->used, pa, val);

	*(uint16_t*)(vq->used_hva + pa) = val;
//    address_space_cache_invalidate(&caches->used, pa, sizeof(val));
    vq->used_idx = val;
}


/* Called within rcu_read_lock().  */
static void virtqueue_split_flush(VirtQueue *vq, unsigned int count)
{
    uint16_t old, new;

    if (unlikely(!vq->vring.used))
        return;

    /* Make sure buffer is written before we update index. */
    smp_wmb();

    old = vq->used_idx;
    new = old + count;

    vring_used_idx_set(vq, new);
    vq->inuse -= count;

    if (unlikely((int16_t)(new - vq->signalled_used) < (uint16_t)(new - old)))
        vq->signalled_used_valid = false;
}

static void virtqueue_flush(VirtQueue *vq, unsigned int count)
{
    if (unlikely(vq->vdev->broken)) {
        vq->inuse -= count;
        return;
    }

    if (virtio_vdev_has_feature(vq->vdev, VIRTIO_F_RING_PACKED)) {
        virtqueue_packed_flush(vq, count);
    } else {
        virtqueue_split_flush(vq, count);
    }
}

static void vring_packed_event_read(VirtIODevice *vdev,
                                    uint64_t avail_hva,
                                    VRingPackedDescEvent *e)
{
    hwaddr off_off = offsetof(VRingPackedDescEvent, off_wrap);
    hwaddr off_flags = offsetof(VRingPackedDescEvent, flags);

//    address_space_read_cached(cache, off_flags, &e->flags,
 //                             sizeof(e->flags));
	e->flags = *(uint16_t*)(avail_hva + off_flags);
    /* Make sure flags is seen before off_wrap */
    smp_rmb();
 //   address_space_read_cached(cache, off_off, &e->off_wrap,
  //                            sizeof(e->off_wrap));
	e->off_wrap = *(uint16_t*)(avail_hva + off_off);

//    virtio_tswap16s(vdev, &e->off_wrap);
 //   virtio_tswap16s(vdev, &e->flags);
}

static bool vring_packed_need_event(VirtQueue *vq, bool wrap,
                                    uint16_t off_wrap, uint16_t new,
                                    uint16_t old)
{
    int off = off_wrap & ~(1 << 15);

    if (wrap != off_wrap >> 15)
        off -= vq->vring.num;

    return vring_need_event(off, new, old);
}

static bool virtio_packed_should_notify(VirtIODevice *vdev, VirtQueue *vq)
{
    VRingPackedDescEvent e;
    uint16_t old, new;
    bool v;
 //   VRingMemoryRegionCaches *caches;

  //  caches = vring_get_region_caches(vq);
    vring_packed_event_read(vdev, vq->avail_hva, &e);

    old = vq->signalled_used;
    new = vq->signalled_used = vq->used_idx;
    v = vq->signalled_used_valid;
    vq->signalled_used_valid = true;

    if (e.flags == VRING_PACKED_EVENT_FLAG_DISABLE) {
        return false;
    } else if (e.flags == VRING_PACKED_EVENT_FLAG_ENABLE) {
        return true;
    }

    return !v || vring_packed_need_event(vq, vq->used_wrap_counter,
                                         e.off_wrap, new, old);
}

static int virtio_queue_packed_empty(VirtQueue *vq)
{
    return virtio_queue_packed_empty_rcu(vq);
}

static int virtio_queue_split_empty(VirtQueue *vq)
{
    bool empty;

    if (unlikely(vq->vdev->broken))
        return 1;

    if (unlikely(!vq->vring.avail))
        return 1;

    if (vq->shadow_avail_idx != vq->last_avail_idx)
        return 0;

    empty = vring_avail_idx(vq) == vq->last_avail_idx;
    return empty;
}

static int virtio_queue_empty(VirtQueue *vq)
{
    if (virtio_vdev_has_feature(vq->vdev, VIRTIO_F_RING_PACKED)) {
        return virtio_queue_packed_empty(vq);
    } else {
        return virtio_queue_split_empty(vq);
    }
}

/* Called within rcu_read_lock().  */
static inline uint16_t vring_avail_flags(VirtQueue *vq)
{
//    VRingMemoryRegionCaches *caches = vring_get_region_caches(vq);
    hwaddr pa = offsetof(VRingAvail, flags);
  //  return virtio_lduw_phys_cached(vq->vdev, &caches->avail, pa);
	return *(uint16_t*)(vq->avail_hva + pa);
}

/* Called within rcu_read_lock().  */
static inline uint16_t vring_get_used_event(VirtQueue *vq)
{
    return vring_avail_ring(vq, vq->vring.num);
}

static bool virtio_split_should_notify(VirtIODevice *vdev, VirtQueue *vq)
{
    uint16_t old, new;
    bool v;
    /* We need to expose used array entries before checking used event. */
    smp_mb();
    /* Always notify when queue is empty (when feature acknowledge) */
    if (virtio_vdev_has_feature(vdev, VIRTIO_F_NOTIFY_ON_EMPTY) &&
        !vq->inuse && virtio_queue_empty(vq))
        return true;

    if (!virtio_vdev_has_feature(vdev, VIRTIO_RING_F_EVENT_IDX))
        return !(vring_avail_flags(vq) & VRING_AVAIL_F_NO_INTERRUPT);
    
    v = vq->signalled_used_valid;
    vq->signalled_used_valid = true;
    old = vq->signalled_used;
    new = vq->signalled_used = vq->used_idx;

    return !v || vring_need_event(vring_get_used_event(vq), new, old);
}


static bool virtio_should_notify(VirtIODevice *vdev, VirtQueue *vq)
{   
    if (virtio_vdev_has_feature(vdev, VIRTIO_F_RING_PACKED)) {
        return virtio_packed_should_notify(vdev, vq);
    } else {
        return virtio_split_should_notify(vdev, vq);
    }   
}

static void virtio_set_isr(VirtIODevice *vdev, int value)
{
    uint8_t old = atomic_read(&vdev->isr_val);

    /* Do not write ISR if it does not change, so that its cacheline remains
     * shared in the common case where the guest does not read it.
     */
    if ((old & value) != value)
        atomic_or(value, &vdev->isr_val);
}

static void virtio_irq(VirtQueue *vq)
{
    virtio_set_isr(vq->vdev, 0x1);
    virtio_notify_vector(vq->vdev, vq->vector);
}

static void virtio_notify(VirtIODevice *vdev, VirtQueue *vq)
{   
   if (!virtio_should_notify(vdev, vq))
       return;

    virtio_irq(vq);                    
}

static void virtqueue_push(VirtQueue *vq, const VirtQueueElement *elem,
                    unsigned int len)
{       
    virtqueue_fill(vq, elem, len, 0);
    virtqueue_flush(vq, 1);
} 

static int virtio_net_handle_rx_mode(VirtIONet *n, uint8_t cmd,
                                     struct iovec *iov, unsigned int iov_cnt)
{
    uint8_t on;
    size_t s;

    s = iov_to_buf(iov, iov_cnt, 0, &on, sizeof(on));
    if (s != sizeof(on))
        return VIRTIO_NET_ERR;

    if (cmd == VIRTIO_NET_CTRL_RX_PROMISC ||
    	cmd == VIRTIO_NET_CTRL_RX_ALLMULTI ||
    	cmd == VIRTIO_NET_CTRL_RX_ALLUNI ||
    	cmd == VIRTIO_NET_CTRL_RX_NOMULTI ||
    	cmd == VIRTIO_NET_CTRL_RX_NOUNI ||
    	cmd == VIRTIO_NET_CTRL_RX_NOBCAST) {
    	return VIRTIO_NET_OK;
    }


    return VIRTIO_NET_ERR;
}

static size_t iov_size(const struct iovec *iov, const unsigned int iov_cnt)
{
    size_t len;
    unsigned int i;

    len = 0;
    for (i = 0; i < iov_cnt; i++) {
        len += iov[i].iov_len;
    }
    return len;
} 

static int virtio_net_handle_mac(VirtIONet *n, uint8_t cmd,
                                 struct iovec *iov, unsigned int iov_cnt)
{
    struct virtio_net_ctrl_mac mac_data;
    size_t s;
    int in_use = 0;
    uint8_t *macs;

    if (cmd == VIRTIO_NET_CTRL_MAC_ADDR_SET) {
        if (iov_size(iov, iov_cnt) != sizeof(n->mac))
            return VIRTIO_NET_ERR;

        s = iov_to_buf(iov, iov_cnt, 0, &n->mac, sizeof(n->mac));

        return VIRTIO_NET_OK;
    }

    if (cmd != VIRTIO_NET_CTRL_MAC_TABLE_SET)
        return VIRTIO_NET_ERR;

    macs = kzalloc(MAC_TABLE_ENTRIES * ETH_ALEN, GFP_KERNEL);

    s = iov_to_buf(iov, iov_cnt, 0, &mac_data.entries,
                   sizeof(mac_data.entries));
    if (s != sizeof(mac_data.entries))
        goto error;

    iov_discard_front(&iov, &iov_cnt, s);

    if (mac_data.entries * ETH_ALEN > iov_size(iov, iov_cnt))
        goto error;

    if (mac_data.entries <= MAC_TABLE_ENTRIES) {
        s = iov_to_buf(iov, iov_cnt, 0, macs,
                       mac_data.entries * ETH_ALEN);
        if (s != mac_data.entries * ETH_ALEN) {
            goto error;
        }
        in_use += mac_data.entries;
    }
    iov_discard_front(&iov, &iov_cnt, mac_data.entries * ETH_ALEN);

    s = iov_to_buf(iov, iov_cnt, 0, &mac_data.entries,
                   sizeof(mac_data.entries));
    if (s != sizeof(mac_data.entries))
        goto error;

    iov_discard_front(&iov, &iov_cnt, s);

    if (mac_data.entries * ETH_ALEN != iov_size(iov, iov_cnt))
        goto error;

    if (mac_data.entries <= MAC_TABLE_ENTRIES - in_use) {
        s = iov_to_buf(iov, iov_cnt, 0, &macs[in_use * ETH_ALEN],
                       mac_data.entries * ETH_ALEN);
        if (s != mac_data.entries * ETH_ALEN) {
            goto error;
        }
        in_use += mac_data.entries;
    }

    kfree(macs);

    return VIRTIO_NET_OK;

error:
    kfree(macs);
    return VIRTIO_NET_ERR;
}


static int virtio_net_handle_vlan_table(VirtIONet *n, uint8_t cmd,
                                        struct iovec *iov, unsigned int iov_cnt)
{
    uint16_t vid;
    size_t s;

    s = iov_to_buf(iov, iov_cnt, 0, &vid, sizeof(vid));
    if (s != sizeof(vid))
        return VIRTIO_NET_ERR;

    if (vid >= MAX_VLAN)
        return VIRTIO_NET_ERR;

    if (cmd == VIRTIO_NET_CTRL_VLAN_ADD ||
        cmd == VIRTIO_NET_CTRL_VLAN_DEL) {
        return VIRTIO_NET_OK;
    }

    return VIRTIO_NET_ERR;
}

static int virtio_net_handle_announce(VirtIONet *n, uint8_t cmd,
                                      struct iovec *iov, unsigned int iov_cnt)
{
    if (cmd == VIRTIO_NET_CTRL_ANNOUNCE_ACK &&
        n->status & VIRTIO_NET_S_ANNOUNCE) {
        n->status &= ~VIRTIO_NET_S_ANNOUNCE;
        return VIRTIO_NET_OK;
    } else {
        return VIRTIO_NET_ERR;
    }
}

static int virtio_net_handle_mq(VirtIONet *n, uint8_t cmd,
                                struct iovec *iov, unsigned int iov_cnt)
{
    VirtIODevice *vdev = (VirtIODevice *)(n);
    struct virtio_net_ctrl_mq mq;
    size_t s;
    uint16_t queues;

    s = iov_to_buf(iov, iov_cnt, 0, &mq, sizeof(mq));
    if (s != sizeof(mq))
        return VIRTIO_NET_ERR;

    if (cmd != VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET)
        return VIRTIO_NET_ERR;

    queues = mq.virtqueue_pairs;

    if (queues < VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN ||
        queues > VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX ||
        queues > n->max_queues ||
        !n->multiqueue) {
        return VIRTIO_NET_ERR;
    }

    n->curr_queues = queues;

    /* stop the backend before changing the number of queues to avoid handling a
     * disabled queue */
    virtio_net_set_status(vdev, vdev->status);
    virtio_net_set_queues(n);

    return VIRTIO_NET_OK;
}

static inline uint64_t virtio_net_supported_guest_offloads(VirtIONet *n)
{
    VirtIODevice *vdev = (VirtIODevice *)(n);
    return virtio_net_guest_offloads_by_features(vdev->guest_features);
}

static int virtio_net_handle_offloads(VirtIONet *n, uint8_t cmd,
                                     struct iovec *iov, unsigned int iov_cnt)
{
    VirtIODevice *vdev = (VirtIODevice *)(n);
    uint64_t offloads;
    size_t s;

    if (!virtio_vdev_has_feature(vdev, VIRTIO_NET_F_CTRL_GUEST_OFFLOADS))
        return VIRTIO_NET_ERR;

    s = iov_to_buf(iov, iov_cnt, 0, &offloads, sizeof(offloads));
    if (s != sizeof(offloads))
        return VIRTIO_NET_ERR;

    if (cmd == VIRTIO_NET_CTRL_GUEST_OFFLOADS_SET) {
        uint64_t supported_offloads;

        if (!n->has_vnet_hdr)
            return VIRTIO_NET_ERR;

        virtio_clear_feature(&offloads, VIRTIO_NET_F_RSC_EXT);

        supported_offloads = virtio_net_supported_guest_offloads(n);
        if (offloads & ~supported_offloads) {
            return VIRTIO_NET_ERR;
        }

        n->curr_guest_offloads = offloads;
        virtio_net_apply_guest_offloads(n);

        return VIRTIO_NET_OK;
    } else {
        return VIRTIO_NET_ERR;
    }
}

static void virtio_net_handle_ctrl(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtIONet *n = (VirtIONet *)(vdev);
    struct virtio_net_ctrl_hdr ctrl;
    virtio_net_ctrl_ack status = VIRTIO_NET_ERR;
    VirtQueueElement *elem;
    size_t s;
    struct iovec *iov;
    unsigned int iov_cnt;

    for (;;) {
        elem = virtqueue_pop(vq);
        if (!elem)
            break;

        if (iov_size(elem->in_sg, elem->in_num) < sizeof(status) ||
            iov_size(elem->out_sg, elem->out_num) < sizeof(ctrl)) {
            virtqueue_detach_element(vq, elem, 0);
            kfree(elem);
            break;
        }

        iov_cnt = elem->out_num;
        iov = elem->out_sg;

        s = iov_to_buf(iov, iov_cnt, 0, &ctrl, sizeof(ctrl));
        iov_discard_front(&iov, &iov_cnt, sizeof(ctrl));

        if (s != sizeof(ctrl)) {
            status = VIRTIO_NET_ERR;
        } else if (ctrl.class == VIRTIO_NET_CTRL_RX) {
            status = virtio_net_handle_rx_mode(n, ctrl.cmd, iov, iov_cnt);
        } else if (ctrl.class == VIRTIO_NET_CTRL_MAC) {
            status = virtio_net_handle_mac(n, ctrl.cmd, iov, iov_cnt);
        } else if (ctrl.class == VIRTIO_NET_CTRL_VLAN) {
            status = virtio_net_handle_vlan_table(n, ctrl.cmd, iov, iov_cnt);
        } else if (ctrl.class == VIRTIO_NET_CTRL_ANNOUNCE) {
            status = virtio_net_handle_announce(n, ctrl.cmd, iov, iov_cnt);
        } else if (ctrl.class == VIRTIO_NET_CTRL_MQ) {
            status = virtio_net_handle_mq(n, ctrl.cmd, iov, iov_cnt);
        } else if (ctrl.class == VIRTIO_NET_CTRL_GUEST_OFFLOADS) {
            status = virtio_net_handle_offloads(n, ctrl.cmd, iov, iov_cnt);
        }

        s = iov_from_buf(elem->in_sg, elem->in_num, 0, &status, sizeof(status));
        if (s != sizeof(status))
			printk(">>>>%s:%d\n", __func__, __LINE__);

        virtqueue_push(vq, elem, sizeof(status));
        virtio_notify(vdev, vq);
        kfree(elem);
    }
}

static void virtio_net_change_num_queues(VirtIONet *n, int new_max_queues)
{   
    VirtIODevice *vdev = (VirtIODevice *)(n);
    int old_num_queues = virtio_get_num_queues(vdev);
    int new_num_queues = new_max_queues * 2 + 1;
    int i;

//	printk(">>>>>%s:%d %d %d\n",__func__, __LINE__, old_num_queues, new_num_queues);
    
    if (old_num_queues == new_num_queues)
        return;
    
    virtio_del_queue(vdev, old_num_queues - 1);
    
    for (i = new_num_queues - 1; i < old_num_queues - 1; i += 2)
        virtio_net_del_queue(n, i / 2);
    
    for (i = old_num_queues - 1; i < new_num_queues - 1; i += 2)
        virtio_net_add_queue(n, i / 2);
    
    /* add ctrl_vq last */ 
    virtio_add_queue(vdev, 64, virtio_net_handle_ctrl);
//    virtio_add_queue(vdev, 64, NULL);
}

static int tap_enable(VirtIONet *n, int index)
{       
    NetClientState *nc = n->my_sub_ncs[index];

    struct ifreq ifr;
    int ret;
    
    if (!nc)
        return 0;

    if (n->max_queues == 1)
        return 0;

    if (nc->enabled) {
        return 0;
    } else {
    	memset(&ifr, 0, sizeof(ifr));
    	ifr.ifr_flags = IFF_ATTACH_QUEUE;

		ret = my_tun_set_queue(nc->tap_priv, &ifr);
        if (ret == 0)
            nc->enabled = true;

        return ret;
    }
}

static int tap_disable(VirtIONet *n, int index)
{
    int ret;
    struct ifreq ifr;
    NetClientState *nc = n->my_sub_ncs[index];

    if (!nc)
        return 0;

    if (nc->enabled == 0) {
        return 0;
    } else {
    	memset(&ifr, 0, sizeof(ifr));
    	ifr.ifr_flags = IFF_DETACH_QUEUE;

		ret = my_tun_set_queue(nc->tap_priv, &ifr);
        if (ret == 0)
            nc->enabled = false;

        return ret;
    }
}

static void virtio_net_set_queues(VirtIONet *n)
{
    int i;
    int r;

    if (n->nic_deleted) 
        return;

    for (i = 0; i < n->max_queues; i++) {
        if (i < n->curr_queues)
            r = tap_enable(n, i);
        else
            r = tap_disable(n, i);
    }
}

static void virtio_net_set_multiqueue(VirtIONet *n, int multiqueue)
{
    int max = multiqueue ? n->max_queues : 1;

//	printk(">>>>>%s:%d %d\n",__func__, __LINE__, multiqueue);

    n->multiqueue = multiqueue;
    virtio_net_change_num_queues(n, max);

    virtio_net_set_queues(n);
}

static void virtio_net_set_hdr_len(VirtIONet *n, int mergeable_rx_bufs,
                                       int version_1)
{
	int ret;
    int i;
    NetClientState *nc;
    int guest_hdr_len;

    if (version_1)
        guest_hdr_len = sizeof(struct virtio_net_hdr_mrg_rxbuf);
    else
        guest_hdr_len = mergeable_rx_bufs ?
            sizeof(struct virtio_net_hdr_mrg_rxbuf) :
            sizeof(struct virtio_net_hdr);

    for (i = 0; i < n->max_queues; i++) {
        nc = n->my_sub_ncs[i];

        if (n->has_vnet_hdr) {
			nc->host_vnet_hdr_len = guest_hdr_len;

			if (0 > (ret = my_set_hdrsz(nc->tap_priv, &guest_hdr_len)))
				printk(">>>>>%s:%d\n", __func__, __LINE__);
        }
    }
}

static uint64_t virtio_net_guest_offloads_by_features(uint32_t features)
{
    static const uint64_t guest_offloads_mask =
        (1ULL << VIRTIO_NET_F_GUEST_CSUM) |
        (1ULL << VIRTIO_NET_F_GUEST_TSO4) |
        (1ULL << VIRTIO_NET_F_GUEST_TSO6) |
        (1ULL << VIRTIO_NET_F_GUEST_ECN)  |
        (1ULL << VIRTIO_NET_F_GUEST_UFO);

    return guest_offloads_mask & features;
}

static void virtio_net_apply_guest_offloads(VirtIONet *n)
{
    tap_set_offload(n->my_sub_ncs[0]->tap_priv,
            !!(n->curr_guest_offloads & (1ULL << VIRTIO_NET_F_GUEST_CSUM)),
            !!(n->curr_guest_offloads & (1ULL << VIRTIO_NET_F_GUEST_TSO4)),
            !!(n->curr_guest_offloads & (1ULL << VIRTIO_NET_F_GUEST_TSO6)),
            !!(n->curr_guest_offloads & (1ULL << VIRTIO_NET_F_GUEST_ECN)),
            !!(n->curr_guest_offloads & (1ULL << VIRTIO_NET_F_GUEST_UFO)));
}

static void virtio_net_set_features(VirtIODevice *vdev, uint64_t features)
{
    VirtIONet *n = (VirtIONet *)(vdev);
    int i;

//    printk(">>>>>>>%s:%d from_guest=%lx backend=%lx %s\n",
 //       __func__, __LINE__, features, vdev->backend_features, vdev->name);
    //from_guest=130efffa7 backend=179ffffe7
    if (!virtio_has_feature_(vdev->backend_features, VIRTIO_NET_F_MTU))
        features &= ~(1ULL << VIRTIO_NET_F_MTU);

    virtio_net_set_multiqueue(n, virtio_has_feature_(features, VIRTIO_NET_F_MQ));

    virtio_net_set_hdr_len(n, virtio_has_feature_(features,
                                                  VIRTIO_NET_F_MRG_RXBUF),
                               virtio_has_feature_(features,
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

static void virtio_net_reset(VirtIODevice *vdev)
{   
    VirtIONet *n = (VirtIONet *)(vdev);
    
    /* multiqueue is disabled by default */
    n->curr_queues = 1;
    n->status &= ~VIRTIO_NET_S_ANNOUNCE;
    
    /* Flush any MAC and VLAN filter table state */
    memcpy(&n->mac[0], &n->macaddr, sizeof(n->mac));
}

static int vq2q(int queue_index)
{
    return queue_index / 2;
}

static void virtio_net_guest_notifier_mask(VirtIODevice *vdev, int idx,
                                           bool mask)
{                       
    VirtIONet *n = (VirtIONet *)(vdev);
    NetClientState *nc = n->my_sub_ncs[vq2q(idx)];
    
    vhost_virtqueue_mask(&nc->dev, vdev, idx, mask);
} 

static bool virtio_net_guest_notifier_pending(VirtIODevice *vdev, int idx)
{                       
    VirtIONet *n = (VirtIONet *)(vdev);
    NetClientState *nc = n->my_sub_ncs[vq2q(idx)]; 
                            
    return vhost_virtqueue_pending(&nc->dev, idx);
} 



static int vhost_net_start_one(struct NetClientState *nc,
                               VirtIODevice *dev)
{
    struct vhost_vring_file file = { };
    int r;

    nc->dev.nvqs = 2;
    nc->dev.vqs = nc->vqs;

    r = vhost_dev_enable_notifiers(&nc->dev, dev);
    if (r < 0) {
        goto fail_notifiers;
    }

    r = vhost_dev_start(&nc->dev, dev);
    if (r < 0) {
        goto fail_start;
    }

    file.tap_priv = (uint64_t)nc->tap_priv;
    for (file.index = 0; file.index < nc->dev.nvqs; ++file.index) {
        if (!virtio_queue_enabled(dev, nc->dev.vq_index +
                                      file.index)) {
            /* Queue might not be ready for start */
            continue;
        }

		r = my_vhost_net_ioctl(nc->dev.opaque,
								VHOST_NET_SET_BACKEND,
			    				(uint64_t)&file);
        if (r < 0)
            goto fail;
    }

    return 0;
fail:
    while (file.index-- > 0) {
        if (!virtio_queue_enabled(dev, nc->dev.vq_index +
                                      file.index)) {
            /* Queue might not be ready for start */
            continue;
        }
#if 0
    	file.tap_priv = 0UL;
		my_vhost_net_ioctl(nc->dev.opaque,
								VHOST_NET_SET_BACKEND,
			    				(uint64_t)&file);
#endif
    }

    vhost_dev_stop_(&nc->dev, dev);
fail_start:
    vhost_dev_disable_notifiers(&nc->dev, dev);
fail_notifiers:
    return r;
}

static void vhost_net_stop_one(NetClientState * nc,
                               VirtIODevice *dev)
{
#if 0
    struct vhost_vring_file file = { .tap_priv = 0UL };

    for (file.index = 0; file.index < nc->dev.nvqs; ++file.index) {
		int r = my_vhost_net_ioctl(nc->dev.opaque,
								VHOST_NET_SET_BACKEND,
			    				(uint64_t)&file);
        if(r < 0)
			printk(">>>>%s:%d\n", __func__, __LINE__);
    }
#endif

    vhost_dev_stop_(&nc->dev, dev);
    vhost_dev_disable_notifiers(&nc->dev, dev);
}


static int vhost_net_start(VirtIODevice *dev, NetClientState **ncs,
                    int total_queues)
{           
    int r, e, i;         
            
    for (i = 0; i < total_queues; i++)
		ncs[i]->dev.vq_index = i * 2;

    r = virtio_pci_set_guest_notifiers(dev, total_queues * 2, true);
    if (r < 0) {
		printk(">>>>>%s:%d\n", __func__, __LINE__);
        goto err;
    }

    for (i = 0; i < total_queues; i++) {
        r = vhost_net_start_one(ncs[i], dev);
        if (r < 0)
            goto err_start;
    }

    return 0;

err_start:
    while (--i >= 0)
        vhost_net_stop_one(ncs[i], dev);

    e = virtio_pci_set_guest_notifiers(dev, total_queues * 2, false);
    if (e < 0)
		printk(">>>>>%s:%d\n", __func__, __LINE__);
err:
    return r;
}

static void vhost_net_stop(VirtIODevice *dev, NetClientState **ncs,
                    int total_queues)
{
    int i, r;

    for (i = 0; i < total_queues; i++)
        vhost_net_stop_one(ncs[i], dev);

    r = virtio_pci_set_guest_notifiers(dev, total_queues * 2, false);
    if (r < 0)
		printk(">>>>>%s:%d\n", __func__, __LINE__);
}

static bool virtio_net_started(VirtIONet *n, uint8_t status)
{           
    //VirtIODevice *vdev = (VirtIODevice *)n;
	//struct kvm *kvm = vdev->pci_dev.bus->kvm;
    
    return (status & VIRTIO_CONFIG_S_DRIVER_OK) &&
        (n->status & VIRTIO_NET_S_LINK_UP);
	//&& vm_running(kvm);
}

static void virtio_net_set_status(struct VirtIODevice *vdev, uint8_t status)
{   
    VirtIONet *n = (VirtIONet *)(vdev);
    int queues = n->multiqueue ? n->max_queues : 1;

    if ((virtio_net_started(n, status) && !n->my_sub_ncs[0]->link_down) ==
        !!n->vhost_started)
        return;

    if (!n->vhost_started) {
        int r;

        n->vhost_started = 1;
        r = vhost_net_start(vdev, n->my_sub_ncs, queues);
        if (r < 0) {
			printk(">>>>>%s:%d\n", __func__, __LINE__);
            n->vhost_started = 0;
        }
    } else {
        vhost_net_stop(vdev, n->my_sub_ncs, queues);
        n->vhost_started = 0;
    }
}

void create_vnet(struct kvm *kvm)
{
	struct virt_pci_bridge *bridge = kvm->vdevices.vbridge;
	struct virt_pci_bus *bus = bridge->bus;
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
    do_pci_register_device(pci_dev, bus,
                               "vhost-net", NULL, NULL,
                                PCI_VENDOR_ID_REDHAT_QUMRANET, PCI_DEVICE_ID_VIRTIO_NET,
                                PCI_CLASS_NETWORK_ETHERNET, VIRTIO_PCI_ABI_VERSION);

    realize_vdev_net_instance(vdev);

    //4. reset
    virtio_pci_reset(vdev);

	kvm->vdevices.vnet = n;
}

static void vhost_net_unrealize(VirtIODevice *vdev)
{
	int i;
	NetClientState *nc;
    VirtIONet *vn = (VirtIONet*)vdev;

	virtio_net_set_status(vdev, 0);

	//delete multiple rx/tx qeueus
	for (i = 0; i <  vn->max_queues; i++)
		virtio_net_del_queue(vn, i);

	//delete control qeueu
	virtio_del_queue(vdev, vn->max_queues * 2);

	virtio_cleanup_(vdev);

	for (i = 0; i < vn->max_queues; i++) {
		nc = vn->my_sub_ncs[i];
    	vhost_dev_cleanup_(&nc->dev);
		my_tun_chr_close(nc->tap_priv);
		kfree(nc);
	}
}

void destroy_vnet(struct kvm *kvm)
{
	PCIDevice *pci_dev;
    VirtIODevice *vdev;
    VirtIONet *vn;

	vn = kvm->vdevices.vnet;
	vdev = &vn->parent_obj;
	pci_dev = &vdev->pci_dev;

	//1. destroy pci
	//2. destroy vdev
	//3. destroy vs
    do_pci_unregister_device(pci_dev);

    vhost_net_unrealize(vdev);

	kfree(vn);
}
