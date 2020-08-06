#ifndef ARCH_X86_KVM_VIRTIO_H
#define ARCH_X86_KVM_VIRTIO_H

#include "vpci.h"

#define QEMU_ALIGN_DOWN(n, m) ((n) / (m) * (m)) 

/* Round number up to multiple. Safe when m is not a power of 2 (see
 * ROUND_UP for a faster version when a power of 2 is guaranteed) */
#define QEMU_ALIGN_UP(n, m) QEMU_ALIGN_DOWN((n) + (m) - 1, (m))

#define VIRTIO_PCI_VRING_ALIGN         4096
#define VIRTQUEUE_MAX_SIZE 1024

#define REGION_SIZE              0x1000
#define MODERN_BAR_COMMON_OFFSET 0x0
#define MODERN_BAR_ISR_OFFSET    0x1000
#define MODERN_BAR_DEVICE_OFFSET 0x2000
#define MODERN_BAR_NOTIFY_OFFSET 0x2000

#define VIRTIO_F_RING_PACKED        34

#define QLIST_HEAD(name, type)                                          \
struct name {                                                           \
        struct type *lh_first;  /* first element */                     \
}

#define QLIST_ENTRY(type)                                               \
struct {                                                                \
        struct type *le_next;   /* next element */                      \
        struct type **le_prev;  /* address of previous next element */  \
}

#define QLIST_FIRST(head)                ((head)->lh_first)
#define QLIST_NEXT(elm, field)           ((elm)->field.le_next)

#define QLIST_REMOVE(elm, field) do {                                   \
        if ((elm)->field.le_next != NULL)                               \
                (elm)->field.le_next->field.le_prev =                   \
                    (elm)->field.le_prev;                               \
        *(elm)->field.le_prev = (elm)->field.le_next;                   \
} while (0)
            
#define QLIST_INSERT_HEAD(head, elm, field) do {                        \
        if (((elm)->field.le_next = (head)->lh_first) != NULL)          \
                (head)->lh_first->field.le_prev = &(elm)->field.le_next;\
        (head)->lh_first = (elm);                                       \
        (elm)->field.le_prev = &(head)->lh_first;                       \
} while (0)

#define VIRTIO_PCI_CONFIG_OFF(msix_enabled) ((msix_enabled) ? 24 : 20)

#define VIRTIO_PCI_CONFIG_SIZE(dev)     VIRTIO_PCI_CONFIG_OFF(msix_enabled(dev))

/* migrate extra state */
#define VIRTIO_PCI_FLAG_MIGRATE_EXTRA (1 << VIRTIO_PCI_FLAG_MIGRATE_EXTRA_BIT)

/* Init error enabling flags */
#define VIRTIO_PCI_FLAG_INIT_DEVERR (1 << VIRTIO_PCI_FLAG_INIT_DEVERR_BIT)

/* Init Link Control register */
#define VIRTIO_PCI_FLAG_INIT_LNKCTL (1 << VIRTIO_PCI_FLAG_INIT_LNKCTL_BIT)

/* Init Power Management */
#define VIRTIO_PCI_FLAG_INIT_PM (1 << VIRTIO_PCI_FLAG_INIT_PM_BIT)
                    
/* Init Function Level Reset capability */
#define VIRTIO_PCI_FLAG_INIT_FLR (1 << VIRTIO_PCI_FLAG_INIT_FLR_BIT)

/* A guest should never accept this.  It implies negotiation is broken. */
#define VIRTIO_F_BAD_FEATURE        30

#define VIRTIO_LEGACY_FEATURES ((0x1ULL << VIRTIO_F_BAD_FEATURE) | \
                                (0x1ULL << VIRTIO_F_NOTIFY_ON_EMPTY) | \
                                (0x1ULL << VIRTIO_F_ANY_LAYOUT))

#define VHOST_INVALID_FEATURE_BIT   (0xff)

#define PCI_DEVICE_ID_VIRTIO_SCSI        0x1004

typedef struct VirtIODevice VirtIODevice;
typedef struct VirtQueue VirtQueue;

typedef struct {
    MSIMessage msg;
    int virq;
    unsigned int users;
} VirtIOIRQFD;

typedef struct VirtIOPCIRegion {
  //  MemoryRegion mr;
    uint32_t offset;
    uint32_t size;
    uint32_t type;
} VirtIOPCIRegion;

typedef uint64_t hwaddr;

typedef struct VirtQueueElement
{
    unsigned int index;
    unsigned int len;
    unsigned int ndescs;
    unsigned int out_num;
    unsigned int in_num;
    hwaddr *in_addr;
    hwaddr *out_addr;
    struct iovec *in_sg;
    struct iovec *out_sg;
} VirtQueueElement;

typedef void (*VirtIOHandleOutput)(VirtIODevice *, VirtQueue *);

typedef struct VirtIOPCIQueue {
  uint16_t num;
  bool enabled;
  uint32_t desc[2];
  uint32_t avail[2];
  uint32_t used[2];
} VirtIOPCIQueue;
    
typedef struct VRing
{
    unsigned int num;
    unsigned int num_default;
    unsigned int align;
    hwaddr desc;
    hwaddr avail;
    hwaddr used;
   // VRingMemoryRegionCaches *caches;
} VRing;


struct VirtQueue {
    VRing vring;
    VirtQueueElement *used_elems;
	uint64_t desc_hva;
	uint64_t avail_hva;
	uint64_t used_hva;

    /* Next head to pop */
    uint16_t last_avail_idx;
    bool last_avail_wrap_counter;

    /* Last avail_idx read from VQ. */
    uint16_t shadow_avail_idx;
    bool shadow_avail_wrap_counter;

    uint16_t used_idx;
    bool used_wrap_counter;

    /* Last used index value we have signalled on */
    uint16_t signalled_used;

    /* Last used index value we have signalled on */
    bool signalled_used_valid;

    /* Notification enabled? */
    bool notification;

    uint16_t queue_index;

    unsigned int inuse;

    uint16_t vector;
    VirtIOHandleOutput handle_output;
    VirtIODevice *vdev;
    uint64_t evt_id;
    bool host_notifier_enabled;
	VirtIOPCIQueue vq_config_buf;

	wait_queue_head_t *wq_head;
    QLIST_ENTRY(VirtQueue) node;
};

struct VirtIODevice {
    PCIDevice pci_dev;
    uint8_t status;
	char *name;
    atomic_t isr_val;
    uint16_t queue_sel;

    uint64_t guest_features;
    uint64_t host_features;
    uint64_t backend_features;
    uint64_t legacy_features;

    size_t config_len;
    void *config;
    uint16_t config_vector;
    uint32_t generation;
    VirtQueue *vq;
    uint16_t device_id;
    bool broken; /* device in invalid state, needs reset */
    bool start_on_kick; /* when virtio 1.0 feature has not been negotiated */
	QLIST_HEAD(, VirtQueue) *vector_queues;

    uint32_t pci_guest_features[2];
    uint32_t nvectors;
    uint32_t dfselect;
    uint32_t gfselect;
    int config_cap;
    uint32_t flags;
    VirtIOIRQFD *vector_irqfd;
    int nvqs_with_notifiers;
    uint32_t legacy_io_bar_idx;
    uint32_t msix_bar_idx;
    uint32_t modern_mem_bar_idx;
    union {
        struct {
            VirtIOPCIRegion common;
            VirtIOPCIRegion isr;
            VirtIOPCIRegion device;
            VirtIOPCIRegion notify;
        };
        VirtIOPCIRegion regs[5];
    };

    uint64_t (*get_features)(VirtIODevice *vdev,
                             uint64_t requested_features);
    uint64_t (*bad_features)(VirtIODevice *vdev);
    void (*set_features)(VirtIODevice *vdev, uint64_t val);
    int (*validate_features)(VirtIODevice *vdev);
    void (*get_config)(VirtIODevice *vdev, uint8_t *config);
    void (*set_config)(VirtIODevice *vdev, const uint8_t *config);
    void (*reset)(VirtIODevice *vdev);
    void (*set_status)(VirtIODevice *vdev, uint8_t val);
    bool (*guest_notifier_pending)(VirtIODevice *vdev, int n);
    void (*guest_notifier_mask)(VirtIODevice *vdev, int n, bool mask);
};


/* All region addresses and sizes must be 4K aligned. */
#define VHOST_PAGE_SIZE 0x1000
    
struct vhost_dev;

struct vhost_virtqueue {
    int kick;
    int call;
    void *desc;
    void *avail;
    void *used;
    int num;
    unsigned long long desc_phys;
    unsigned desc_size;
    unsigned long long avail_phys;
    unsigned avail_size;
    unsigned long long used_phys;
    unsigned used_size;
    struct vhost_dev *dev;
};


struct vhost_dev {
    VirtIODevice *vdev;
    struct vhost_memory *mem;
    struct vhost_virtqueue *vqs;
    int nvqs;
    int vq_index;
    uint64_t features;
    uint64_t acked_features;
    uint64_t backend_features;
    uint64_t protocol_features;
    uint64_t max_queues;
    bool started;
    void *opaque;
    long (*ioctl_hook)(void *, unsigned int,
					unsigned long);
	int (*release_hook)(void *);
	void (*clear_vq_signaled)(void *opaque, int vq_idx);
};


typedef struct VRingPackedDescEvent {
    uint16_t off_wrap;
    uint16_t flags;
} VRingPackedDescEvent ;

typedef struct VRingDesc
{   
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
} VRingDesc;

typedef struct VRingPackedDesc {
    uint64_t addr;
    uint32_t len;
    uint16_t id;
    uint16_t flags;
} VRingPackedDesc;

typedef struct VRingAvail
{   
    uint16_t flags;
    uint16_t idx;
    uint16_t ring[0];
} VRingAvail;


typedef struct VRingUsedElem
{
    uint32_t id;
    uint32_t len;
} VRingUsedElem;


typedef struct VRingUsed
{
    uint16_t flags;
    uint16_t idx;
    VRingUsedElem ring[0];
} VRingUsed;

struct evt_node {
	struct list_head  list;
	VirtQueue *vq;
};

typedef struct VirtIOFeature {
    uint64_t flags;
    size_t end;
} VirtIOFeature;


uint64_t vhost_get_features(struct vhost_dev *hdev, const int *feature_bits,
                            uint64_t features);


bool vhost_virtqueue_pending(struct vhost_dev *hdev, int n);

enum {
    VIRTIO_PCI_FLAG_BUS_MASTER_BUG_MIGRATION_BIT,
    VIRTIO_PCI_FLAG_USE_IOEVENTFD_BIT,
    VIRTIO_PCI_FLAG_MIGRATE_EXTRA_BIT,
    VIRTIO_PCI_FLAG_MODERN_PIO_NOTIFY_BIT,
    VIRTIO_PCI_FLAG_DISABLE_PCIE_BIT,
    VIRTIO_PCI_FLAG_PAGE_PER_VQ_BIT,
    VIRTIO_PCI_FLAG_ATS_BIT,
    VIRTIO_PCI_FLAG_INIT_DEVERR_BIT,
    VIRTIO_PCI_FLAG_INIT_LNKCTL_BIT,
    VIRTIO_PCI_FLAG_INIT_PM_BIT,
    VIRTIO_PCI_FLAG_INIT_FLR_BIT,
};

/* page per vq flag to be used by split drivers within guests */
#define VIRTIO_PCI_FLAG_PAGE_PER_VQ \
    (1 << VIRTIO_PCI_FLAG_PAGE_PER_VQ_BIT)

#define QEMU_VIRTIO_PCI_QUEUE_MEM_MULT 0x1000
#define VIRTIO_QUEUE_MAX 1024
#define VIRTIO_NO_VECTOR 0xffff


static inline int virtio_pci_queue_mem_mult(struct VirtIODevice *vdev)
{
    return (vdev->flags & VIRTIO_PCI_FLAG_PAGE_PER_VQ) ?
        QEMU_VIRTIO_PCI_QUEUE_MEM_MULT : 4;
}

void virtio_device_realize(VirtIODevice *vdev);

static inline bool virtio_pci_modern(void)
{       
    return true;                
}   
    
static inline bool virtio_pci_legacy(void)
{   
    return true;
}

static inline void virtio_add_feature(uint64_t *features, unsigned int fbit)
{       
    *features |= (1ULL << fbit);
}   
    
static inline void virtio_clear_feature(uint64_t *features, unsigned int fbit)
{
    *features &= ~(1ULL << fbit);
}   

static inline bool virtio_has_feature_(uint64_t features, unsigned int fbit)
{
    return !!(features & (1ULL << fbit));
}

static inline bool virtio_vdev_has_feature(VirtIODevice *vdev,
                                           unsigned int fbit)
{
    return virtio_has_feature_(vdev->guest_features, fbit);
}

/**
 * clz64 - count leading zeros in a 64-bit value.
 * @val: The value to search
 *
 * Returns 64 if the value is zero.  Note that the GCC builtin is
 * undefined if the value is zero.
 */
static inline int clz64(uint64_t val)
{
    return val ? __builtin_clzll(val) : 64;
}

/*  
 * Return @value rounded up to the nearest power of two modulo 2^64.
 * This is *zero* for @value > 2^63, so be careful.
 */ 
static inline uint64_t pow2ceil(uint64_t value)
{
    int n = clz64(value - 1);
    
    if (!n)
        return !value;

    return 0x8000000000000000ull >> (n - 1);
}

void virtio_init(VirtIODevice *vdev, const char *name,
                 uint16_t device_id, size_t config_size);

VirtQueue *virtio_add_queue(VirtIODevice *vdev, int queue_size,
                            VirtIOHandleOutput handle_output);

void virtio_del_queue(VirtIODevice *vdev, int n);
int vhost_dev_init_(struct vhost_dev *hdev, void *opaque,
                   uint32_t busyloop_timeout);
int vhost_dev_enable_notifiers(struct vhost_dev *hdev, VirtIODevice *vdev);

int virtio_pci_set_guest_notifiers(VirtIODevice *vdev, int nvqs, bool assign);
int vhost_dev_start(struct vhost_dev *hdev, VirtIODevice *vdev);
void vhost_virtqueue_mask(struct vhost_dev *hdev, VirtIODevice *vdev, int n, bool mask);
void vhost_dev_disable_notifiers(struct vhost_dev *hdev, VirtIODevice *vdev);
void vhost_dev_stop_(struct vhost_dev *hdev, VirtIODevice *vdev);
void virtio_pci_reset(VirtIODevice *vdev);
struct kvm *find_kvm_by_id(uint64_t kvm_id);
int virtio_set_status(VirtIODevice *vdev, uint8_t val);

void virtio_cleanup_(VirtIODevice *vdev);
void vhost_ack_features(struct vhost_dev *hdev, const int *feature_bits,
                        uint64_t features);
int virtio_get_num_queues(VirtIODevice *vdev);

bool virtio_queue_enabled(VirtIODevice *vdev, int n);
size_t virtio_feature_get_config_size(VirtIOFeature *feature_sizes,
                                      uint64_t host_features);
void vhost_dev_cleanup_(struct vhost_dev *hdev);
void virtio_notify_vector(VirtIODevice *vdev, uint16_t vector);
#endif
