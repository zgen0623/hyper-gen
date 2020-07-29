#ifndef ARCH_X86_KVM_VPCI_H
#define ARCH_X86_KVM_VPCI_H

#include <asm/processor.h>
#include <asm/mwait.h>
#include <linux/kvm_host.h>
#include <asm/pvclock.h>
#include "kvm_cache_regs.h"
#include <uapi/linux/pci_regs.h>
#include "vpci.h"

#define ALIGN_UP(x, align_to)   (((x) + ((align_to)-1)) & ~((align_to)-1))

#define PCI_NUM_PINS 4 /* A-D */

#define PCI_ROM_SLOT 6
#define PCI_NUM_REGIONS 7

#define  PCI_HEADER_TYPE_MULTI_FUNCTION 0x80

#define PCI_CONFIG_HEADER_SIZE 0x40
#define PCI_CONFIG_SPACE_SIZE 0x100
#define PCIE_CONFIG_SPACE_SIZE  0x1000
            
#define PCI_BUILD_BDF(bus, devfn)     ((bus << 8) | (devfn))
#define PCI_BUS_MAX             256
#define PCI_DEVFN_MAX           256
#define PCI_SLOT_MAX            32
#define PCI_FUNC_MAX            8

#define PCI_BAR_UNMAPPED (~(pcibus_t)0)
# define UINT64_MAX     (__UINT64_C(18446744073709551615))
#define HWADDR_MAX UINT64_MAX

/* PCI_MSI_ADDRESS_LO */
#define PCI_MSI_ADDRESS_LO_MASK         (~0x3)

/* If we get rid of cap allocator, we won't need those. */
#define PCI_MSI_32_SIZEOF       0x0a
#define PCI_MSI_64_SIZEOF       0x0e
#define PCI_MSI_32M_SIZEOF      0x14
#define PCI_MSI_64M_SIZEOF      0x18

#define PCI_MSI_VECTORS_MAX     32

#define MSIX_CONTROL_OFFSET (PCI_MSIX_FLAGS + 1)

/* PIRQRC[A:D]: PIRQx Route Control Registers */
#define PIIX_PIRQCA 0x60
#define PIIX_PIRQCB 0x61
#define PIIX_PIRQCC 0x62
#define PIIX_PIRQCD 0x63

#define PIIX_NUM_PIC_IRQS       16      /* i8259 * 2 */
#define PIIX_NUM_PIRQS          4ULL    /* PIRQ[A-D] */

#define UINT32_MAX     (4294967295U)

/* MSI enable bit and maskall bit are in byte 1 in FLAGS register */
#define MSIX_CONTROL_OFFSET (PCI_MSIX_FLAGS + 1)
#define MSIX_ENABLE_MASK (PCI_MSIX_FLAGS_ENABLE >> 8)
#define MSIX_MASKALL_MASK (PCI_MSIX_FLAGS_MASKALL >> 8)

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

#define VIRTIO_PCI_REGION_SIZE(dev)     VIRTIO_PCI_CONFIG_OFF(msix_present(dev))

typedef struct MSIMessage MSIMessage;

typedef struct virt_pci_bus PCIBus;
typedef struct virt_pci_device PCIDevice;

typedef uint64_t pcibus_t;

typedef struct PCIIORegion {
    pcibus_t addr; /* current PCI mapping address. -1 means not mapped */
    pcibus_t size;
    uint8_t type;
	enum kvm_bus bus_idx;
	PCIDevice *pci_dev;
	struct kvm_io_device dev;
	uint32_t msix_pba_offset;
} PCIIORegion;

enum {
    QEMU_PCI_CAP_MSI = 0x1,
    QEMU_PCI_CAP_MSIX = 0x2,
    QEMU_PCI_CAP_EXPRESS = 0x4,

    /* multifunction capable device */
#define QEMU_PCI_CAP_MULTIFUNCTION_BITNR        3
    QEMU_PCI_CAP_MULTIFUNCTION = (1 << QEMU_PCI_CAP_MULTIFUNCTION_BITNR),

    /* command register SERR bit enabled */
#define QEMU_PCI_CAP_SERR_BITNR 4
    QEMU_PCI_CAP_SERR = (1 << QEMU_PCI_CAP_SERR_BITNR),
    /* Standard hot plug controller. */
#define QEMU_PCI_SHPC_BITNR 5
    QEMU_PCI_CAP_SHPC = (1 << QEMU_PCI_SHPC_BITNR),
#define QEMU_PCI_SLOTID_BITNR 6
    QEMU_PCI_CAP_SLOTID = (1 << QEMU_PCI_SLOTID_BITNR),
    /* PCI Express capability - Power Controller Present */
#define QEMU_PCIE_SLTCAP_PCP_BITNR 7
    QEMU_PCIE_SLTCAP_PCP = (1 << QEMU_PCIE_SLTCAP_PCP_BITNR),
    /* Link active status in endpoint capability is always set */
#define QEMU_PCIE_LNKSTA_DLLLA_BITNR 8
    QEMU_PCIE_LNKSTA_DLLLA = (1 << QEMU_PCIE_LNKSTA_DLLLA_BITNR),
#define QEMU_PCIE_EXTCAP_INIT_BITNR 9
    QEMU_PCIE_EXTCAP_INIT = (1 << QEMU_PCIE_EXTCAP_INIT_BITNR),
};
   

typedef void PCIConfigWriteFunc(PCIDevice *pci_dev,
                                uint32_t address, uint32_t data, int len);
typedef uint32_t PCIConfigReadFunc(PCIDevice *pci_dev,
                                   uint32_t address, int len);
typedef int (*MSIVectorUseNotifier)(PCIDevice *dev, unsigned int vector,
                                      MSIMessage msg);
typedef void (*MSIVectorReleaseNotifier)(PCIDevice *dev, unsigned int vector);
typedef void (*MSIVectorPollNotifier)(PCIDevice *dev,
                                      unsigned int vector_start,
                                      unsigned int vector_end);


struct virt_pci_device {
    uint8_t *config;
    uint8_t *cmask;
    uint8_t *wmask;
    uint8_t *w1cmask;
    uint8_t *used;
    int32_t devfn;
    char name[64];
    PCIIORegion io_regions[PCI_NUM_REGIONS];
    PCIConfigReadFunc *config_read;
    PCIConfigWriteFunc *config_write;
    uint8_t irq_state;
    uint32_t cap_present;
    uint8_t msix_cap;
    int msix_entries_nr;
    uint8_t *msix_table;
    uint8_t *msix_pba;
//    MemoryRegion msix_exclusive_bar;
 //   MemoryRegion msix_table_mmio;
  //  MemoryRegion msix_pba_mmio;
    unsigned *msix_entry_used;
    bool msix_function_masked;
    uint8_t msi_cap;
    MSIVectorUseNotifier msix_vector_use_notifier;
    MSIVectorReleaseNotifier msix_vector_release_notifier;
    MSIVectorPollNotifier msix_vector_poll_notifier;
	uint32_t msix_pba_offset;
    PCIBus *bus;
};

typedef void (*pci_set_irq_fn)(void *opaque, int irq_num, int level);
typedef int (*pci_map_irq_fn)(struct virt_pci_device *pci_dev, int irq_num);

struct virt_pci_bus {
    struct virt_pci_device *devices[PCI_SLOT_MAX * PCI_FUNC_MAX];
    
    //for  intx irq
    pci_set_irq_fn set_irq;
    pci_map_irq_fn map_irq;
    void *irq_opaque;
    int *irq_count;
	struct kvm *kvm;
};

struct virt_pci_bridge {
	struct kvm_io_device conf_dev;
	struct kvm_io_device data_dev;
	uint32_t conf_reg;
	
	struct virt_pci_bus *bus;
};


static inline int pci_is_express(const PCIDevice *d)
{           
    return d->cap_present & QEMU_PCI_CAP_EXPRESS;
}   

static inline uint32_t pci_config_size(const PCIDevice *d)
{
    return pci_is_express(d) ? PCIE_CONFIG_SPACE_SIZE : PCI_CONFIG_SPACE_SIZE;
}   

static inline uint16_t pci_get_bdf(PCIDevice *dev)
{   
    return PCI_BUILD_BDF(0, dev->devfn);
}  


struct MSIMessage {
    uint64_t address;
    uint32_t data;
};

struct piix{
    PCIDevice pci;
	uint64_t pic_levels;
};

bool msix_is_masked(PCIDevice *dev, unsigned int vector);
void msix_set_pending(PCIDevice *dev, unsigned int vector);
void create_vpci(struct kvm_vcpu *vcpu);
int pci_add_capability(PCIDevice *pdev, uint8_t cap_id,
                       uint8_t offset, uint8_t size);

static inline uint8_t
pci_get_byte(const uint8_t *config)
{
    return *(uint8_t*)config;
}

static inline void
pci_set_byte(uint8_t *config, uint8_t val)
{
    *(uint8_t*)config = val;
}   

static inline uint16_t
pci_get_word(const uint8_t *config)
{
    return *(uint16_t*)config;
}

static inline void
pci_set_word(uint8_t *config, uint16_t val)
{
    *(uint16_t*)config = val;
}   


static inline uint32_t
pci_get_long(const uint8_t *config)
{   
    return *(uint32_t*)config;
}   

static inline void 
pci_set_long(const uint8_t *config, uint32_t val)
{   
    *(uint32_t*)config = val;
}

static inline void
pci_set_quad(uint8_t *config, uint64_t val)
{   
    *(uint64_t*)config = val;
}

static inline uint64_t
pci_get_quad(const uint8_t *config)
{
    return *(uint64_t*)config;
}

static inline int pci_irq_state(PCIDevice *d, int irq_num)
{
    return (d->irq_state >> irq_num) & 0x1;
}

static inline uint8_t msi_flags_off(const PCIDevice* dev)
{
    return dev->msi_cap + PCI_MSI_FLAGS;
}

static inline bool msi_present(const PCIDevice *dev)
{
    return dev->cap_present & QEMU_PCI_CAP_MSI;
}

static inline void pci_set_irq_state(PCIDevice *d, int irq_num, int level)
{
    d->irq_state &= ~(0x1 << irq_num);
    d->irq_state |= level << irq_num;
}

static inline int ctz32(uint32_t val)
{   
    return val ? __builtin_ctz(val) : 32;
}

static inline unsigned int msi_nr_vectors(uint16_t flags)
{
    return 1U <<
        ((flags & PCI_MSI_FLAGS_QSIZE) >> ctz32(PCI_MSI_FLAGS_QSIZE));
}

static inline uint8_t msi_address_lo_off(const PCIDevice* dev)
{
    return dev->msi_cap + PCI_MSI_ADDRESS_LO;
}

static inline uint8_t msi_address_hi_off(const PCIDevice* dev)
{
    return dev->msi_cap + PCI_MSI_ADDRESS_HI;
}

static inline uint8_t msi_data_off(const PCIDevice* dev, bool msi64bit)
{
    return dev->msi_cap + (msi64bit ? PCI_MSI_DATA_64 : PCI_MSI_DATA_32);
}

static inline uint8_t msi_cap_sizeof(uint16_t flags) 
{           
    switch (flags & (PCI_MSI_FLAGS_MASKBIT | PCI_MSI_FLAGS_64BIT)) {
    case PCI_MSI_FLAGS_MASKBIT | PCI_MSI_FLAGS_64BIT:
        return PCI_MSI_64M_SIZEOF;
    case PCI_MSI_FLAGS_64BIT:
        return PCI_MSI_64_SIZEOF;
    case PCI_MSI_FLAGS_MASKBIT:
        return PCI_MSI_32M_SIZEOF;
    case 0:
        return PCI_MSI_32_SIZEOF;
    default:
        break;
    }
    return 0;
}

static inline uint32_t 
pci_long_test_and_set_mask(uint8_t *config, uint32_t mask)
{           
    uint32_t val = pci_get_long(config);
    pci_set_long(config, val | mask);
    return val & mask;
}

static inline uint32_t
pci_long_test_and_clear_mask(uint8_t *config, uint32_t mask) 
{           
    uint32_t val = pci_get_long(config);
    pci_set_long(config, val & ~mask);
    return val & mask;
}

static inline PCIDevice *pci_dev_find_by_addr(PCIBus *bus, uint32_t addr)
{       
    uint8_t devfn = addr >> 8;
    
    return bus->devices[devfn];
}

static inline int pci_irq_disabled(PCIDevice *d)
{
    return pci_get_word(d->config + PCI_COMMAND) & PCI_COMMAND_INTX_DISABLE;
}

static inline uint64_t range_get_last(uint64_t offset, uint64_t len)
{                                
    return offset + len - 1;
}   

static inline uint16_t
pci_word_test_and_set_mask(uint8_t *config, uint16_t mask)
{       
    uint16_t val = pci_get_word(config);
    pci_set_word(config, val | mask);
    return val & mask;
}  

/* Check whether a given range covers a given byte. */
static inline int range_covers_byte(uint64_t offset, uint64_t len,
                                    uint64_t byte)
{
    return offset <= byte && byte <= range_get_last(offset, len);
}
    
/* Check whether 2 given ranges overlap.
 * Undefined if ranges that wrap around 0. */
static inline int ranges_overlap(uint64_t first1, uint64_t len1,
                                 uint64_t first2, uint64_t len2)
{       
    uint64_t last1 = range_get_last(first1, len1);
    uint64_t last2 = range_get_last(first2, len2); 
        
    return !(last2 < first1 || last1 < first2);
}

void msix_clr_pending(PCIDevice *dev, int vector);
void msix_vector_unuse(PCIDevice *dev, unsigned vector);
int msix_vector_use(PCIDevice *dev, unsigned vector);

void msix_notify(PCIDevice *dev, unsigned vector);
int msix_enabled(PCIDevice *dev);
void pci_set_irq(PCIDevice *pci_dev, int level);
void msix_unuse_all_vectors(PCIDevice *dev);
int msix_present(PCIDevice *dev);
void pci_default_write_config(PCIDevice *d, uint32_t addr, uint32_t val_in, int l);
uint32_t pci_default_read_config(PCIDevice *d,
                                 uint32_t address, int len);

PCIDevice *do_pci_register_device(PCIDevice *pci_dev, PCIBus *bus,
                                        const char *name,
                                        PCIConfigWriteFunc *config_write,
                                        PCIConfigReadFunc *config_read,
                                        uint16_t vendor_id,
                                        uint16_t device_id,
                                        uint16_t class_id,
                                        uint16_t revision);

unsigned int msix_nr_vectors_allocated(const PCIDevice *dev);
MSIMessage pci_get_msi_message(PCIDevice *dev, int vector);

int msix_set_vector_notifiers(PCIDevice *dev,
                              MSIVectorUseNotifier use_notifier,
                              MSIVectorReleaseNotifier release_notifier,
                              MSIVectorPollNotifier poll_notifier);

int msix_init_exclusive_bar(PCIDevice *dev, unsigned short nentries,
                            uint8_t bar_nr);

static inline uint8_t msi_mask_off(const PCIDevice* dev, bool msi64bit)
{
    return dev->msi_cap + (msi64bit ? PCI_MSI_MASK_64 : PCI_MSI_MASK_32);
}

static inline uint8_t msi_pending_off(const PCIDevice* dev, bool msi64bit)
{
    return dev->msi_cap + (msi64bit ? PCI_MSI_PENDING_64 : PCI_MSI_PENDING_32);
}

static inline void pci_irq_assert(PCIDevice *pci_dev)
{       
    pci_set_irq(pci_dev, 1);
}       
        
static inline void pci_irq_deassert(PCIDevice *pci_dev)
{       
    pci_set_irq(pci_dev, 0);
}

void pci_register_bar(PCIDevice *pci_dev, int bar_num,
                      uint8_t type, pcibus_t size,
					struct kvm_io_device_ops *ops,
					enum kvm_bus bus_idx);
#endif
