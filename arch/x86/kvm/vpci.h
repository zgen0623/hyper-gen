#ifndef ARCH_X86_KVM_VPCI_H
#define ARCH_X86_KVM_VPCI_H

#include <asm/processor.h>
#include <asm/mwait.h>
#include <linux/kvm_host.h>
#include <asm/pvclock.h>
#include "kvm_cache_regs.h"
#include <uapi/linux/pci_regs.h>

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

typedef struct MSIMessage MSIMessage;

typedef struct virt_pci_bus PCIBus;
typedef struct virt_pci_device PCIDevice;

typedef uint64_t pcibus_t;

typedef struct PCIIORegion {
    pcibus_t addr; /* current PCI mapping address. -1 means not mapped */
    pcibus_t size;
    uint8_t type;
	struct kvm_io_device *dev;
} PCIIORegion;

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

#endif
