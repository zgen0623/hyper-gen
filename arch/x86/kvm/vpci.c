#include <linux/slab.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/mm.h>
#include <linux/vmacache.h>
#include <linux/stat.h>
#include <linux/fcntl.h>
#include <linux/swap.h>
#include <linux/string.h>
#include <asm/msr.h>
#include <asm/desc.h>
#include <linux/kernel_stat.h>
#include <asm/div64.h>
#include <asm/irq_remapping.h>
#include <asm/processor.h>
#include <asm/user.h>
#include <asm/fpu/xstate.h>
#include <asm/cpu.h>
#include <asm/processor.h>
#include <asm/processor.h>
#include <asm/mwait.h>
#include <linux/kvm_host.h>
#include <asm/pvclock.h>
#include <linux/pci_regs.h>
#include <linux/pci.h>
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

void vpci_bar_update(enum kvm_bus bus_idx,
			       struct kvm_io_device *dev,
					enum kvm_pci_bar_update_type type,
					uint64_t addr, uint64_t size);

void handle_vpci_bar_update(struct kvm_vcpu *vcpu);

static void msix_handle_mask_update(PCIDevice *dev, int vector, bool was_masked);
static int pci_bar(PCIDevice *d, int reg);
static void pci_irq_handler(void *opaque, int irq_num, int level);

static int vpci_intx(PCIDevice *pci_dev)
{
    return pci_get_byte(pci_dev->config + PCI_INTERRUPT_PIN) - 1;
}

unsigned int msix_nr_vectors_allocated(const PCIDevice *dev)
{           
    return dev->msix_entries_nr;
}   

void pci_set_irq(PCIDevice *pci_dev, int level)
{
    int intx = vpci_intx(pci_dev);
    pci_irq_handler(pci_dev, intx, level);
}

static void msix_free_irq_entries(PCIDevice *dev)
{
    int vector;

    for (vector = 0; vector < dev->msix_entries_nr; ++vector) {
        dev->msix_entry_used[vector] = 0;
        msix_clr_pending(dev, vector);
    }
}

static int msix_set_notifier_for_vector(PCIDevice *dev, unsigned int vector)
{
    MSIMessage msg;

    if (msix_is_masked(dev, vector))
        return 0;

    msg = msix_get_message(dev, vector);

    return dev->msix_vector_use_notifier(dev, vector, msg);
}

static void msix_unset_notifier_for_vector(PCIDevice *dev, unsigned int vector)
{
    if (msix_is_masked(dev, vector))
        return;

    dev->msix_vector_release_notifier(dev, vector);
}


int msix_set_vector_notifiers(PCIDevice *dev,
                              MSIVectorUseNotifier use_notifier,
                              MSIVectorReleaseNotifier release_notifier,
                              MSIVectorPollNotifier poll_notifier)
{           
    int vector, ret;
    
    dev->msix_vector_use_notifier = use_notifier;
    dev->msix_vector_release_notifier = release_notifier;
    dev->msix_vector_poll_notifier = poll_notifier;
        
    if ((dev->config[dev->msix_cap + MSIX_CONTROL_OFFSET] &
        (MSIX_ENABLE_MASK | MSIX_MASKALL_MASK)) == MSIX_ENABLE_MASK) {
        for (vector = 0; vector < dev->msix_entries_nr; vector++) {
            ret = msix_set_notifier_for_vector(dev, vector);
            if (ret < 0)
                goto undo;
        }
    }

    if (dev->msix_vector_poll_notifier)
        dev->msix_vector_poll_notifier(dev, 0, dev->msix_entries_nr);

    return 0;

undo:
    while (--vector >= 0)
        msix_unset_notifier_for_vector(dev, vector);

    dev->msix_vector_use_notifier = NULL;
    dev->msix_vector_release_notifier = NULL;
    return ret;
}



MSIMessage pci_get_msi_message(PCIDevice *dev, int vector)
{   
    MSIMessage msg;

    if (msix_enabled(dev)) {
        msg = msix_get_message(dev, vector);
    } else if (msi_enabled(dev)) {
        msg = msi_get_message(dev, vector);
    }

    return msg;
} 


void msix_unuse_all_vectors(PCIDevice *dev)
{   
    if (!msix_present(dev))
        return;

    msix_free_irq_entries(dev);
}   
   

void msix_vector_unuse(PCIDevice *dev, unsigned vector)
{   
    if (vector >= dev->msix_entries_nr || !dev->msix_entry_used[vector])
        return;

    if (--dev->msix_entry_used[vector])
        return;

    msix_clr_pending(dev, vector);
}  

int msix_vector_use(PCIDevice *dev, unsigned vector) 
{           
    if (vector >= dev->msix_entries_nr)
        return -EINVAL;         
        
    dev->msix_entry_used[vector]++;

    return 0;
} 


static void msix_mask_all(PCIDevice *dev, unsigned nentries)
{
    int vector;

    for (vector = 0; vector < nentries; ++vector) {
        unsigned offset =
            vector * PCI_MSIX_ENTRY_SIZE + PCI_MSIX_ENTRY_VECTOR_CTRL;
        bool was_masked = msix_is_masked(dev, vector);

        dev->msix_table[offset] |= PCI_MSIX_ENTRY_CTRL_MASKBIT;
        msix_handle_mask_update(dev, vector, was_masked);
    }
}

static int msix_init(PCIDevice *dev, unsigned short nentries,
              uint8_t table_bar_nr,
              unsigned table_offset, 
              uint8_t pba_bar_nr, unsigned pba_offset, uint8_t cap_pos, unsigned bar_size)
{
    int cap;
    unsigned table_size, pba_size;
    uint8_t *config;

    if (nentries < 1 || nentries > PCI_MSIX_FLAGS_QSIZE + 1) {
        printk(">>>>The number of MSI-X vectors is invalid\n");
        return -EINVAL;
    }

    table_size = nentries * PCI_MSIX_ENTRY_SIZE;
    pba_size = ALIGN_UP(nentries, 64) / 8;

    /* Sanity test: table & pba don't overlap, fit within BARs, min aligned */
    if ((table_bar_nr == pba_bar_nr &&
         ranges_overlap(table_offset, table_size, pba_offset, pba_size)) ||
        table_offset + table_size > bar_size ||
        pba_offset + pba_size > bar_size ||
        (table_offset | pba_offset) & PCI_MSIX_FLAGS_BIRMASK) {
        printk(">>>>>>error: table & pba overlap, or they don't fit in BARs,"
                   " or don't align\n");
        return -EINVAL;
    }

    cap = pci_add_capability(dev, PCI_CAP_ID_MSIX,
                              cap_pos, MSIX_CAP_LENGTH);
    if (cap < 0) {
        return cap;
    }

    dev->msix_cap = cap;
    dev->cap_present |= QEMU_PCI_CAP_MSIX;
    config = dev->config + cap;

    pci_set_word(config + PCI_MSIX_FLAGS, nentries - 1);
    dev->msix_entries_nr = nentries;
    dev->msix_function_masked = true;

    pci_set_long(config + PCI_MSIX_TABLE, table_offset | table_bar_nr);
    pci_set_long(config + PCI_MSIX_PBA, pba_offset | pba_bar_nr);

    /* Make flags bit writable. */
    dev->wmask[cap + MSIX_CONTROL_OFFSET] |= MSIX_ENABLE_MASK |
                                             MSIX_MASKALL_MASK;
    dev->msix_table = kzalloc(table_size, GFP_KERNEL);
    dev->msix_pba = kzalloc(pba_size, GFP_KERNEL);
    dev->msix_entry_used = kzalloc(nentries * sizeof *dev->msix_entry_used, GFP_KERNEL);

    msix_mask_all(dev, nentries);

    return 0;
}

void pci_register_bar(PCIDevice *pci_dev, int bar_num,
                      uint8_t type, pcibus_t size,
					struct kvm_io_device_ops *ops,
					enum kvm_bus bus_idx)
{
    PCIIORegion *r;
    uint32_t addr; /* offset in pci config space */
    uint64_t wmask;

    if (size & (size-1)) {
        printk(">>>>ERROR: PCI region size must be pow2 "
                    "type=0x%x, size=0x%llx\n", type, size);
		return;
    }

    r = &pci_dev->io_regions[bar_num];

    r->addr = PCI_BAR_UNMAPPED;
    r->size = size;
    r->type = type;
	r->bus_idx = bus_idx;
	r->pci_dev = pci_dev;
	kvm_iodevice_init(&r->dev, ops);

    wmask = ~(size - 1);
    if (bar_num == PCI_ROM_SLOT) {
        /* ROM enable bit is writable */
        wmask |= PCI_ROM_ADDRESS_ENABLE;
    }

    addr = pci_bar(pci_dev, bar_num);
    pci_set_long(pci_dev->config + addr, type);

    if (!(r->type & PCI_BASE_ADDRESS_SPACE_IO) &&
        r->type & PCI_BASE_ADDRESS_MEM_TYPE_64) {
        pci_set_quad(pci_dev->wmask + addr, wmask);
        pci_set_quad(pci_dev->cmask + addr, ~0ULL);
    } else {
        pci_set_long(pci_dev->wmask + addr, wmask & 0xffffffff);
        pci_set_long(pci_dev->cmask + addr, 0xffffffff);
    }
}


static uint32_t msix_table_mmio_read(PCIDevice *dev, hwaddr offset,
                                     unsigned size)
{
    return pci_get_long(dev->msix_table + offset);
}

static uint32_t msix_pba_mmio_read(PCIDevice *dev, hwaddr offset,
                                   unsigned size)
{
    if (dev->msix_vector_poll_notifier) {
        unsigned vector_start = offset * 8;
        unsigned vector_end = MIN(offset + size * 8, dev->msix_entries_nr);
        dev->msix_vector_poll_notifier(dev, vector_start, vector_end);
    }

    return pci_get_long(dev->msix_pba + offset);
}

static int msix_bar_read(struct kvm_vcpu *vcpu, struct kvm_io_device *dev,
			      gpa_t addr, int len, void *val)
{
	PCIIORegion *r = container_of(dev, PCIIORegion, dev);
	PCIDevice *pci_dev = r->pci_dev;
	uint32_t msix_pba_offset = pci_dev->msix_pba_offset;
	uint32_t offset = addr - r->addr;	

	if (offset < msix_pba_offset)
		*(uint32_t*)val = msix_table_mmio_read(pci_dev, offset, len);
	else
		*(uint32_t*)val = msix_pba_mmio_read(pci_dev, offset - msix_pba_offset, len);

	return 0;
}

static void msix_table_mmio_write(PCIDevice *dev, hwaddr offset,
                                  uint32_t val, unsigned size)
{
    int vector = offset / PCI_MSIX_ENTRY_SIZE;
    bool was_masked;

    was_masked = msix_is_masked(dev, vector);
    pci_set_long(dev->msix_table + offset, val);
    msix_handle_mask_update(dev, vector, was_masked);
}


static int msix_bar_write(struct kvm_vcpu *vcpu, struct kvm_io_device *dev,
			       gpa_t addr, int len, const void *val)
{
	PCIIORegion *r = container_of(dev, PCIIORegion, dev);
	PCIDevice *pci_dev = r->pci_dev;
	uint32_t msix_pba_offset = pci_dev->msix_pba_offset;
	uint32_t offset = addr - r->addr;	

	if (offset < msix_pba_offset)
		msix_table_mmio_write(pci_dev, offset,
                                  *(uint32_t*)val, len);

	return 0;
}


static struct kvm_io_device_ops msix_bar_ops = {
	.read     = msix_bar_read,
	.write    = msix_bar_write,
};


int msix_init_exclusive_bar(PCIDevice *dev, unsigned short nentries,
                            uint8_t bar_nr)
{
    int ret;
    uint32_t bar_size = 4096;
    uint32_t bar_pba_offset = bar_size / 2;
    uint32_t bar_pba_size = ALIGN_UP(nentries, 64) / 8;

    if (nentries * PCI_MSIX_ENTRY_SIZE > bar_pba_offset)
        bar_pba_offset = nentries * PCI_MSIX_ENTRY_SIZE;

    if (bar_pba_offset + bar_pba_size > 4096) {
        bar_size = bar_pba_offset + bar_pba_size;
	}

	dev->msix_pba_offset = bar_pba_offset;

    bar_size = pow2ceil(bar_size);

    ret = msix_init(dev, nentries, bar_nr,
                    0, 
                    bar_nr, bar_pba_offset,
                    0, bar_size);
    if (ret)
        return ret;

    pci_register_bar(dev, bar_nr, PCI_BASE_ADDRESS_SPACE_MEMORY,
                     bar_size, &msix_bar_ops, KVM_MMIO_BUS);

    return 0;
}




static uint8_t pci_find_space(PCIDevice *pdev, uint8_t size)
{
    int offset = PCI_CONFIG_HEADER_SIZE;
    int i;
    for (i = PCI_CONFIG_HEADER_SIZE; i < PCI_CONFIG_SPACE_SIZE; ++i) {
        if (pdev->used[i])
            offset = i + 1;
        else if (i - offset + 1 == size)
            return offset;
    }
    return 0;
}

static uint8_t pci_find_capability_at_offset(PCIDevice *pdev, uint8_t offset)
{
    uint8_t next, prev, found = 0;

    if (!(pdev->used[offset])) {
        return 0;
    }

    for (prev = PCI_CAPABILITY_LIST; (next = pdev->config[prev]);
         prev = next + PCI_CAP_LIST_NEXT) {
        if (next <= offset && next > found) {
            found = next;
        }
    }

    return found;
}


int pci_add_capability(PCIDevice *pdev, uint8_t cap_id,
                       uint8_t offset, uint8_t size)
{
    uint8_t *config;
    int i, overlapping_cap;

    if (!offset) {
        offset = pci_find_space(pdev, size);
		if (!offset) {
			printk(">>>>error: %s:%d\n",__func__, __LINE__);
			return -1;
		}
    } else {
        for (i = offset; i < offset + size; i++) {
            overlapping_cap = pci_find_capability_at_offset(pdev, i);
            if (overlapping_cap) {
                printk("%02x:%02x.%x "
                           "Attempt to add PCI capability %x at offset "
                           "%x overlaps existing capability %x at offset %x\n",
                           0, PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn),
                           cap_id, offset, overlapping_cap, i);
                return -EINVAL;
            }
        }
    }

    config = pdev->config + offset;
    config[PCI_CAP_LIST_ID] = cap_id;
    config[PCI_CAP_LIST_NEXT] = pdev->config[PCI_CAPABILITY_LIST];
    pdev->config[PCI_CAPABILITY_LIST] = offset;
    pdev->config[PCI_STATUS] |= PCI_STATUS_CAP_LIST;
    memset(pdev->used + offset, 0xFF, ALIGN_UP(size, 4));
    /* Make capability read-only by default */
    memset(pdev->wmask + offset, 0, size);
    /* Check capability by default */
    memset(pdev->cmask + offset, 0xFF, size);

    return offset;
}


static bool pci_bus_devfn_available(PCIBus *bus, int devfn)
{   
    return !(bus->devices[devfn]);
}

static void pci_config_alloc(PCIDevice *pci_dev)
{
    int config_size = pci_config_size(pci_dev);

    pci_dev->config = kzalloc(config_size , GFP_KERNEL);
    pci_dev->cmask = kzalloc(config_size , GFP_KERNEL);
    pci_dev->wmask = kzalloc(config_size , GFP_KERNEL);
    pci_dev->w1cmask = kzalloc(config_size , GFP_KERNEL);
    pci_dev->used = kzalloc(config_size , GFP_KERNEL);
} 

static void pci_init_cmask(PCIDevice *dev)
{
    pci_set_word(dev->cmask + PCI_VENDOR_ID, 0xffff);
    pci_set_word(dev->cmask + PCI_DEVICE_ID, 0xffff);
    dev->cmask[PCI_STATUS] = PCI_STATUS_CAP_LIST;
    dev->cmask[PCI_REVISION_ID] = 0xff;
    dev->cmask[PCI_CLASS_PROG] = 0xff;
    pci_set_word(dev->cmask + PCI_CLASS_DEVICE, 0xffff);
    dev->cmask[PCI_HEADER_TYPE] = 0xff;
    dev->cmask[PCI_CAPABILITY_LIST] = 0xff;
}

static void pci_init_wmask(PCIDevice *dev)
{
    int config_size = pci_config_size(dev);

    dev->wmask[PCI_CACHE_LINE_SIZE] = 0xff;
    dev->wmask[PCI_INTERRUPT_LINE] = 0xff;
    pci_set_word(dev->wmask + PCI_COMMAND,
                 PCI_COMMAND_IO | PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER |
                 PCI_COMMAND_INTX_DISABLE);
    if (dev->cap_present & QEMU_PCI_CAP_SERR) {
        pci_word_test_and_set_mask(dev->wmask + PCI_COMMAND, PCI_COMMAND_SERR);
    }

    memset(dev->wmask + PCI_CONFIG_HEADER_SIZE, 0xff,
           config_size - PCI_CONFIG_HEADER_SIZE);
}

static void pci_init_w1cmask(PCIDevice *dev)
{
    /*
     * Note: It's okay to set w1cmask even for readonly bits as
     * long as their value is hardwired to 0.
     */
    pci_set_word(dev->w1cmask + PCI_STATUS,
                 PCI_STATUS_PARITY | PCI_STATUS_SIG_TARGET_ABORT |
                 PCI_STATUS_REC_TARGET_ABORT | PCI_STATUS_REC_MASTER_ABORT |
                 PCI_STATUS_SIG_SYSTEM_ERROR | PCI_STATUS_DETECTED_PARITY);
}

static int pci_init_multifunction(PCIBus *bus, PCIDevice *dev)
{
    uint8_t slot = PCI_SLOT(dev->devfn);
    uint8_t func;

    if (dev->cap_present & QEMU_PCI_CAP_MULTIFUNCTION) {
        dev->config[PCI_HEADER_TYPE] |= PCI_HEADER_TYPE_MULTI_FUNCTION;
    }
    
    if (PCI_FUNC(dev->devfn)) {
        PCIDevice *f0 = bus->devices[PCI_DEVFN(slot, 0)];
        if (f0 && !(f0->cap_present & QEMU_PCI_CAP_MULTIFUNCTION)) {
            /* function 0 should set multifunction bit */
            printk("PCI: single function device can't be populated "
                       "in function %x.%x", slot, PCI_FUNC(dev->devfn));
            return -1;
        }
        return 0;
    }

    if (dev->cap_present & QEMU_PCI_CAP_MULTIFUNCTION) {
        return 0;
    }

    /* function 0 indicates single function, so function > 0 must be NULL */
    for (func = 1; func < PCI_FUNC_MAX; ++func) {
        if (bus->devices[PCI_DEVFN(slot, func)]) {
            printk("PCI: %x.0 indicates single function, "
                       "but %x.%x is already populated.",
                       slot, slot, func);
            return -1;
        }
    }

	return 0;
}

static void pci_config_free_(PCIDevice *pci_dev)
{
    kfree(pci_dev->config);
    kfree(pci_dev->cmask);
    kfree(pci_dev->wmask);
    kfree(pci_dev->w1cmask);
    kfree(pci_dev->used);
}

void do_pci_unregister_device(PCIDevice *pci_dev)
{
	int i;
    PCIIORegion *r;
	struct kvm *kvm = pci_dev->bus->kvm;

    for(i = 0; i < PCI_NUM_REGIONS; i++) {
        r = &pci_dev->io_regions[i];
        /* this region isn't registered */
        if (!r->size)
            continue;

		mutex_lock(&kvm->slots_lock);
		kvm_io_bus_unregister_dev(kvm, r->bus_idx, &r->dev);
		mutex_unlock(&kvm->slots_lock);
    }

    kfree(pci_dev->msix_table);
    kfree(pci_dev->msix_pba);
    kfree(pci_dev->msix_entry_used);

    pci_dev->bus->devices[pci_dev->devfn] = NULL;
    pci_config_free_(pci_dev);
}

uint32_t pci_default_read_config(PCIDevice *d,
                                 uint32_t address, int len)
{
    uint32_t val = 0;

    memcpy(&val, d->config + address, len);
    return le32_to_cpu(val);
}

static int pci_bar(PCIDevice *d, int reg)
{
    uint8_t type;

    if (reg != PCI_ROM_SLOT)
        return PCI_BASE_ADDRESS_0 + reg * 4;

    type = d->config[PCI_HEADER_TYPE] & ~PCI_HEADER_TYPE_MULTI_FUNCTION;

    return type == PCI_HEADER_TYPE_BRIDGE ? PCI_ROM_ADDRESS1 : PCI_ROM_ADDRESS;
}

static pcibus_t pci_bar_address(PCIDevice *d,
                                int reg, uint8_t type, pcibus_t size)
{
    pcibus_t new_addr, last_addr;
    int bar = pci_bar(d, reg);
    uint16_t cmd = pci_get_word(d->config + PCI_COMMAND);

    if (type & PCI_BASE_ADDRESS_SPACE_IO) {
        if (!(cmd & PCI_COMMAND_IO)) {
            return PCI_BAR_UNMAPPED;
        }

        new_addr = pci_get_long(d->config + bar) & ~(size - 1);
        last_addr = new_addr + size - 1;
        /* Check if 32 bit BAR wraps around explicitly.
         * TODO: make priorities correct and remove this work around.
         */
        if (last_addr <= new_addr || last_addr >= UINT32_MAX ||
            (new_addr == 0)) {
            return PCI_BAR_UNMAPPED;
        }
        return new_addr;
    }

    if (!(cmd & PCI_COMMAND_MEMORY)) {
        return PCI_BAR_UNMAPPED;
    }

    if (type & PCI_BASE_ADDRESS_MEM_TYPE_64) {
        new_addr = pci_get_quad(d->config + bar);
    } else {
        new_addr = pci_get_long(d->config + bar);
    }

    /* the ROM slot has a specific enable bit */
    if (reg == PCI_ROM_SLOT && !(new_addr & PCI_ROM_ADDRESS_ENABLE)) {
        return PCI_BAR_UNMAPPED;
    }

    new_addr &= ~(size - 1);
    last_addr = new_addr + size - 1;
    if (last_addr <= new_addr || last_addr == PCI_BAR_UNMAPPED ||
        (new_addr == 0)) {
        return PCI_BAR_UNMAPPED;
    }

    if  (!(type & PCI_BASE_ADDRESS_MEM_TYPE_64) && last_addr >= UINT32_MAX) {
        return PCI_BAR_UNMAPPED;
    }

    if (last_addr >= HWADDR_MAX) {
        return PCI_BAR_UNMAPPED;
    }

    return new_addr;
}

static void pci_update_mappings(PCIDevice *d)
{
	int ret;
    PCIIORegion *r;
    int i;
    pcibus_t new_addr;

    for(i = 0; i < PCI_NUM_REGIONS; i++) {
        r = &d->io_regions[i];
        /* this region isn't registered */
        if (!r->size)
            continue;

        new_addr = pci_bar_address(d, i, r->type, r->size);

        /* This bar isn't changed */
        if (new_addr == r->addr)
            continue;

        /* now do the real mapping */
        if (r->addr != PCI_BAR_UNMAPPED) {
			vpci_bar_update(r->bus_idx, &r->dev, PCI_BAR_UNREGISTER, 0, 0);
			if (ret < 0)
				printk(">>>>error %s:%d\n",__func__, __LINE__);
        }
        
        r->addr = new_addr;

        if (r->addr != PCI_BAR_UNMAPPED)
			vpci_bar_update(r->bus_idx, &r->dev, PCI_BAR_REGISTER, r->addr, r->size);
    }   
} 



static void pci_change_irq_level(PCIDevice *pci_dev, int irq_num, int change)
{
    PCIBus *bus;
    bus = pci_dev->bus;
    irq_num = bus->map_irq(pci_dev, irq_num);

    bus->irq_count[irq_num] += change;
    bus->set_irq(bus->irq_opaque, irq_num, bus->irq_count[irq_num] != 0);
}

static void pci_update_irq_disabled(PCIDevice *d, int was_irq_disabled)
{
    int i, disabled = pci_irq_disabled(d);
    if (disabled == was_irq_disabled)
        return;

    for (i = 0; i < PCI_NUM_PINS; ++i) {
        int state = pci_irq_state(d, i);
        pci_change_irq_level(d, i, disabled ? -state : state);
    }
}


static void pci_update_irq_status(PCIDevice *dev)
{
    if (dev->irq_state) {
        dev->config[PCI_STATUS] |= PCI_STATUS_INTERRUPT;
    } else {
        dev->config[PCI_STATUS] &= ~PCI_STATUS_INTERRUPT;
    }
}

static void pci_irq_handler(void *opaque, int irq_num, int level)
{
    PCIDevice *pci_dev = opaque;
    int change;

    change = level - pci_irq_state(pci_dev, irq_num);
    if (!change)
        return;

    pci_set_irq_state(pci_dev, irq_num, level);
    pci_update_irq_status(pci_dev);
    if (pci_irq_disabled(pci_dev))
        return;

    pci_change_irq_level(pci_dev, irq_num, change);
}

void pci_device_deassert_intx(PCIDevice *dev)
{       
    int i;
    for (i = 0; i < PCI_NUM_PINS; ++i) {
        pci_irq_handler(dev, i, 0);
    }
} 

bool msi_is_masked(const PCIDevice *dev, unsigned int vector)
{
    uint16_t flags = pci_get_word(dev->config + msi_flags_off(dev));
    uint32_t mask;

    if (!(flags & PCI_MSI_FLAGS_MASKBIT)) {
        return false;
    }

    mask = pci_get_long(dev->config +
                        msi_mask_off(dev, flags & PCI_MSI_FLAGS_64BIT));
    return mask & (1U << vector);
}


MSIMessage msi_get_message(PCIDevice *dev, unsigned int vector)
{
    uint16_t flags = pci_get_word(dev->config + msi_flags_off(dev));
    bool msi64bit = flags & PCI_MSI_FLAGS_64BIT;
    unsigned int nr_vectors = msi_nr_vectors(flags);
    MSIMessage msg;

    if (msi64bit) {
        msg.address = pci_get_quad(dev->config + msi_address_lo_off(dev));
    } else {
        msg.address = pci_get_long(dev->config + msi_address_lo_off(dev));
    }

    /* upper bit 31:16 is zero */
    msg.data = pci_get_word(dev->config + msi_data_off(dev, msi64bit));
    if (nr_vectors > 1) {
        msg.data &= ~(nr_vectors - 1);
        msg.data |= vector;
    }

    return msg;
}

void msi_send_message(PCIDevice *dev, MSIMessage msg)
{
    if (pci_get_word(dev->config + PCI_COMMAND)
                      & PCI_COMMAND_MASTER) {
		struct kvm_kernel_irq_routing_entry route;

	    route.msi.address_lo = (uint32_t)msg.address;
		route.msi.address_hi = msg.address >> 32;
		route.msi.data = msg.data;
		route.msi.flags = 0;
		route.msi.devid = 0;

		kvm_set_msi(&route, dev->bus->kvm, KVM_USERSPACE_IRQ_SOURCE_ID, 1, false);
	}
}

void msi_notify(PCIDevice *dev, unsigned int vector)
{
    uint16_t flags = pci_get_word(dev->config + msi_flags_off(dev));
    bool msi64bit = flags & PCI_MSI_FLAGS_64BIT;
    MSIMessage msg;

    if (msi_is_masked(dev, vector)) {
        pci_long_test_and_set_mask(
            dev->config + msi_pending_off(dev, msi64bit), 1U << vector);
        return;
    }

    msg = msi_get_message(dev, vector);

    msi_send_message(dev, msg);
}

void msi_write_config(PCIDevice *dev, uint32_t addr, uint32_t val, int len)
{
    uint16_t flags = pci_get_word(dev->config + msi_flags_off(dev));
    bool msi64bit = flags & PCI_MSI_FLAGS_64BIT;
    bool msi_per_vector_mask = flags & PCI_MSI_FLAGS_MASKBIT;
    unsigned int nr_vectors;
    uint8_t log_num_vecs;
    uint8_t log_max_vecs;
    unsigned int vector;
    uint32_t pending;

    if (!msi_present(dev) ||
        !ranges_overlap(addr, len, dev->msi_cap, msi_cap_sizeof(flags))) {
        return;
    }

    if (!(flags & PCI_MSI_FLAGS_ENABLE)) {
        return;
    }

    pci_device_deassert_intx(dev);

    log_num_vecs =
        (flags & PCI_MSI_FLAGS_QSIZE) >> ctz32(PCI_MSI_FLAGS_QSIZE);
    log_max_vecs =
        (flags & PCI_MSI_FLAGS_QMASK) >> ctz32(PCI_MSI_FLAGS_QMASK);
    if (log_num_vecs > log_max_vecs) {
        flags &= ~PCI_MSI_FLAGS_QSIZE;
        flags |= log_max_vecs << ctz32(PCI_MSI_FLAGS_QSIZE);
        pci_set_word(dev->config + msi_flags_off(dev), flags);
    }

    if (!msi_per_vector_mask) {
        return;
    }

    nr_vectors = msi_nr_vectors(flags);

    /* This will discard pending interrupts, if any. */
    pending = pci_get_long(dev->config + msi_pending_off(dev, msi64bit));
    pending &= 0xffffffff >> (PCI_MSI_VECTORS_MAX - nr_vectors);
    pci_set_long(dev->config + msi_pending_off(dev, msi64bit), pending);

    /* deliver pending interrupts which are unmasked */
    for (vector = 0; vector < nr_vectors; ++vector) {
        if (msi_is_masked(dev, vector) || !(pending & (1U << vector))) {
            continue;
        }

        pci_long_test_and_clear_mask(
            dev->config + msi_pending_off(dev, msi64bit), 1U << vector);
        msi_notify(dev, vector);
    }
}

int msix_present(PCIDevice *dev)
{
    return dev->cap_present & QEMU_PCI_CAP_MSIX;
}

static bool msix_masked(PCIDevice *dev)
{
    return dev->config[dev->msix_cap + MSIX_CONTROL_OFFSET] & MSIX_MASKALL_MASK;
}

bool msi_enabled(const PCIDevice *dev)
{
    return msi_present(dev) &&
        (pci_get_word(dev->config + msi_flags_off(dev)) &
         PCI_MSI_FLAGS_ENABLE);
}

int msix_enabled(PCIDevice *dev)
{
    return (dev->cap_present & QEMU_PCI_CAP_MSIX) &&
        (dev->config[dev->msix_cap + MSIX_CONTROL_OFFSET] &
         MSIX_ENABLE_MASK);
}

static void msix_update_function_masked(PCIDevice *dev)
{
    dev->msix_function_masked = !msix_enabled(dev) || msix_masked(dev);
}

static bool msix_vector_masked(PCIDevice *dev, unsigned int vector, bool fmask)
{
    unsigned offset = vector * PCI_MSIX_ENTRY_SIZE;

    return fmask || dev->msix_table[offset + PCI_MSIX_ENTRY_VECTOR_CTRL] &
        PCI_MSIX_ENTRY_CTRL_MASKBIT;
}

static uint8_t *msix_pending_byte(PCIDevice *dev, int vector)
{
    return dev->msix_pba + vector / 8;
}

static uint8_t msix_pending_mask(int vector)
{
    return 1 << (vector % 8);
} 

void msix_clr_pending(PCIDevice *dev, int vector)
{
    *msix_pending_byte(dev, vector) &= ~msix_pending_mask(vector);
}

bool msix_is_masked(PCIDevice *dev, unsigned int vector)
{
    return msix_vector_masked(dev, vector, dev->msix_function_masked);
}

void msix_set_pending(PCIDevice *dev, unsigned int vector)
{
    *msix_pending_byte(dev, vector) |= msix_pending_mask(vector);
}

static int msix_is_pending(PCIDevice *dev, int vector)
{                                     
    return *msix_pending_byte(dev, vector) & msix_pending_mask(vector);
}

MSIMessage msix_get_message(PCIDevice *dev, unsigned vector)
{
    uint8_t *table_entry = dev->msix_table + vector * PCI_MSIX_ENTRY_SIZE;
    MSIMessage msg;

    msg.address = pci_get_quad(table_entry + PCI_MSIX_ENTRY_LOWER_ADDR);
    msg.data = pci_get_long(table_entry + PCI_MSIX_ENTRY_DATA);
    return msg;
}

static void msix_fire_vector_notifier(PCIDevice *dev,
                                      unsigned int vector, bool is_masked)
{
    MSIMessage msg;
    int ret;

    if (!dev->msix_vector_use_notifier) {
        return;
    }

    if (is_masked) {
        dev->msix_vector_release_notifier(dev, vector);
    } else {
        msg = msix_get_message(dev, vector);
        ret = dev->msix_vector_use_notifier(dev, vector, msg);
    }
}

void msix_notify(PCIDevice *dev, unsigned vector)
{
    MSIMessage msg;

    if (vector >= dev->msix_entries_nr || !dev->msix_entry_used[vector]) {
        return;
    }

    if (msix_is_masked(dev, vector)) {
        msix_set_pending(dev, vector);
        return;
    }

    msg = msix_get_message(dev, vector);

    msi_send_message(dev, msg);
}


static void msix_handle_mask_update(PCIDevice *dev, int vector, bool was_masked)
{
    bool is_masked = msix_is_masked(dev, vector);

    if (is_masked == was_masked)
        return;

    msix_fire_vector_notifier(dev, vector, is_masked);

    if (!is_masked && msix_is_pending(dev, vector)) {
        msix_clr_pending(dev, vector);
        msix_notify(dev, vector);
    }
}

void msix_write_config(PCIDevice *dev, uint32_t addr,
                       uint32_t val, int len)
{
    unsigned enable_pos = dev->msix_cap + MSIX_CONTROL_OFFSET;
    int vector;
    bool was_masked;

    if (!msix_present(dev) || !range_covers_byte(addr, len, enable_pos)) {
        return;
    }

    was_masked = dev->msix_function_masked; 
    msix_update_function_masked(dev);

    if (!msix_enabled(dev)) {
        return;
    }

    pci_device_deassert_intx(dev);


    if (dev->msix_function_masked == was_masked)
        return;

    for (vector = 0; vector < dev->msix_entries_nr; ++vector)
        msix_handle_mask_update(dev, vector,
                                msix_vector_masked(dev, vector, was_masked));
}

void pci_default_write_config(PCIDevice *d, uint32_t addr, uint32_t val_in, int l)
{
    int i, was_irq_disabled = pci_irq_disabled(d);
    uint32_t val = val_in;

    for (i = 0; i < l; val >>= 8, ++i) {
        uint8_t wmask = d->wmask[addr + i];
        uint8_t w1cmask = d->w1cmask[addr + i];
        d->config[addr + i] = (d->config[addr + i] & ~wmask) | (val & wmask);
        d->config[addr + i] &= ~(val & w1cmask); /* W1C: Write 1 to Clear */
    }

    if (ranges_overlap(addr, l, PCI_BASE_ADDRESS_0, 24) ||
        ranges_overlap(addr, l, PCI_ROM_ADDRESS, 4) ||
        ranges_overlap(addr, l, PCI_ROM_ADDRESS1, 4) ||
        range_covers_byte(addr, l, PCI_COMMAND))
        pci_update_mappings(d);

    if (range_covers_byte(addr, l, PCI_COMMAND))
        pci_update_irq_disabled(d, was_irq_disabled);

    msi_write_config(d, addr, val_in, l);
    msix_write_config(d, addr, val_in, l);
}

PCIDevice *do_pci_register_device(PCIDevice *pci_dev, PCIBus *bus,
                                        const char *name,
                                        PCIConfigWriteFunc *config_write,
                                        PCIConfigReadFunc *config_read,
                                        uint16_t vendor_id,
                                        uint16_t device_id,
                                        uint16_t class_id,
                                        uint16_t revision)
{
	int devfn;
    pci_dev->bus = bus;

    for(devfn = 0; devfn < ARRAY_SIZE(bus->devices);
        devfn += PCI_FUNC_MAX) {
        if (pci_bus_devfn_available(bus, devfn)) {
            goto found;
        }   
    }   
    return NULL;

    found: ;

    pci_dev->devfn = devfn;
    strlcpy(pci_dev->name, name, sizeof(pci_dev->name));

    pci_dev->irq_state = 0;
    pci_config_alloc(pci_dev);

	pci_set_word(&pci_dev->config[PCI_VENDOR_ID], vendor_id);
	pci_set_word(&pci_dev->config[PCI_DEVICE_ID], device_id);
	pci_set_word(&pci_dev->config[PCI_REVISION_ID], revision);
	pci_set_word(&pci_dev->config[PCI_CLASS_DEVICE], class_id);
	pci_set_word(&pci_dev->config[PCI_SUBSYSTEM_VENDOR_ID],
		PCI_SUBVENDOR_ID_REDHAT_QUMRANET);
	pci_set_word(&pci_dev->config[PCI_SUBSYSTEM_ID],
		PCI_SUBDEVICE_ID_QEMU);

    pci_init_cmask(pci_dev);
    pci_init_wmask(pci_dev);
    pci_init_w1cmask(pci_dev);

    if (0 > pci_init_multifunction(bus, pci_dev)) {
		do_pci_unregister_device(pci_dev);
        return NULL;
	}

    if (!config_read)
        config_read = pci_default_read_config;

    if (!config_write)
        config_write = pci_default_write_config;

    pci_dev->config_read = config_read;
    pci_dev->config_write = config_write;
    bus->devices[devfn] = pci_dev;

    return pci_dev;
}

static void piix3_set_irq_pic(PCIDevice *dev, int pic_irq)
{
	struct piix *piix = container_of(dev, struct piix, pci);

	int level = !!(piix->pic_levels &
                    (((1ULL << PIIX_NUM_PIRQS) - 1) <<
                     (pic_irq * PIIX_NUM_PIRQS)));

	kvm_set_irq(dev->bus->kvm, KVM_USERSPACE_IRQ_SOURCE_ID,
                    pic_irq, level, 1);
}

static void piix3_set_irq_level_internal(PCIDevice *dev, int pirq, int level)
{
    int pic_irq;
    uint64_t mask;
	struct piix *piix = container_of(dev, struct piix, pci);

    pic_irq = dev->config[PIIX_PIRQCA + pirq];
    if (pic_irq >= PIIX_NUM_PIC_IRQS) {
        return;
    }

    mask = 1ULL << ((pic_irq * PIIX_NUM_PIRQS) + pirq);

    piix->pic_levels &= ~mask;
    piix->pic_levels |= mask * !!level;
}

static void piix3_set_irq_level(PCIDevice *dev, int pirq, int level)
{
    int pic_irq;

    pic_irq = dev->config[PIIX_PIRQCA + pirq];
    if (pic_irq >= PIIX_NUM_PIC_IRQS) {
        return;
    }

    piix3_set_irq_level_internal(dev, pirq, level);

    piix3_set_irq_pic(dev, pic_irq);
}

int pci_bus_get_irq_level(PCIBus *bus, int irq_num)
{   
    return !!bus->irq_count[irq_num];
} 

static void piix3_update_irq_levels(PCIDevice *dev)
{
    PCIBus *bus = dev->bus;
	struct piix *piix = container_of(dev, struct piix, pci);
    int pirq;

    piix->pic_levels = 0;
    for (pirq = 0; pirq < PIIX_NUM_PIRQS; pirq++) {
        piix3_set_irq_level(dev, pirq, pci_bus_get_irq_level(bus, pirq));
    }
}

static void piix3_write_config(PCIDevice *dev,
                               uint32_t address, uint32_t val, int len)
{
    pci_default_write_config(dev, address, val, len);

    if (ranges_overlap(address, len, PIIX_PIRQCA, 4)) {
        int pic_irq;

        piix3_update_irq_levels(dev);
        for (pic_irq = 0; pic_irq < PIIX_NUM_PIC_IRQS; pic_irq++) {
            piix3_set_irq_pic(dev, pic_irq);
        }
    }
}

static void piix3_reset(PCIDevice *d)
{
	struct piix *piix = container_of(d, struct piix, pci);
    uint8_t *pci_conf = d->config;

    pci_conf[0x04] = 0x07; /* master, memory and I/O */
    pci_conf[0x05] = 0x00;
    pci_conf[0x06] = 0x00;
    pci_conf[0x07] = 0x02; /* PCI_status_devsel_medium */
    pci_conf[0x4c] = 0x4d;
    pci_conf[0x4e] = 0x03;
    pci_conf[0x4f] = 0x00;
    pci_conf[0x60] = 0x80;
    pci_conf[0x61] = 0x80;
    pci_conf[0x62] = 0x80;
    pci_conf[0x63] = 0x80;
    pci_conf[0x69] = 0x02;
    pci_conf[0x70] = 0x80;
    pci_conf[0x76] = 0x0c;
    pci_conf[0x77] = 0x0c;
    pci_conf[0x78] = 0x02;
    pci_conf[0x79] = 0x00;
    pci_conf[0x80] = 0x00;
    pci_conf[0x82] = 0x00;
    pci_conf[0xa0] = 0x08;
    pci_conf[0xa2] = 0x00;
    pci_conf[0xa3] = 0x00;
    pci_conf[0xa4] = 0x00;
    pci_conf[0xa5] = 0x00;
    pci_conf[0xa6] = 0x00;
    pci_conf[0xa7] = 0x00;
    pci_conf[0xa8] = 0x0f;
    pci_conf[0xaa] = 0x00;
    pci_conf[0xab] = 0x00;
    pci_conf[0xac] = 0x00;
    pci_conf[0xae] = 0x00;

    piix->pic_levels = 0;
}


static void piix3_set_irq(void *opaque, int pirq, int level)
{
    PCIDevice *dev = opaque;

    piix3_set_irq_level(dev, pirq, level);
}

static int pci_slot_get_pirq(PCIDevice *pci_dev, int pci_intx)
{
    int slot_addend;

    slot_addend = (pci_dev->devfn >> 3) - 1;

    return (pci_intx + slot_addend) & 3;
}

static void pci_bus_irqs(PCIBus *bus, pci_set_irq_fn set_irq, pci_map_irq_fn map_irq,
                  void *irq_opaque, int nirq)
{   
    bus->set_irq = set_irq;
    bus->map_irq = map_irq;
    bus->irq_opaque = irq_opaque;
    bus->irq_count = kzalloc(PIIX_NUM_PIRQS * sizeof(bus->irq_count[0]), GFP_KERNEL);
} 

static void create_piix(struct virt_pci_bus *bus)
{
    struct piix *piix;
	PCIDevice *pci_dev;

	piix = kzalloc(sizeof(struct piix), GFP_KERNEL);
	if (!piix) {
		printk(">>>>>error %s:%d\n", __func__, __LINE__);
		return;
	}

	pci_dev = &piix->pci;

    pci_dev->cap_present = QEMU_PCI_CAP_SERR
                        | QEMU_PCIE_LNKSTA_DLLLA
                        | QEMU_PCIE_EXTCAP_INIT
    					| QEMU_PCI_CAP_MULTIFUNCTION;

    do_pci_register_device(pci_dev, bus,
                               "piix", piix3_write_config, NULL,
                                PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_82371SB_0,
                                PCI_CLASS_BRIDGE_ISA, 0);
    piix3_reset(pci_dev);

	pci_bus_irqs(pci_dev->bus, piix3_set_irq, pci_slot_get_pirq,
                    pci_dev, PIIX_NUM_PIRQS);

	bus->piix = piix;
}

static void destroy_piix(struct virt_pci_bus *bus)
{
    struct piix *piix;
	PCIDevice *pci_dev;

	piix = bus->piix;
	pci_dev = &piix->pci;

    do_pci_unregister_device(pci_dev);

    kfree(bus->irq_count);
	kfree(piix);
}


static void pci_host_config_write_common(PCIDevice *pci_dev, uint32_t addr,
                                  uint32_t limit, uint32_t val, uint32_t len)
{
    if (limit <= addr)
        return;

    pci_dev->config_write(pci_dev, addr, val, MIN(len, limit - addr));
}

static uint32_t pci_host_config_read_common(PCIDevice *pci_dev, uint32_t addr,
                                     uint32_t limit, uint32_t len)
{
    uint32_t ret;

    if (limit <= addr)
        return ~0x0;

    ret = pci_dev->config_read(pci_dev, addr, MIN(len, limit - addr));

    return ret;
}

static void pci_data_write(PCIBus *s, uint32_t addr, uint32_t val, int len)
{   
    PCIDevice *pci_dev = pci_dev_find_by_addr(s, addr);
    uint32_t config_addr = addr & (PCI_CONFIG_SPACE_SIZE - 1);
    
    if (!pci_dev)
        return;

//	printk(">>>>>%s:%d %x %x %x\n", __func__, __LINE__, addr, val, len);
    
    pci_host_config_write_common(pci_dev, config_addr, PCI_CONFIG_SPACE_SIZE,
                                 val, len);
}

static uint32_t pci_data_read(PCIBus *s, uint32_t addr, int len)
{
    PCIDevice *pci_dev = pci_dev_find_by_addr(s, addr);
    uint32_t config_addr = addr & (PCI_CONFIG_SPACE_SIZE - 1);
    uint32_t val;

    if (!pci_dev)
        return ~0x0;

//	printk(">>>>>%s:%d %x %x\n", __func__, __LINE__, addr, len);

    val = pci_host_config_read_common(pci_dev, config_addr,
                                      PCI_CONFIG_SPACE_SIZE, len);

    return val;
}

static int vpci_data_write(struct kvm_vcpu *vcpu, struct kvm_io_device *dev,
			       gpa_t addr, int len, const void *val)
{
	struct virt_pci_bridge *bridge = container_of(dev, struct virt_pci_bridge, data_dev);

	if (bridge->conf_reg & (1u << 31))
        pci_data_write(bridge->bus, bridge->conf_reg | (addr & 3), *(uint32_t*)val, len);

	return 0;
}

static int vpci_data_read(struct kvm_vcpu *vcpu, struct kvm_io_device *dev,
			      gpa_t addr, int len, void *val)
{
	struct virt_pci_bridge *bridge = container_of(dev, struct virt_pci_bridge, data_dev);

    if (!(bridge->conf_reg & (1U << 31))) {
        *(uint32_t*)val = 0xffffffff;
		return 0;
    }

    *(uint32_t*)val = pci_data_read(bridge->bus, bridge->conf_reg | (addr & 3), len);

	return 0;
}

static const struct kvm_io_device_ops vbridge_data_ops = {
	.read     = vpci_data_read,
	.write    = vpci_data_write,
};

static int vpci_conf_write(struct kvm_vcpu *vcpu, struct kvm_io_device *dev,
			       gpa_t addr, int len, const void *val)
{
	struct virt_pci_bridge *bridge = container_of(dev, struct virt_pci_bridge, conf_dev);

    if (len != 4)
		return -EOPNOTSUPP;

    bridge->conf_reg = *(uint32_t*)val;

	return 0;
}

static int vpci_conf_read(struct kvm_vcpu *vcpu, struct kvm_io_device *dev,
			      gpa_t addr, int len, void *val)
{
	struct virt_pci_bridge *bridge = container_of(dev, struct virt_pci_bridge, conf_dev);

	*(uint32_t*)val = bridge->conf_reg;

	return 0;
}

static const struct kvm_io_device_ops vbridge_conf_ops = {
	.read     = vpci_conf_read,
	.write    = vpci_conf_write,
};


void create_vpci(struct kvm *kvm)
{
	int ret;
	struct virt_pci_bridge *bridge;
	struct virt_pci_bus *bus;
	
	bus = kzalloc(sizeof(struct virt_pci_bus), GFP_KERNEL);
	if (!bus) {
		printk(">>>>>error %s:%d\n", __func__, __LINE__);
		return;
	}
	
	bridge = kzalloc(sizeof(struct virt_pci_bridge), GFP_KERNEL);
	if (!bridge) {
		printk(">>>>>error %s:%d\n", __func__, __LINE__);
		goto fail_1;
	}
	bridge->bus = bus;

	kvm_iodevice_init(&bridge->conf_dev, &vbridge_conf_ops);
	kvm_iodevice_init(&bridge->data_dev, &vbridge_data_ops);

	mutex_lock(&kvm->slots_lock);
	ret = kvm_io_bus_register_dev(kvm, KVM_PIO_BUS, 0xcf8, 4,
				      &bridge->conf_dev);
	if (ret < 0) {
		printk(">>>>>error %s:%d\n", __func__, __LINE__);
		goto fail_2;
	}

	ret = kvm_io_bus_register_dev(kvm, KVM_PIO_BUS, 0xcfc, 4,
				      &bridge->data_dev);
	if (ret < 0) {
		printk(">>>>>error %s:%d\n", __func__, __LINE__);
		goto fail_3;
	}
	mutex_unlock(&kvm->slots_lock);

	kvm->vdevices.vbridge = bridge;
	bus->kvm = kvm;

	create_piix(bus);

	return;

fail_3:
	kvm_io_bus_unregister_dev(kvm, KVM_PIO_BUS, &bridge->conf_dev);

fail_2:
	mutex_unlock(&kvm->slots_lock);
	kfree(bridge);
fail_1:
	kfree(bus);
	return;
}


void destroy_vpci(struct kvm *kvm)
{
	struct virt_pci_bridge *bridge;
	struct virt_pci_bus *bus;

	bridge = kvm->vdevices.vbridge;
	bus = bridge->bus;

	destroy_piix(bus);

	mutex_lock(&kvm->slots_lock);
	kvm_io_bus_unregister_dev(kvm, KVM_PIO_BUS, &bridge->data_dev);
	kvm_io_bus_unregister_dev(kvm, KVM_PIO_BUS, &bridge->conf_dev);
	mutex_unlock(&kvm->slots_lock);

	kfree(bridge);
	kfree(bus);
}



