#include <linux/slab.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/mm.h>
#include <linux/vmacache.h>
#include <linux/stat.h>
#include <linux/fcntl.h>
#include <linux/swap.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/sched/mm.h>
#include <linux/sched/coredump.h>
#include <linux/sched/signal.h>
#include <linux/sched/numa_balancing.h>
#include <linux/sched/task.h>
#include <linux/pagemap.h>
#include <linux/perf_event.h>
#include <linux/highmem.h>
#include <linux/spinlock.h>
#include <linux/key.h>
#include <linux/personality.h>
#include <linux/binfmts.h>
#include <linux/utsname.h>
#include <linux/pid_namespace.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/tsacct_kern.h>
#include <linux/cn_proc.h>
#include <linux/audit.h>
#include <linux/tracehook.h>
#include <linux/kmod.h>
#include <linux/fsnotify.h>
#include <linux/fs_struct.h>
#include <linux/pipe_fs_i.h>
#include <linux/oom.h>
#include <linux/compat.h>
#include <linux/vmalloc.h>

#include <trace/events/fs.h>

#include <linux/uaccess.h>
#include <asm/mmu_context.h>
#include <asm/tlb.h>
#include <linux/kvm_host.h>
#include <linux/export.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/sched/stat.h>

#include <asm/processor.h>
#include <asm/user.h>
#include <asm/fpu/xstate.h>
#include <asm/cpu.h>
#include <asm/processor.h>
#include <asm/processor.h>
#include <asm/mwait.h>
#include <linux/kvm_host.h>
#include <asm/pvclock.h>
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


#include <linux/clocksource.h>
#include <linux/interrupt.h>
#include <linux/kvm.h>
#include <linux/fs.h>
#include <linux/vmalloc.h>
#include <linux/export.h>
#include <linux/moduleparam.h>
#include <linux/mman.h>
#include <linux/highmem.h>
#include <linux/iommu.h>
#include <linux/intel-iommu.h>
#include <linux/cpufreq.h>
#include <linux/user-return-notifier.h>
#include <linux/srcu.h>
#include <linux/slab.h>
#include <linux/perf_event.h>
#include <linux/uaccess.h>
#include <linux/hash.h>
#include <linux/pci.h>
#include <linux/timekeeper_internal.h>
#include <linux/pvclock_gtod.h>
#include <linux/kvm_irqfd.h>
#include <linux/irqbypass.h>
#include <linux/sched/stat.h>
#include <linux/mem_encrypt.h>

#include <trace/events/kvm.h>

#include <asm/debugreg.h>
#include <asm/msr.h>
#include <asm/desc.h>
#include <asm/mce.h>
#include <linux/kernel_stat.h>
#include <asm/fpu/internal.h> /* Ugh! */
#include <asm/pvclock.h>
#include <asm/div64.h>
#include <asm/irq_remapping.h>

//the following are hardcode for tempolory
#define CPUS 2
#define DIES 1
#define CORES 2
#define THREADS 1
#define RAM_SIZE 0x80000000
#define KERNEL_PATH "/home/gen/openSource/guen/vmlinux"
#define KERNEL_CMDLINE  "console=ttyS0 root=/dev/sda"

void init_vm_possible_cpus(struct kvm *kvm)
{
	int i;
	CPUArchIdList *list;
	list = vzalloc(sizeof(CPUArchIdList) +
                                  sizeof(CPUArchId) * CPUS);
	list->len = CPUS;
    for (i = 0; i < list->len; i++) {
        X86CPUTopoInfo topo;
    
        list->cpus[i].arch_id = x86_apicid_from_cpu_idx(DIES, CORES,
                                         THREADS, i);

        x86_topo_ids_from_apicid(list->cpus[i].arch_id,
                                 DIES, CORES,
                                 THREADS, &topo);

        list->cpus[i].props.socket_id = topo.pkg_id;
        list->cpus[i].props.core_id = topo.core_id;
        list->cpus[i].props.thread_id = topo.smt_id;
    }

	kvm->possible_cpus = list;
}

void init_env_possible_cpus(CPUX86State *env, struct kvm *kvm)
{
	int i;
	CPUArchIdList *list;

	env->nr_cores = CORES;
	env->nr_threads = THREADS;

	list = kvm->possible_cpus;
	for (i = 0; i < list->len; i++) {
		if (env->apic_id == list->cpus[i].arch_id) {
			env->socket_id = list->cpus[i].props.socket_id;
        	env->core_id =	list->cpus[i].props.core_id;
        	env->thread_id = list->cpus[i].props.thread_id;
			break;
		}
	}
}

uint64_t kernel_entry;

static void load_linux_mini(struct kvm_vcpu *vcpu)
{
    int i;
	void *buf;
	loff_t size;
	int rc;
    Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdrs;

	rc = kernel_read_file_from_path(KERNEL_PATH, &buf, &size, 1024*1024*100,
						READING_MODULE);
	if (rc || size == 0 || size < sizeof(ehdr)) {
		printk(">>>>>fail to read file kernel file %s:%d\n", __func__, __LINE__);
		return;
	}

	ehdr = (Elf64_Ehdr *)buf;

    if (ehdr->e_ident[EI_MAG0] != ELFMAG0
        || ehdr->e_ident[EI_MAG1] != ELFMAG1
        || ehdr->e_ident[EI_MAG2] != ELFMAG2
        || ehdr->e_ident[EI_MAG3] != ELFMAG3) {
		printk(">>>>>fail to read file kernel file %s:%d\n", __func__, __LINE__);
		return;
    }

    if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB) {
		printk(">>>>>fail to read file kernel file %s:%d\n", __func__, __LINE__);
		return;
    }

    if (ehdr->e_phentsize != sizeof(Elf64_Phdr)) {
		printk(">>>>>fail to read file kernel file %s:%d\n", __func__, __LINE__);
		return;
    }

    if (ehdr->e_phoff < sizeof(Elf64_Ehdr)) {
		printk(">>>>>fail to read file kernel file %s:%d\n", __func__, __LINE__);
		return;
    }

	phdrs = (Elf64_Phdr *)(buf + ehdr->e_phoff);

    for (i = 0; i < ehdr->e_phnum; i++) {
		struct gfn_to_hva_cache ghc;
        Elf64_Phdr *phdr = &phdrs[i];
        uint8_t *addr;

        if ((phdr->p_type & PT_LOAD) == 0
             || phdr->p_filesz == 0)
            continue;

		addr = (uint8_t *)(buf + phdr->p_offset);

		if (kvm_gfn_to_hva_cache_init(vcpu->kvm, &ghc, phdr->p_paddr, phdr->p_filesz)) {
			printk(">>>>>fail to read file kernel file %s:%d\n", __func__, __LINE__);
			return;
		}

    	memcpy((void*)ghc.hva, addr, phdr->p_filesz);
    }   

    kernel_entry = ehdr->e_entry;
}

#define KERNEL_CMDLINE_ADDR  0x20000

static void load_cmdline_mini(struct kvm_vcpu *vcpu)
{
    const char *kernel_cmdline = KERNEL_CMDLINE;
	struct gfn_to_hva_cache ghc;
    uint64_t len = strlen(kernel_cmdline) + 1;

	if (kvm_gfn_to_hva_cache_init(vcpu->kvm, &ghc, KERNEL_CMDLINE_ADDR,
			len)) {
		printk(">>>>>fail to map kernel cmdline %s:%d\n", __func__, __LINE__);
		return;
	}

    memcpy((void*)ghc.hva, kernel_cmdline, len);
}

static uint8_t compute_checksum(void *base, size_t len)
{
    uint8_t *bytes;
    uint8_t sum;

    for (bytes = base, sum = 0; len > 0; len--)
        sum += *bytes++;

    return (256 - sum);
}

#define MP_PROCESSOR  0
#define APIC_VERSION  0x14
#define CPU_ENABLED   1
#define CPU_BOOTPROCESSOR  2
#define CPU_STEPPING   0x600
#define CPU_FEATURE_APIC  0x200
#define CPU_FEATURE_FPU  0x001

#define MP_BUS  1
#define MP_IOAPIC 2
#define IO_APIC_DEFAULT_PHYS_BASE 0xfec00000

#define MP_INTSRC 3
#define MP_LINTSRC 4

#define mp_irq_source_types_mp_INT  0
#define mp_irq_source_types_mp_NMI  1
#define mp_irq_source_types_mp_SMI  2
#define mp_irq_source_types_mp_ExtINT 3
#define MP_IRQDIR_DEFAULT  0

#define MPC_SPEC  4

#define MPTABLE_BASE_ADDR  0x9fc00

static void build_mptable_mini(struct kvm_vcpu *vcpu)
{
    int i;
    int pin;
    const CPUArchIdList *possible_cpus = vcpu->kvm->possible_cpus;
    struct mpc_table *mpc_table;
	struct mpf_intel *mpf_intel;
	struct mpc_cpu *mpc_cpu;
	struct mpc_bus *mpc_bus;
	struct mpc_ioapic *mpc_ioapic;
	struct mpc_intsrc *mpc_intsrc;
	struct mpc_lintsrc *mpc_lintsrc;

    uint8_t *base_mp;
    uint8_t ioapic_id =
        x86_apicid_from_cpu_idx(DIES, CORES, THREADS, CPUS - 1) + 1;
	struct gfn_to_hva_cache ghc;


    uint64_t len = sizeof(struct mpf_intel)
                    + sizeof(struct mpc_table)
                    + sizeof(struct mpc_cpu) * CPUS 
                    + sizeof(struct mpc_ioapic)
                    + sizeof(struct mpc_bus)
                    + sizeof(struct mpc_intsrc) * 16
                    + sizeof(struct mpc_lintsrc) * 2;

	if (kvm_gfn_to_hva_cache_init(vcpu->kvm, &ghc, MPTABLE_BASE_ADDR,
			len)) {
		printk(">>>>>fail to map mptable %s:%d\n", __func__, __LINE__);
		return;
	}

	base_mp = (uint8_t*)ghc.hva;
    memset(base_mp, 0, len);


    //build mpf
    mpf_intel = (struct mpf_intel *)base_mp;
    memcpy(mpf_intel->signature, "_MP_", 4);
    mpf_intel->length = 1;
    mpf_intel->specification = 4;
    mpf_intel->physptr = MPTABLE_BASE_ADDR + sizeof(struct mpf_intel);
    mpf_intel->checksum =
         compute_checksum((uint8_t *)mpf_intel, sizeof(struct mpf_intel));
    base_mp += sizeof(struct mpf_intel);

    /* We set the location of the mpc_table here but we can't fill
     * it out until we have the length of the entire table later.
     */
    mpc_table = (struct mpc_table *)base_mp;
    base_mp += sizeof(struct mpc_table);




    //build mpc_cpu
    mpc_cpu = (struct mpc_cpu *)base_mp;
    for (i = 0; i < CPUS; i++) {
        uint8_t apic_id = possible_cpus->cpus[i].arch_id;

        mpc_cpu[i].type = MP_PROCESSOR;
        mpc_cpu[i].apicid = apic_id;
        mpc_cpu[i].apicver = APIC_VERSION;
        mpc_cpu[i].cpuflag = CPU_ENABLED |
             (apic_id == 0 ? CPU_BOOTPROCESSOR : 0);
        mpc_cpu[i].cpufeature = CPU_STEPPING;
        mpc_cpu[i].featureflag = CPU_FEATURE_APIC | CPU_FEATURE_FPU;

        base_mp += sizeof(struct mpc_cpu);
    }


    //build mpc bus
    mpc_bus = (struct mpc_bus *)base_mp;
    mpc_bus->type = MP_BUS;
    mpc_bus->busid = 0;
    memcpy(mpc_bus->bustype, "ISA   ", 6);

    base_mp += sizeof(struct mpc_bus);




    //build mpc ioapic
    mpc_ioapic = (struct mpc_ioapic *)base_mp;
    mpc_ioapic->type = MP_IOAPIC;
    mpc_ioapic->apicid = ioapic_id;
    mpc_ioapic->apicver = APIC_VERSION;
    mpc_ioapic->flags = MPC_APIC_USABLE;
    mpc_ioapic->apicaddr = IO_APIC_DEFAULT_PHYS_BASE;

    base_mp += sizeof(struct mpc_ioapic);

    //build mpc interrupt source
    mpc_intsrc = (struct mpc_intsrc *)base_mp;

#define SCI_INT 9
#define INTENTRY_FLAGS_TRIGGER_LEVEL        0xc
#define INTENTRY_FLAGS_POLARITY_ACTIVELO    0x3
    for (pin = 0; pin < 16; pin++) {
        mpc_intsrc[i].type = MP_INTSRC;
        mpc_intsrc[i].srcbus = 0;
        mpc_intsrc[i].dstapic = ioapic_id;

        mpc_intsrc[i].dstirq = pin;
        switch (pin) {
        case 0:
            /* Pin 0 is an ExtINT pin. */
            mpc_intsrc[i].irqtype = mp_irq_source_types_mp_ExtINT;
            break;
        case 2:
            /* IRQ 0 is routed to pin 2. */
            mpc_intsrc[i].irqtype = mp_irq_source_types_mp_INT;
            mpc_intsrc[i].srcbusirq = 0;
            break;
        case SCI_INT:
            /* ACPI SCI is level triggered and active-lo. */
            mpc_intsrc[i].irqflag = INTENTRY_FLAGS_POLARITY_ACTIVELO |
                INTENTRY_FLAGS_TRIGGER_LEVEL;
            mpc_intsrc[i].irqtype = mp_irq_source_types_mp_INT;
            mpc_intsrc[i].srcbusirq = SCI_INT;
            break;
        default:
            /* All other pins are identity mapped. */
            mpc_intsrc[i].irqtype = mp_irq_source_types_mp_INT;
            mpc_intsrc[i].srcbusirq = pin;
            break;
        }
    }


    //build mpc line interrupt source
    mpc_lintsrc = (struct mpc_lintsrc *)base_mp;

    mpc_lintsrc[0].type = MP_LINTSRC;
    mpc_lintsrc[0].irqtype = mp_irq_source_types_mp_ExtINT;
    mpc_lintsrc[0].irqflag = MP_IRQDIR_DEFAULT;
    mpc_lintsrc[0].srcbusid = 0;
    mpc_lintsrc[0].srcbusirq = 0;
    mpc_lintsrc[0].destapic = 0;
    mpc_lintsrc[0].destapiclint = 0;

    mpc_lintsrc[1].type = MP_LINTSRC;
    mpc_lintsrc[1].irqtype = mp_irq_source_types_mp_NMI;
    mpc_lintsrc[1].irqflag = MP_IRQDIR_DEFAULT;
    mpc_lintsrc[1].srcbusid = 0;
    mpc_lintsrc[1].srcbusirq = 0;
    mpc_lintsrc[1].destapic = 0xFF; /* to all local APICs */
    mpc_lintsrc[1].destapiclint = 1;

    base_mp += sizeof(struct mpc_lintsrc) * 2;


    //build mpc table
    memcpy(mpc_table->signature, "PCMP", 4);
    mpc_table->length = base_mp - (uint8_t *)mpc_table;
    mpc_table->spec = MPC_SPEC;
    memcpy(mpc_table->oem, "GEN     ", 8);
    memcpy(mpc_table->productid, "MINIVM      ", 12);
    mpc_table->lapic = APIC_DEFAULT_PHYS_BASE;

    mpc_table->checksum =
         compute_checksum((uint8_t *)mpc_table, mpc_table->length);
}

struct e820entry {
    uint64_t addr;
    uint64_t size;
    uint32_t type_;
}__attribute__((packed));

struct _zeropage {
    uint8_t pad1[0x1e8];                    /* 0x000 */
    uint8_t e820_entries;                  /* 0x1e8 */
    uint8_t pad2[0x8];                      /* 0x1e9 */
	struct setup_header hdr;
    uint8_t pad3[0x68];                     /* 0x268 */
    struct e820entry e820_map[0x80];           /* 0x2d0 */
    uint8_t pad4[0x330];                    /* 0xcd0 */
} __attribute__((packed));

#define ZERO_PAGE_START 0x7000

static void add_e820_entry(struct _zeropage *params,
	uint64_t addr, uint64_t size, uint32_t mem_type)
{
    params->e820_map[params->e820_entries].addr = addr;
    params->e820_map[params->e820_entries].size = size;
    params->e820_map[params->e820_entries].type_ = mem_type;
    params->e820_entries += 1;
}

#define EBDA_START 0x9fc00
#define E820_RAM 1

#define KERNEL_LOADER_OTHER 0xff
#define KERNEL_BOOT_FLAG_MAGIC 0xaa55
#define KERNEL_HDR_MAGIC 0x53726448
#define KERNEL_MIN_ALIGNMENT_BYTES 0x01000000

static void build_bootparams_mini(struct kvm_vcpu *vcpu)
{
    uint8_t *addr;
	struct gfn_to_hva_cache ghc;
    uint64_t len;
	struct _zeropage *boot_params;

    //mapping gpa of zeropage to hva
    len = sizeof(struct _zeropage);

	if (kvm_gfn_to_hva_cache_init(vcpu->kvm, &ghc, ZERO_PAGE_START,
			len)) {
		printk(">>>>>fail to map zeropage %s:%d\n", __func__, __LINE__);
		return;
	}

	addr = (uint8_t*)ghc.hva;

    boot_params = (struct _zeropage *)addr;

    *(uint64_t*)boot_params = 0x12345;

    boot_params->hdr.type_of_loader = KERNEL_LOADER_OTHER;
    boot_params->hdr.boot_flag = KERNEL_BOOT_FLAG_MAGIC;
    boot_params->hdr.header = KERNEL_HDR_MAGIC;
    boot_params->hdr.cmd_line_ptr = KERNEL_CMDLINE_ADDR;
    boot_params->hdr.cmdline_size = 0x10000;
    boot_params->hdr.kernel_alignment = KERNEL_MIN_ALIGNMENT_BYTES;

    add_e820_entry(boot_params, 0, EBDA_START, E820_RAM);
    add_e820_entry(boot_params, 0x100000, RAM_SIZE - 0x100000, E820_RAM);
}

void init_virt_machine(struct kvm_vcpu *vcpu)
{
	if (vcpu->vcpu_id != 0)
		return;

	load_linux_mini(vcpu);

	load_cmdline_mini(vcpu);

	build_mptable_mini(vcpu);
	
	build_bootparams_mini(vcpu);
}

static void kvm_irqchip_add_irq_route(struct kvm_irq_routing *routing, int irq, int irqchip, int pin)
{
    struct kvm_irq_routing_entry e = {};

    e.gsi = irq;
    e.type = KVM_IRQ_ROUTING_IRQCHIP;
    e.flags = 0;
    e.u.irqchip.irqchip = irqchip;
    e.u.irqchip.pin = pin;

	routing->entries[routing->nr] = e;
	routing->nr++;
}

static void kvm_pc_setup_irq_routing(struct kvm *kvm)
{   
    int i;
	int r;
	struct kvm_irq_routing *routing;
	struct kvm_irq_routing_entry *entries = NULL;
	int ent_nr = 7 + 8 + 23;

	routing = vmalloc(sizeof(*routing) + ent_nr * sizeof(*entries));
	if (!entries) {
		printk(">>>>>fail to irq routing %s:%d\n", __func__, __LINE__);
		return;
	}	
	routing->nr = 0;
        
    for (i = 0; i < 8; ++i) {
        if (i == 2) {
            continue;
        }
        kvm_irqchip_add_irq_route(routing, i, KVM_IRQCHIP_PIC_MASTER, i);
    }

    for (i = 8; i < 16; ++i) {
        kvm_irqchip_add_irq_route(routing, i, KVM_IRQCHIP_PIC_SLAVE, i - 8);
    }

    for (i = 0; i < 24; ++i) {
        if (i == 0) {
            kvm_irqchip_add_irq_route(routing, i, KVM_IRQCHIP_IOAPIC, 2);
        } else if (i != 2) {
            kvm_irqchip_add_irq_route(routing, i, KVM_IRQCHIP_IOAPIC, i);
        }
    }

	r = kvm_set_irq_routing(kvm, routing->entries, routing->nr, 0);
	if (r) {
		printk(">>>>>fail to irq routing %s:%d\n", __func__, __LINE__);
		return;
	}
}

int create_virt_machine(struct kvm *kvm)
{
	int r;

	kvm_vm_ioctl_set_identity_map_addr(kvm, 0xfeffc000);

	r = kvm_vm_ioctl_set_tss_addr(kvm, 0xfeffc000 + 0x1000);
	if (r != 0)
		return r;

	mutex_lock(&kvm->lock);

	r = -EEXIST;
	if (irqchip_in_kernel(kvm))
		goto create_irqchip_unlock;

	r = -EINVAL;
	if (kvm->created_vcpus)
		goto create_irqchip_unlock;

	r = kvm_pic_init(kvm);
	if (r)
		goto create_irqchip_unlock;

	r = kvm_ioapic_init(kvm);
	if (r) {
		kvm_pic_destroy(kvm);
		goto create_irqchip_unlock;
	}

	r = kvm_setup_default_irq_routing(kvm);
	if (r) {
		kvm_ioapic_destroy(kvm);
		kvm_pic_destroy(kvm);
		goto create_irqchip_unlock;
	}

	smp_wmb();
	kvm->arch.irqchip_mode = KVM_IRQCHIP_KERNEL;

	r = kvm_get_supported_msrs();
    if (r) {
		goto create_irqchip_unlock;
    }

    kvm_get_supported_feature_msrs();

	init_vm_possible_cpus(kvm);	

	if (!kvm->arch.vpit)
		kvm->arch.vpit = kvm_create_pit(kvm, 0);

//	kvm_pc_setup_irq_routing(kvm);
	

create_irqchip_unlock:
	mutex_unlock(&kvm->lock);
	return r;
}
