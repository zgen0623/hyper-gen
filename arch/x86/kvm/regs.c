#include <linux/kvm_host.h>
#include <linux/export.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/sched/stat.h>

#include <asm/processor.h>
#include <asm/user.h>
#include <asm/fpu/xstate.h>
#include "cpuid.h"
#include "lapic.h"
#include "mmu.h"
#include "trace.h"
#include "pmu.h"
#include "regs.h"
#include "x86.h"
#include <asm/cpu.h>
#include <asm/processor.h>
#include <asm/processor.h>
#include <asm/mwait.h>
#include <linux/kvm_host.h>
#include <asm/pvclock.h>
#include "kvm_cache_regs.h"
#include "irq.h"
#include "mmu.h"
#include "i8254.h"
#include "tss.h"
#include "kvm_cache_regs.h"
#include "x86.h"
#include "cpuid.h"
#include "pmu.h"
#include "hyperv.h"
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



#define BOOT_GDT_OFFSET  0x500
#define BOOT_IDT_OFFSET 0x520
#define BOOT_STACK_POINTER 0x8ff0
#define ZERO_PAGE_START 0x7000

#define PML4_START 0x9000
#define PDPTE_START 0xa000
#define PDE_START 0xb000

extern unsigned num_emulated_msrs;
extern unsigned num_msrs_to_save;
extern u32 msrs_to_save[];
extern u32 emulated_msrs[];

extern u32 msr_based_features[];
extern unsigned int num_msr_based_features;


uint32_t has_architectural_pmu_version;
uint32_t num_architectural_pmu_gp_counters;
uint32_t num_architectural_pmu_fixed_counters;


static struct kvm_cpuid2 *get_supported_cpuid(void);

bool has_msr_star;
bool has_msr_hsave_pa;
bool has_msr_tsc_aux;
bool has_msr_tsc_adjust;
bool has_msr_tsc_deadline;
bool has_msr_feature_control;
bool has_msr_mcg_ext_ctl;
bool has_msr_misc_enable;
bool has_msr_smbase;
bool has_msr_bndcfgs;
bool has_msr_hv_hypercall;
bool has_msr_hv_crash;
bool has_msr_hv_reset;
bool has_msr_hv_vpindex;
bool has_msr_hv_runtime;
bool has_msr_hv_synic;
bool has_msr_hv_stimer;
bool has_msr_hv_frequencies;
bool has_msr_hv_reenlightenment;
bool has_msr_xss;
bool has_msr_umwait;
bool has_msr_spec_ctrl;
bool has_msr_tsx_ctrl;
bool has_msr_virt_ssbd;
bool has_msr_smi_count;
bool has_msr_arch_capabs;
bool has_msr_core_capabs;
bool has_msr_vmx_vmfunc;

struct kvm_msr_list *kvm_feature_msrs = NULL;

#define CACHE_DESCRIPTOR_UNAVAILABLE 0xFF

/*
 * Known CPUID 2 cache descriptors.
 * From Intel SDM Volume 2A, CPUID instruction
 */
struct CPUID2CacheDescriptorInfo cpuid2_cache_descriptors[] = {
    [0x06] = { .level = 1, .type = INSTRUCTION_CACHE, .size =   8 * KiB,
               .associativity = 4,  .line_size = 32, },
    [0x08] = { .level = 1, .type = INSTRUCTION_CACHE, .size =  16 * KiB,
               .associativity = 4,  .line_size = 32, },
    [0x09] = { .level = 1, .type = INSTRUCTION_CACHE, .size =  32 * KiB,
               .associativity = 4,  .line_size = 64, },
    [0x0A] = { .level = 1, .type = DATA_CACHE,        .size =   8 * KiB,
               .associativity = 2,  .line_size = 32, },
    [0x0C] = { .level = 1, .type = DATA_CACHE,        .size =  16 * KiB,
               .associativity = 4,  .line_size = 32, },
    [0x0D] = { .level = 1, .type = DATA_CACHE,        .size =  16 * KiB,
               .associativity = 4,  .line_size = 64, },
    [0x0E] = { .level = 1, .type = DATA_CACHE,        .size =  24 * KiB,
               .associativity = 6,  .line_size = 64, },
    [0x1D] = { .level = 2, .type = UNIFIED_CACHE,     .size = 128 * KiB,
               .associativity = 2,  .line_size = 64, },
    [0x21] = { .level = 2, .type = UNIFIED_CACHE,     .size = 256 * KiB,
               .associativity = 8,  .line_size = 64, },
    /* lines per sector is not supported cpuid2_cache_descriptor(),
    * so descriptors 0x22, 0x23 are not included
    */
    [0x24] = { .level = 2, .type = UNIFIED_CACHE,     .size =   1 * MiB,
               .associativity = 16, .line_size = 64, },
    /* lines per sector is not supported cpuid2_cache_descriptor(),
    * so descriptors 0x25, 0x20 are not included
    */
    [0x2C] = { .level = 1, .type = DATA_CACHE,        .size =  32 * KiB,
               .associativity = 8,  .line_size = 64, },
    [0x30] = { .level = 1, .type = INSTRUCTION_CACHE, .size =  32 * KiB,
               .associativity = 8,  .line_size = 64, },
    [0x41] = { .level = 2, .type = UNIFIED_CACHE,     .size = 128 * KiB,
               .associativity = 4,  .line_size = 32, },
    [0x42] = { .level = 2, .type = UNIFIED_CACHE,     .size = 256 * KiB,
               .associativity = 4,  .line_size = 32, },
    [0x43] = { .level = 2, .type = UNIFIED_CACHE,     .size = 512 * KiB,
               .associativity = 4,  .line_size = 32, },
    [0x44] = { .level = 2, .type = UNIFIED_CACHE,     .size =   1 * MiB,
               .associativity = 4,  .line_size = 32, },
    [0x45] = { .level = 2, .type = UNIFIED_CACHE,     .size =   2 * MiB,
               .associativity = 4,  .line_size = 32, },
    [0x46] = { .level = 3, .type = UNIFIED_CACHE,     .size =   4 * MiB,
               .associativity = 4,  .line_size = 64, },
    [0x47] = { .level = 3, .type = UNIFIED_CACHE,     .size =   8 * MiB,
               .associativity = 8,  .line_size = 64, },
    [0x48] = { .level = 2, .type = UNIFIED_CACHE,     .size =   3 * MiB,
               .associativity = 12, .line_size = 64, },
    /* Descriptor 0x49 depends on CPU family/model, so it is not included */
    [0x4A] = { .level = 3, .type = UNIFIED_CACHE,     .size =   6 * MiB,
               .associativity = 12, .line_size = 64, },
    [0x4B] = { .level = 3, .type = UNIFIED_CACHE,     .size =   8 * MiB,
               .associativity = 16, .line_size = 64, },
    [0x4C] = { .level = 3, .type = UNIFIED_CACHE,     .size =  12 * MiB,
               .associativity = 12, .line_size = 64, },
    [0x4D] = { .level = 3, .type = UNIFIED_CACHE,     .size =  16 * MiB,
               .associativity = 16, .line_size = 64, },
    [0x4E] = { .level = 2, .type = UNIFIED_CACHE,     .size =   6 * MiB,
               .associativity = 24, .line_size = 64, },
    [0x60] = { .level = 1, .type = DATA_CACHE,        .size =  16 * KiB,
               .associativity = 8,  .line_size = 64, },
    [0x66] = { .level = 1, .type = DATA_CACHE,        .size =   8 * KiB,
               .associativity = 4,  .line_size = 64, },
    [0x67] = { .level = 1, .type = DATA_CACHE,        .size =  16 * KiB,
               .associativity = 4,  .line_size = 64, },
    [0x68] = { .level = 1, .type = DATA_CACHE,        .size =  32 * KiB,
               .associativity = 4,  .line_size = 64, },
    [0x78] = { .level = 2, .type = UNIFIED_CACHE,     .size =   1 * MiB,
               .associativity = 4,  .line_size = 64, },
    /* lines per sector is not supported cpuid2_cache_descriptor(),
    * so descriptors 0x79, 0x7A, 0x7B, 0x7C are not included.
    */
    [0x7D] = { .level = 2, .type = UNIFIED_CACHE,     .size =   2 * MiB,
               .associativity = 8,  .line_size = 64, },
    [0x7F] = { .level = 2, .type = UNIFIED_CACHE,     .size = 512 * KiB,
               .associativity = 2,  .line_size = 64, },
    [0x80] = { .level = 2, .type = UNIFIED_CACHE,     .size = 512 * KiB,
               .associativity = 8,  .line_size = 64, },
    [0x82] = { .level = 2, .type = UNIFIED_CACHE,     .size = 256 * KiB,
               .associativity = 8,  .line_size = 32, },
    [0x83] = { .level = 2, .type = UNIFIED_CACHE,     .size = 512 * KiB,
               .associativity = 8,  .line_size = 32, },
    [0x84] = { .level = 2, .type = UNIFIED_CACHE,     .size =   1 * MiB,
               .associativity = 8,  .line_size = 32, },
    [0x85] = { .level = 2, .type = UNIFIED_CACHE,     .size =   2 * MiB,
               .associativity = 8,  .line_size = 32, },
    [0x86] = { .level = 2, .type = UNIFIED_CACHE,     .size = 512 * KiB,
               .associativity = 4,  .line_size = 64, },
    [0x87] = { .level = 2, .type = UNIFIED_CACHE,     .size =   1 * MiB,
               .associativity = 8,  .line_size = 64, },
    [0xD0] = { .level = 3, .type = UNIFIED_CACHE,     .size = 512 * KiB,
               .associativity = 4,  .line_size = 64, },
    [0xD1] = { .level = 3, .type = UNIFIED_CACHE,     .size =   1 * MiB,
               .associativity = 4,  .line_size = 64, },
    [0xD2] = { .level = 3, .type = UNIFIED_CACHE,     .size =   2 * MiB,
               .associativity = 4,  .line_size = 64, },
    [0xD6] = { .level = 3, .type = UNIFIED_CACHE,     .size =   1 * MiB,
               .associativity = 8,  .line_size = 64, },
    [0xD7] = { .level = 3, .type = UNIFIED_CACHE,     .size =   2 * MiB,
               .associativity = 8,  .line_size = 64, },
    [0xD8] = { .level = 3, .type = UNIFIED_CACHE,     .size =   4 * MiB,
               .associativity = 8,  .line_size = 64, },
    [0xDC] = { .level = 3, .type = UNIFIED_CACHE,     .size = 1.5 * MiB,
               .associativity = 12, .line_size = 64, },
    [0xDD] = { .level = 3, .type = UNIFIED_CACHE,     .size =   3 * MiB,
               .associativity = 12, .line_size = 64, },
    [0xDE] = { .level = 3, .type = UNIFIED_CACHE,     .size =   6 * MiB,
               .associativity = 12, .line_size = 64, },
    [0xE2] = { .level = 3, .type = UNIFIED_CACHE,     .size =   2 * MiB,
               .associativity = 16, .line_size = 64, },
    [0xE3] = { .level = 3, .type = UNIFIED_CACHE,     .size =   4 * MiB,
               .associativity = 16, .line_size = 64, },
    [0xE4] = { .level = 3, .type = UNIFIED_CACHE,     .size =   8 * MiB,
               .associativity = 16, .line_size = 64, },
    [0xEA] = { .level = 3, .type = UNIFIED_CACHE,     .size =  12 * MiB,
               .associativity = 24, .line_size = 64, },
    [0xEB] = { .level = 3, .type = UNIFIED_CACHE,     .size =  18 * MiB,
               .associativity = 24, .line_size = 64, },
    [0xEC] = { .level = 3, .type = UNIFIED_CACHE,     .size =  24 * MiB,
               .associativity = 24, .line_size = 64, },
};


/*
 * Definitions of the hardcoded cache entries we expose:
 * These are legacy cache values. If there is a need to change any
 * of these values please use builtin_x86_defs
 */

/* L1 data cache: */
static CPUCacheInfo legacy_l1d_cache = {
    .type = DATA_CACHE,
    .level = 1,
    .size = 32 * KiB,
    .self_init = 1,
    .line_size = 64,
    .associativity = 8,
    .sets = 64,
    .partitions = 1,
    .no_invd_sharing = true,
};

/*FIXME: CPUID leaf 0x80000005 is inconsistent with leaves 2 & 4 */
static CPUCacheInfo legacy_l1d_cache_amd = {
    .type = DATA_CACHE,
    .level = 1,
    .size = 64 * KiB,
    .self_init = 1,
    .line_size = 64,
    .associativity = 2,
    .sets = 512,
    .partitions = 1,
    .lines_per_tag = 1,
    .no_invd_sharing = true,
};

/* L1 instruction cache: */
static CPUCacheInfo legacy_l1i_cache = {
    .type = INSTRUCTION_CACHE,
    .level = 1,
    .size = 32 * KiB,
    .self_init = 1,
    .line_size = 64,
    .associativity = 8,
    .sets = 64,
    .partitions = 1,
    .no_invd_sharing = true,
};

/*FIXME: CPUID leaf 0x80000005 is inconsistent with leaves 2 & 4 */
static CPUCacheInfo legacy_l1i_cache_amd = {
    .type = INSTRUCTION_CACHE,
    .level = 1,
    .size = 64 * KiB,
    .self_init = 1,
    .line_size = 64,
    .associativity = 2,
    .sets = 512,
    .partitions = 1,
    .lines_per_tag = 1,
    .no_invd_sharing = true,
};

/* Level 2 unified cache: */
static CPUCacheInfo legacy_l2_cache = {
    .type = UNIFIED_CACHE,
    .level = 2,
    .size = 4 * MiB,
    .self_init = 1,
    .line_size = 64,
    .associativity = 16,
    .sets = 4096,
    .partitions = 1,
    .no_invd_sharing = true,
};

/*FIXME: CPUID leaf 2 descriptor is inconsistent with CPUID leaf 4 */
static CPUCacheInfo legacy_l2_cache_cpuid2 = {
    .type = UNIFIED_CACHE,
    .level = 2,
    .size = 2 * MiB,
    .line_size = 64,
    .associativity = 8,
};

/*FIXME: CPUID leaf 0x80000006 is inconsistent with leaves 2 & 4 */
static CPUCacheInfo legacy_l2_cache_amd = {
    .type = UNIFIED_CACHE,
    .level = 2,
    .size = 512 * KiB,
    .line_size = 64,
    .lines_per_tag = 1,
    .associativity = 16,
    .sets = 512,
    .partitions = 1,
};


/* Level 3 unified cache: */
static CPUCacheInfo legacy_l3_cache = {
    .type = UNIFIED_CACHE,
    .level = 3,
    .size = 16 * MiB,
    .line_size = 64,
    .associativity = 16,
    .sets = 16384,
    .partitions = 1,
    .lines_per_tag = 1,
    .self_init = true,
    .inclusive = true,
    .complex_indexing = true,
};


static FeatureWordInfo feature_word_info[FEATURE_WORDS] = {
    [FEAT_1_EDX] = {
        .type = CPUID_FEATURE_WORD,
        .feat_names = {
            "fpu", "vme", "de", "pse",
            "tsc", "msr", "pae", "mce",
            "cx8", "apic", NULL, "sep",
            "mtrr", "pge", "mca", "cmov",
            "pat", "pse36", "pn" /* Intel psn */, "clflush" /* Intel clfsh */,
            NULL, "ds" /* Intel dts */, "acpi", "mmx",
            "fxsr", "sse", "sse2", "ss",
            "ht" /* Intel htt */, "tm", "ia64", "pbe",
        },
        .cpuid = {.eax = 1, .reg = R_EDX, },
    },
    [FEAT_1_ECX] = {
        .type = CPUID_FEATURE_WORD,
        .feat_names = {
            "pni" /* Intel,AMD sse3 */, "pclmulqdq", "dtes64", "monitor",
            "ds-cpl", "vmx", "smx", "est",
            "tm2", "ssse3", "cid", NULL,
            "fma", "cx16", "xtpr", "pdcm",
            NULL, "pcid", "dca", "sse4.1",
            "sse4.2", "x2apic", "movbe", "popcnt",
            "tsc-deadline", "aes", "xsave", NULL /* osxsave */,
            "avx", "f16c", "rdrand", "hypervisor",
        },
        .cpuid = { .eax = 1, .reg = R_ECX, },
    },
    /* Feature names that are already defined on feature_name[] but
     * are set on CPUID[8000_0001].EDX on AMD CPUs don't have their
     * names on feat_names below. They are copied automatically
     * to features[FEAT_8000_0001_EDX] if and only if CPU vendor is AMD.
     */
    [FEAT_8000_0001_EDX] = {
        .type = CPUID_FEATURE_WORD,
        .feat_names = {
            NULL /* fpu */, NULL /* vme */, NULL /* de */, NULL /* pse */,
            NULL /* tsc */, NULL /* msr */, NULL /* pae */, NULL /* mce */,
            NULL /* cx8 */, NULL /* apic */, NULL, "syscall",
            NULL /* mtrr */, NULL /* pge */, NULL /* mca */, NULL /* cmov */,
            NULL /* pat */, NULL /* pse36 */, NULL, NULL /* Linux mp */,
            "nx", NULL, "mmxext", NULL /* mmx */,
            NULL /* fxsr */, "fxsr-opt", "pdpe1gb", "rdtscp",
            NULL, "lm", "3dnowext", "3dnow",
        },
        .cpuid = { .eax = 0x80000001, .reg = R_EDX, },
    },
    [FEAT_8000_0001_ECX] = {
        .type = CPUID_FEATURE_WORD,
        .feat_names = {
            "lahf-lm", "cmp-legacy", "svm", "extapic",
            "cr8legacy", "abm", "sse4a", "misalignsse",
            "3dnowprefetch", "osvw", "ibs", "xop",
            "skinit", "wdt", NULL, "lwp",
            "fma4", "tce", NULL, "nodeid-msr",
            NULL, "tbm", "topoext", "perfctr-core",
            "perfctr-nb", NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        .cpuid = { .eax = 0x80000001, .reg = R_ECX, },
        /*
         * TOPOEXT is always allowed but can't be enabled blindly by
         * "-cpu host", as it requires consistent cache topology info
         * to be provided so it doesn't confuse guests.
         */
        .no_autoenable_flags = CPUID_EXT3_TOPOEXT,
    },
    [FEAT_C000_0001_EDX] = {
        .type = CPUID_FEATURE_WORD,
        .feat_names = {
            NULL, NULL, "xstore", "xstore-en",
            NULL, NULL, "xcrypt", "xcrypt-en",
            "ace2", "ace2-en", "phe", "phe-en",
            "pmm", "pmm-en", NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        .cpuid = { .eax = 0xC0000001, .reg = R_EDX, },
    },
    [FEAT_KVM] = {
        .type = CPUID_FEATURE_WORD,
        .feat_names = {
            "kvmclock", "kvm-nopiodelay", "kvm-mmu", "kvmclock",
            "kvm-asyncpf", "kvm-steal-time", "kvm-pv-eoi", "kvm-pv-unhalt",
            NULL, "kvm-pv-tlb-flush", NULL, "kvm-pv-ipi",
            "kvm-poll-control", "kvm-pv-sched-yield", NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            "kvmclock-stable-bit", NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        .cpuid = { .eax = KVM_CPUID_FEATURES, .reg = R_EAX, },
    },
    [FEAT_KVM_HINTS] = {
        .type = CPUID_FEATURE_WORD,
        .feat_names = {
            "kvm-hint-dedicated", NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        .cpuid = { .eax = KVM_CPUID_FEATURES, .reg = R_EDX, },
        /*
         * KVM hints aren't auto-enabled by -cpu host, they need to be
         * explicitly enabled in the command-line.
         */
        .no_autoenable_flags = ~0U,
    },
    /*
     * .feat_names are commented out for Hyper-V enlightenments because we
     * don't want to have two different ways for enabling them on QEMU command
     * line. Some features (e.g. "hyperv_time", "hyperv_vapic", ...) require
     * enabling several feature bits simultaneously, exposing these bits
     * individually may just confuse guests.
     */
    [FEAT_HYPERV_EAX] = {
        .type = CPUID_FEATURE_WORD,
        .feat_names = {
            NULL /* hv_msr_vp_runtime_access */, NULL /* hv_msr_time_refcount_access */,
            NULL /* hv_msr_synic_access */, NULL /* hv_msr_stimer_access */,
            NULL /* hv_msr_apic_access */, NULL /* hv_msr_hypercall_access */,
            NULL /* hv_vpindex_access */, NULL /* hv_msr_reset_access */,
            NULL /* hv_msr_stats_access */, NULL /* hv_reftsc_access */,
            NULL /* hv_msr_idle_access */, NULL /* hv_msr_frequency_access */,
            NULL /* hv_msr_debug_access */, NULL /* hv_msr_reenlightenment_access */,
            NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        .cpuid = { .eax = 0x40000003, .reg = R_EAX, },
    },
    [FEAT_HYPERV_EBX] = {
        .type = CPUID_FEATURE_WORD,
        .feat_names = {
            NULL /* hv_create_partitions */, NULL /* hv_access_partition_id */,
            NULL /* hv_access_memory_pool */, NULL /* hv_adjust_message_buffers */,
            NULL /* hv_post_messages */, NULL /* hv_signal_events */,
            NULL /* hv_create_port */, NULL /* hv_connect_port */,
            NULL /* hv_access_stats */, NULL, NULL, NULL /* hv_debugging */,
            NULL /* hv_cpu_power_management */, NULL /* hv_configure_profiler */,
            NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        .cpuid = { .eax = 0x40000003, .reg = R_EBX, },
    },
    [FEAT_HYPERV_EDX] = {
        .type = CPUID_FEATURE_WORD,
        .feat_names = {
            NULL /* hv_mwait */, NULL /* hv_guest_debugging */,
            NULL /* hv_perf_monitor */, NULL /* hv_cpu_dynamic_part */,
            NULL /* hv_hypercall_params_xmm */, NULL /* hv_guest_idle_state */,
            NULL, NULL,
            NULL, NULL, NULL /* hv_guest_crash_msr */, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        .cpuid = { .eax = 0x40000003, .reg = R_EDX, },
    },
    [FEAT_HV_RECOMM_EAX] = {
        .type = CPUID_FEATURE_WORD,
        .feat_names = {
            NULL /* hv_recommend_pv_as_switch */,
            NULL /* hv_recommend_pv_tlbflush_local */,
            NULL /* hv_recommend_pv_tlbflush_remote */,
            NULL /* hv_recommend_msr_apic_access */,
            NULL /* hv_recommend_msr_reset */,
            NULL /* hv_recommend_relaxed_timing */,
            NULL /* hv_recommend_dma_remapping */,
            NULL /* hv_recommend_int_remapping */,
            NULL /* hv_recommend_x2apic_msrs */,
            NULL /* hv_recommend_autoeoi_deprecation */,
            NULL /* hv_recommend_pv_ipi */,
            NULL /* hv_recommend_ex_hypercalls */,
            NULL /* hv_hypervisor_is_nested */,
            NULL /* hv_recommend_int_mbec */,
            NULL /* hv_recommend_evmcs */,
            NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        .cpuid = { .eax = 0x40000004, .reg = R_EAX, },
    },
    [FEAT_HV_NESTED_EAX] = {
        .type = CPUID_FEATURE_WORD,
        .cpuid = { .eax = 0x4000000A, .reg = R_EAX, },
    },
    [FEAT_SVM] = {
        .type = CPUID_FEATURE_WORD,
        .feat_names = {
            "npt", "lbrv", "svm-lock", "nrip-save",
            "tsc-scale", "vmcb-clean",  "flushbyasid", "decodeassists",
            NULL, NULL, "pause-filter", NULL,
            "pfthreshold", NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        .cpuid = { .eax = 0x8000000A, .reg = R_EDX, },
    },
    [FEAT_7_0_EBX] = {
        .type = CPUID_FEATURE_WORD,
        .feat_names = {
            "fsgsbase", "tsc-adjust", NULL, "bmi1",
            "hle", "avx2", NULL, "smep",
            "bmi2", "erms", "invpcid", "rtm",
            NULL, NULL, "mpx", NULL,
            "avx512f", "avx512dq", "rdseed", "adx",
            "smap", "avx512ifma", "pcommit", "clflushopt",
            "clwb", "intel-pt", "avx512pf", "avx512er",
            "avx512cd", "sha-ni", "avx512bw", "avx512vl",
        },
        .cpuid = {
            .eax = 7,
            .needs_ecx = true, .ecx = 0,
            .reg = R_EBX,
        },
    },
    [FEAT_7_0_ECX] = {
        .type = CPUID_FEATURE_WORD,
        .feat_names = {
            NULL, "avx512vbmi", "umip", "pku",
            NULL /* ospke */, "waitpkg", "avx512vbmi2", NULL,
            "gfni", "vaes", "vpclmulqdq", "avx512vnni",
            "avx512bitalg", NULL, "avx512-vpopcntdq", NULL,
            "la57", NULL, NULL, NULL,
            NULL, NULL, "rdpid", NULL,
            NULL, "cldemote", NULL, "movdiri",
            "movdir64b", NULL, NULL, NULL,
        },
        .cpuid = {
            .eax = 7,
            .needs_ecx = true, .ecx = 0,
            .reg = R_ECX,
        },
    },
    [FEAT_7_0_EDX] = {
        .type = CPUID_FEATURE_WORD,
        .feat_names = {
            NULL, NULL, "avx512-4vnniw", "avx512-4fmaps",
            NULL, NULL, NULL, NULL,
            NULL, NULL, "md-clear", NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL /* pconfig */, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, "spec-ctrl", "stibp",
            NULL, "arch-capabilities", "core-capability", "ssbd",
        },
        .cpuid = {
            .eax = 7,
            .needs_ecx = true, .ecx = 0,
            .reg = R_EDX,
        },
    },
    [FEAT_7_1_EAX] = {
        .type = CPUID_FEATURE_WORD,
        .feat_names = {
            NULL, NULL, NULL, NULL,
            NULL, "avx512-bf16", NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        .cpuid = {
            .eax = 7,
            .needs_ecx = true, .ecx = 1,
            .reg = R_EAX,
        },
    },
    [FEAT_8000_0007_EDX] = {
        .type = CPUID_FEATURE_WORD,
        .feat_names = {
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            "invtsc", NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        .cpuid = { .eax = 0x80000007, .reg = R_EDX, },
        .unmigratable_flags = 1U << 8, // CPUID_APM_INVTSC,
    },
    [FEAT_8000_0008_EBX] = {
        .type = CPUID_FEATURE_WORD,
        .feat_names = {
            "clzero", NULL, "xsaveerptr", NULL,
            NULL, NULL, NULL, NULL,
            NULL, "wbnoinvd", NULL, NULL,
            "ibpb", NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            "amd-ssbd", "virt-ssbd", "amd-no-ssb", NULL,
            NULL, NULL, NULL, NULL,
        },
        .cpuid = { .eax = 0x80000008, .reg = R_EBX, },
        .unmigratable_flags = 0,
    },
    [FEAT_XSAVE] = {
        .type = CPUID_FEATURE_WORD,
        .feat_names = {
            "xsaveopt", "xsavec", "xgetbv1", "xsaves",
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        .cpuid = {
            .eax = 0xd,
            .needs_ecx = true, .ecx = 1,
            .reg = R_EAX,
        },
    },
    [FEAT_6_EAX] = {
        .type = CPUID_FEATURE_WORD,
        .feat_names = {
            NULL, NULL, "arat", NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        .cpuid = { .eax = 6, .reg = R_EAX, },
    },
    [FEAT_XSAVE_COMP_LO] = {
        .type = CPUID_FEATURE_WORD,
        .cpuid = {
            .eax = 0xD,
            .needs_ecx = true, .ecx = 0,
            .reg = R_EAX,
        },
        .migratable_flags = XSTATE_FP_MASK | XSTATE_SSE_MASK |
            XSTATE_YMM_MASK | XSTATE_BNDREGS_MASK | XSTATE_BNDCSR_MASK |
            XSTATE_OPMASK_MASK | XSTATE_ZMM_Hi256_MASK | XSTATE_Hi16_ZMM_MASK |
            XSTATE_PKRU_MASK,
    },
    [FEAT_XSAVE_COMP_HI] = {
        .type = CPUID_FEATURE_WORD,
        .cpuid = {
            .eax = 0xD,
            .needs_ecx = true, .ecx = 0,
            .reg = R_EDX,
        },
    },
    /*Below are MSR exposed features*/
    [FEAT_ARCH_CAPABILITIES] = {
        .type = MSR_FEATURE_WORD,
        .feat_names = {
            "rdctl-no", "ibrs-all", "rsba", "skip-l1dfl-vmentry",
            "ssb-no", "mds-no", "pschange-mc-no", "tsx-ctrl",
            "taa-no", NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        .msr = {
            .index = MSR_IA32_ARCH_CAPABILITIES,
        },
    },
    [FEAT_CORE_CAPABILITY] = {
        .type = MSR_FEATURE_WORD,
        .feat_names = {
            NULL, NULL, NULL, NULL,
            NULL, "split-lock-detect", NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        .msr = {
            .index = MSR_IA32_CORE_CAPABILITY,
        },
    },

    [FEAT_VMX_PROCBASED_CTLS] = {
        .type = MSR_FEATURE_WORD,
        .feat_names = {
            NULL, NULL, "vmx-vintr-pending", "vmx-tsc-offset",
            NULL, NULL, NULL, "vmx-hlt-exit",
            NULL, "vmx-invlpg-exit", "vmx-mwait-exit", "vmx-rdpmc-exit",
            "vmx-rdtsc-exit", NULL, NULL, "vmx-cr3-load-noexit",
            "vmx-cr3-store-noexit", NULL, NULL, "vmx-cr8-load-exit",
            "vmx-cr8-store-exit", "vmx-flexpriority", "vmx-vnmi-pending", "vmx-movdr-exit",
            "vmx-io-exit", "vmx-io-bitmap", NULL, "vmx-mtf",
            "vmx-msr-bitmap", "vmx-monitor-exit", "vmx-pause-exit", "vmx-secondary-ctls",
        },
        .msr = {
            .index = MSR_IA32_VMX_TRUE_PROCBASED_CTLS,
        }
    },

    [FEAT_VMX_SECONDARY_CTLS] = {
        .type = MSR_FEATURE_WORD,
        .feat_names = {
            "vmx-apicv-xapic", "vmx-ept", "vmx-desc-exit", "vmx-rdtscp-exit",
            "vmx-apicv-x2apic", "vmx-vpid", "vmx-wbinvd-exit", "vmx-unrestricted-guest",
            "vmx-apicv-register", "vmx-apicv-vid", "vmx-ple", "vmx-rdrand-exit",
            "vmx-invpcid-exit", "vmx-vmfunc", "vmx-shadow-vmcs", "vmx-encls-exit",
            "vmx-rdseed-exit", "vmx-pml", NULL, NULL,
            "vmx-xsaves", NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        .msr = {
            .index = MSR_IA32_VMX_PROCBASED_CTLS2,
        }
    },

    [FEAT_VMX_PINBASED_CTLS] = {
        .type = MSR_FEATURE_WORD,
        .feat_names = {
            "vmx-intr-exit", NULL, NULL, "vmx-nmi-exit",
            NULL, "vmx-vnmi", "vmx-preemption-timer", "vmx-posted-intr",
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        .msr = {
            .index = MSR_IA32_VMX_TRUE_PINBASED_CTLS,
        }
    },

    [FEAT_VMX_EXIT_CTLS] = {
        .type = MSR_FEATURE_WORD,
        /*
         * VMX_VM_EXIT_HOST_ADDR_SPACE_SIZE is copied from
         * the LM CPUID bit.
         */
        .feat_names = {
            NULL, NULL, "vmx-exit-nosave-debugctl", NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL /* vmx-exit-host-addr-space-size */, NULL, NULL,
            "vmx-exit-load-perf-global-ctrl", NULL, NULL, "vmx-exit-ack-intr",
            NULL, NULL, "vmx-exit-save-pat", "vmx-exit-load-pat",
            "vmx-exit-save-efer", "vmx-exit-load-efer",
                "vmx-exit-save-preemption-timer", "vmx-exit-clear-bndcfgs",
            NULL, "vmx-exit-clear-rtit-ctl", NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        .msr = {
            .index = MSR_IA32_VMX_TRUE_EXIT_CTLS,
        }
    },

    [FEAT_VMX_ENTRY_CTLS] = {
        .type = MSR_FEATURE_WORD,
        .feat_names = {
            NULL, NULL, "vmx-entry-noload-debugctl", NULL,
            NULL, NULL, NULL, NULL,
            NULL, "vmx-entry-ia32e-mode", NULL, NULL,
            NULL, "vmx-entry-load-perf-global-ctrl", "vmx-entry-load-pat", "vmx-entry-load-efer",
            "vmx-entry-load-bndcfgs", NULL, "vmx-entry-load-rtit-ctl", NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        .msr = {
            .index = MSR_IA32_VMX_TRUE_ENTRY_CTLS,
        }
    },

    [FEAT_VMX_MISC] = {
        .type = MSR_FEATURE_WORD,
        .feat_names = {
            NULL, NULL, NULL, NULL,
            NULL, "vmx-store-lma", "vmx-activity-hlt", "vmx-activity-shutdown",
            "vmx-activity-wait-sipi", NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, "vmx-vmwrite-vmexit-fields", "vmx-zero-len-inject", NULL,
        },
        .msr = {
            .index = MSR_IA32_VMX_MISC,
        }
    },

    [FEAT_VMX_EPT_VPID_CAPS] = {
        .type = MSR_FEATURE_WORD,
        .feat_names = {
            "vmx-ept-execonly", NULL, NULL, NULL,
            NULL, NULL, "vmx-page-walk-4", "vmx-page-walk-5",
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            "vmx-ept-2mb", "vmx-ept-1gb", NULL, NULL,
            "vmx-invept", "vmx-eptad", "vmx-ept-advanced-exitinfo", NULL,
            NULL, "vmx-invept-single-context", "vmx-invept-all-context", NULL,
            NULL, NULL, NULL, NULL,
            "vmx-invvpid", NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            "vmx-invvpid-single-addr", "vmx-invept-single-context",
                "vmx-invvpid-all-context", "vmx-invept-single-context-noglobals",
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        .msr = {
            .index = MSR_IA32_VMX_EPT_VPID_CAP,
        }
    },

    [FEAT_VMX_BASIC] = {
        .type = MSR_FEATURE_WORD,
        .feat_names = {
            [54] = "vmx-ins-outs",
            [55] = "vmx-true-ctls",
        },
        .msr = {
            .index = MSR_IA32_VMX_BASIC,
        },
        /* Just to be safe - we don't support setting the MSEG version field.  */
        .no_autoenable_flags = MSR_VMX_BASIC_DUAL_MONITOR,
    },

    [FEAT_VMX_VMFUNC] = {
        .type = MSR_FEATURE_WORD,
        .feat_names = {
            [0] = "vmx-eptp-switching",
        },
        .msr = {
            .index = MSR_IA32_VMX_VMFUNC,
        }
    },

};

static FeatureDep feature_dependencies[] = {
    {
        .from = { FEAT_7_0_EDX,             CPUID_7_0_EDX_ARCH_CAPABILITIES },
        .to = { FEAT_ARCH_CAPABILITIES,     ~0ull },
    },
    {
        .from = { FEAT_7_0_EDX,             CPUID_7_0_EDX_CORE_CAPABILITY },
        .to = { FEAT_CORE_CAPABILITY,       ~0ull },
    },
    {
        .from = { FEAT_1_ECX,               CPUID_EXT_VMX },
        .to = { FEAT_VMX_PROCBASED_CTLS,    ~0ull },
    },
    {
        .from = { FEAT_1_ECX,               CPUID_EXT_VMX },
        .to = { FEAT_VMX_PINBASED_CTLS,     ~0ull },
    },
    {
        .from = { FEAT_1_ECX,               CPUID_EXT_VMX },
        .to = { FEAT_VMX_EXIT_CTLS,         ~0ull },
    },
    {
        .from = { FEAT_1_ECX,               CPUID_EXT_VMX },
        .to = { FEAT_VMX_ENTRY_CTLS,        ~0ull },
    },
    {
        .from = { FEAT_1_ECX,               CPUID_EXT_VMX },
        .to = { FEAT_VMX_MISC,              ~0ull },
    },
    {
        .from = { FEAT_1_ECX,               CPUID_EXT_VMX },
        .to = { FEAT_VMX_BASIC,             ~0ull },
    },
    {
        .from = { FEAT_8000_0001_EDX,       CPUID_EXT2_LM },
        .to = { FEAT_VMX_ENTRY_CTLS,        VMX_VM_ENTRY_IA32E_MODE },
    },
    {
        .from = { FEAT_VMX_PROCBASED_CTLS,  VMX_CPU_BASED_ACTIVATE_SECONDARY_CONTROLS },
        .to = { FEAT_VMX_SECONDARY_CTLS,    ~0ull },
    },
    {
        .from = { FEAT_XSAVE,               CPUID_XSAVE_XSAVES },
        .to = { FEAT_VMX_SECONDARY_CTLS,    VMX_SECONDARY_EXEC_XSAVES },
    },
    {
        .from = { FEAT_1_ECX,               CPUID_EXT_RDRAND },
        .to = { FEAT_VMX_SECONDARY_CTLS,    VMX_SECONDARY_EXEC_RDRAND_EXITING },
    },
    {
        .from = { FEAT_7_0_EBX,             CPUID_7_0_EBX_INVPCID },
        .to = { FEAT_VMX_SECONDARY_CTLS,    VMX_SECONDARY_EXEC_ENABLE_INVPCID },
    },
    {
        .from = { FEAT_7_0_EBX,             CPUID_7_0_EBX_RDSEED },
        .to = { FEAT_VMX_SECONDARY_CTLS,    VMX_SECONDARY_EXEC_RDSEED_EXITING },
    },
    {
        .from = { FEAT_8000_0001_EDX,       CPUID_EXT2_RDTSCP },
        .to = { FEAT_VMX_SECONDARY_CTLS,    VMX_SECONDARY_EXEC_RDTSCP },
    },
    {
        .from = { FEAT_VMX_SECONDARY_CTLS,  VMX_SECONDARY_EXEC_ENABLE_EPT },
        .to = { FEAT_VMX_EPT_VPID_CAPS,     0xffffffffull },
    },
    {
        .from = { FEAT_VMX_SECONDARY_CTLS,  VMX_SECONDARY_EXEC_ENABLE_EPT },
        .to = { FEAT_VMX_SECONDARY_CTLS,    VMX_SECONDARY_EXEC_UNRESTRICTED_GUEST },
    },
    {
        .from = { FEAT_VMX_SECONDARY_CTLS,  VMX_SECONDARY_EXEC_ENABLE_VPID },
        .to = { FEAT_VMX_EPT_VPID_CAPS,     0xffffffffull << 32 },
    },
    {
        .from = { FEAT_VMX_SECONDARY_CTLS,  VMX_SECONDARY_EXEC_ENABLE_VMFUNC },
        .to = { FEAT_VMX_VMFUNC,            ~0ull },
    },
};

static const ExtSaveArea x86_ext_save_areas[] = {
    [XSTATE_FP_BIT] = {
        /* x87 FP state component is always enabled if XSAVE is supported */
        .feature = FEAT_1_ECX, .bits = CPUID_EXT_XSAVE,
        /* x87 state is in the legacy region of the XSAVE area */
        .offset = 0,
        .size = 512 + sizeof(X86XSaveHeader),
    },
    [XSTATE_SSE_BIT] = {
        /* SSE state component is always enabled if XSAVE is supported */
        .feature = FEAT_1_ECX, .bits = CPUID_EXT_XSAVE,
        /* SSE state is in the legacy region of the XSAVE area */
        .offset = 0,
        .size = 512 + sizeof(X86XSaveHeader),
    },
    [XSTATE_YMM_BIT] =
          { .feature = FEAT_1_ECX, .bits = CPUID_EXT_AVX,
            .offset = offsetof(X86XSaveArea, avx_state),
            .size = sizeof(XSaveAVX) },
    [XSTATE_BNDREGS_BIT] =
          { .feature = FEAT_7_0_EBX, .bits = CPUID_7_0_EBX_MPX,
            .offset = offsetof(X86XSaveArea, bndreg_state),
            .size = sizeof(XSaveBNDREG)  },
    [XSTATE_BNDCSR_BIT] =
          { .feature = FEAT_7_0_EBX, .bits = CPUID_7_0_EBX_MPX,
            .offset = offsetof(X86XSaveArea, bndcsr_state),
            .size = sizeof(XSaveBNDCSR)  },
    [XSTATE_OPMASK_BIT] =
          { .feature = FEAT_7_0_EBX, .bits = CPUID_7_0_EBX_AVX512F,
            .offset = offsetof(X86XSaveArea, opmask_state),
            .size = sizeof(XSaveOpmask) },
    [XSTATE_ZMM_Hi256_BIT] =
          { .feature = FEAT_7_0_EBX, .bits = CPUID_7_0_EBX_AVX512F,
            .offset = offsetof(X86XSaveArea, zmm_hi256_state),
            .size = sizeof(XSaveZMM_Hi256) },
    [XSTATE_Hi16_ZMM_BIT] =
          { .feature = FEAT_7_0_EBX, .bits = CPUID_7_0_EBX_AVX512F,
            .offset = offsetof(X86XSaveArea, hi16_zmm_state),
            .size = sizeof(XSaveHi16_ZMM) },
    [XSTATE_PKRU_BIT] =
          { .feature = FEAT_7_0_ECX, .bits = CPUID_7_0_ECX_PKU,
            .offset = offsetof(X86XSaveArea, pkru_state),
            .size = sizeof(XSavePKRU) },
};


static void host_cpuid(uint32_t function, uint32_t count,
                uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
{
    uint32_t vec[4];

    asm volatile("cpuid"
                 : "=a"(vec[0]), "=b"(vec[1]),
                   "=c"(vec[2]), "=d"(vec[3])
                 : "0"(function), "c"(count) : "cc");

    if (eax)
        *eax = vec[0];
    if (ebx)
        *ebx = vec[1];
    if (ecx)
        *ecx = vec[2];
    if (edx)
        *edx = vec[3];
}

static void x86_cpu_vendor_words2str(char *dst, uint32_t vendor1,
                                     uint32_t vendor2, uint32_t vendor3)
{
    int i;
    for (i = 0; i < 4; i++) {
        dst[i] = vendor1 >> (8 * i);
        dst[i + 4] = vendor2 >> (8 * i);
        dst[i + 8] = vendor3 >> (8 * i);
    }
    dst[CPUID_VENDOR_SZ] = '\0';
}

static void host_vendor_fms(char *vendor, int *family, int *model, int *stepping)
{
    uint32_t eax, ebx, ecx, edx;

    host_cpuid(0x0, 0, &eax, &ebx, &ecx, &edx);
    x86_cpu_vendor_words2str(vendor, ebx, edx, ecx);

    host_cpuid(0x1, 0, &eax, &ebx, &ecx, &edx);
    if (family) {
        *family = ((eax >> 8) & 0x0F) + ((eax >> 20) & 0xFF);
    }
    if (model) {
        *model = ((eax >> 4) & 0x0F) | ((eax & 0xF0000) >> 12);
    }
    if (stepping) {
        *stepping = eax & 0x0F;
    }
}

static int cpu_x86_fill_model_id(char *str)
{
    uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;
    int i;

    for (i = 0; i < 3; i++) {
        host_cpuid(0x80000002 + i, 0, &eax, &ebx, &ecx, &edx);
        memcpy(str + i * 16 +  0, &eax, 4);
        memcpy(str + i * 16 +  4, &ebx, 4);
        memcpy(str + i * 16 +  8, &ecx, 4);
        memcpy(str + i * 16 + 12, &edx, 4);
    }
    return 0;
}

/* Run KVM_GET_SUPPORTED_CPUID ioctl(), allocating a buffer large enough
 * for all entries.
 */
/* Find matching entry for function/index on kvm_cpuid2 struct
 */ 
static struct kvm_cpuid_entry2 *cpuid_find_entry(struct kvm_cpuid2 *cpuid,
                                                 uint32_t function,
                                                 uint32_t index)
{
    int i; 
    for (i = 0; i < cpuid->nent; ++i) {
        if (cpuid->entries[i].function == function &&
            cpuid->entries[i].index == index) {
            return &cpuid->entries[i];
        }
    }
    /* not found: */
    return NULL; 
}

static struct kvm_cpuid_entry2 *cpuid_find_entry_arch(struct kvm_vcpu_arch *arch,
                                                 uint32_t function,
                                                 uint32_t index)
{
    int i; 
    for (i = 0; i < arch->cpuid_nent; ++i) {
        if (arch->cpuid_entries[i].function == function &&
            arch->cpuid_entries[i].index == index) {
            return &arch->cpuid_entries[i];
        }
    }
    /* not found: */
    return NULL; 
}

/* Returns the value for a specific register on the cpuid entry
 */
static uint32_t cpuid_entry_get_reg(struct kvm_cpuid_entry2 *entry, int reg)
{
    uint32_t ret = 0;
    switch (reg) {
    case R_EAX:
        ret = entry->eax;
        break;
    case R_EBX:
        ret = entry->ebx;
        break;
    case R_ECX:
        ret = entry->ecx;
        break;
    case R_EDX:
        ret = entry->edx;
        break;
    }
    return ret;
}

static bool host_tsx_blacklisted(void)
{
    int family, model, stepping;\
    char vendor[CPUID_VENDOR_SZ + 1];

    host_vendor_fms(vendor, &family, &model, &stepping);

    /* Check if we are running on a Haswell host known to have broken TSX */
    return !strcmp(vendor, "GenuineIntel") &&
           (family == 6) &&
           ((model == 63 && stepping < 4) ||
            model == 60 || model == 69 || model == 70);
}

uint32_t kvm_arch_get_supported_cpuid(uint32_t function,
                                      uint32_t index, int reg) 
{
    struct kvm_cpuid2 *cpuid;
    uint32_t ret = 0; 
    uint32_t cpuid_1_edx;
    bool found = false;
    struct kvm_cpuid_entry2 *entry;

    cpuid = get_supported_cpuid();
	BUG_ON(cpuid == NULL);

	entry = cpuid_find_entry(cpuid, function, index);
    if (entry) {
        found = true;
        ret = cpuid_entry_get_reg(entry, reg);
    }    

    /* Fixups for the data returned by KVM, below */
 	if (function == 1 && reg == R_EDX) {
        /* KVM before 2.6.30 misreports the following features */
        ret |= F(MTRR) | F(PAT) | F(MCE) | F(MCA);
    } else if (function == 1 && reg == R_ECX) {
        /* We can set the hypervisor flag, even if KVM does not return it on
         * GET_SUPPORTED_CPUID
         */
        ret |= 1U << 31; //CPUID_EXT_HYPERVISOR bit
        /* tsc-deadline flag is not returned by GET_SUPPORTED_CPUID, but it
         * can be enabled if the kernel has KVM_CAP_TSC_DEADLINE_TIMER,
         * and the irqchip is in the kernel.
         */
        ret |= 1U << 24; //CPUID_EXT_TSC_DEADLINE_TIMER bit
    } else if (function == 6 && reg == R_EAX) {
        ret |= 1U << 2; //CPUID_6_EAX_ARAT bit /* safe to allow because of emulated APIC */
    } else if (function == 7 && index == 0 && reg == R_EBX) {
        if (host_tsx_blacklisted()) {
            ret &= ~((1U << 11) | (1U << 4));// ~(CPUID_7_0_EBX_RTM | CPUID_7_0_EBX_HLE);
        }
    } else if (function == 7 && index == 0 && reg == R_ECX) {
        ret &= ~(1U << 5); //CPUID_7_0_ECX_WAITPKG;
    } else if (function == 0x80000001 && reg == R_ECX) {
        /*
         * It's safe to enable TOPOEXT even if it's not returned by
         * GET_SUPPORTED_CPUID.  Unconditionally enabling TOPOEXT here allows
         * us to keep CPU models including TOPOEXT runnable on older kernels.
         */
        ret |= CPUID_EXT3_TOPOEXT;
    } else if (function == 0x80000001 && reg == R_EDX) {
        /* On Intel, kvm returns cpuid according to the Intel spec,
         * so add missing bits according to the AMD spec:
         */
        cpuid_1_edx = kvm_arch_get_supported_cpuid(1, 0, R_EDX);
        ret |= cpuid_1_edx & CPUID_EXT2_AMD_ALIASES;
    } else if (function == KVM_CPUID_FEATURES && reg == R_EDX) {
        ret |= 1U << 0; // KVM_HINTS_REALTIME;
        found = 1;
    }

    /* fallback for older kernels */
    if ((function == KVM_CPUID_FEATURES) && !found) {
        ret = (1 << KVM_FEATURE_CLOCKSOURCE) |
			(1 << KVM_FEATURE_NOP_IO_DELAY) |
			(1 << KVM_FEATURE_ASYNC_PF);
    }

    return ret;
}

static uint32_t xsave_area_size(uint64_t mask)
{
    int i;
    uint64_t ret = 0;

    for (i = 0; i < ARRAY_SIZE(x86_ext_save_areas); i++) {
        const ExtSaveArea *esa = &x86_ext_save_areas[i];
        if ((mask >> i) & 1) {
            ret = MAX(ret, esa->offset + esa->size);
        }
    }
    return ret;
}

static uint64_t x86_cpu_get_migratable_flags(FeatureWord w)
{
    FeatureWordInfo *wi = &feature_word_info[w];
    uint64_t r = 0;
    int i;

    for (i = 0; i < 64; i++) {
        uint64_t f = 1ULL << i;

        /* If the feature name is known, it is implicitly considered migratable,
         * unless it is explicitly set in unmigratable_flags */
        if ((wi->migratable_flags & f) ||
            (wi->feat_names[i] && !(wi->unmigratable_flags & f))) {
            r |= f;
        }
    }
    return r;
}

uint64_t kvm_arch_get_supported_msr_feature(uint32_t index)
{
    int i;
    uint64_t value;
    uint32_t can_be_one, must_be_one;

    if (kvm_feature_msrs == NULL) { /* Host doesn't support feature MSRs */
        return 0;
    }
    /* Check if requested MSR is supported feature MSR */
    for (i = 0; i < kvm_feature_msrs->nmsrs; i++)
        if (kvm_feature_msrs->indices[i] == index) {
            break;
        }

    if (i == kvm_feature_msrs->nmsrs) {
        return 0; /* if the feature MSR is not supported, simply return 0 */
    }

	do_get_msr_feature(NULL, index, &value);

    switch (index) {
    case MSR_IA32_VMX_PROCBASED_CTLS2:
        /* KVM forgot to add these bits for some time, do this ourselves.  */
        if (kvm_arch_get_supported_cpuid(0xD, 1, R_ECX) & CPUID_XSAVE_XSAVES) {
            value |= (uint64_t)VMX_SECONDARY_EXEC_XSAVES << 32;
        }
        if (kvm_arch_get_supported_cpuid(1, 0, R_ECX) & CPUID_EXT_RDRAND) {
            value |= (uint64_t)VMX_SECONDARY_EXEC_RDRAND_EXITING << 32;
        }
        if (kvm_arch_get_supported_cpuid(7, 0, R_EBX) & CPUID_7_0_EBX_INVPCID) {
            value |= (uint64_t)VMX_SECONDARY_EXEC_ENABLE_INVPCID << 32;
        }
        if (kvm_arch_get_supported_cpuid(7, 0, R_EBX) & CPUID_7_0_EBX_RDSEED) {
            value |= (uint64_t)VMX_SECONDARY_EXEC_RDSEED_EXITING << 32;
        }
        if (kvm_arch_get_supported_cpuid(0x80000001, 0, R_EDX) & CPUID_EXT2_RDTSCP) {
            value |= (uint64_t)VMX_SECONDARY_EXEC_RDTSCP << 32;
        }

        /* fall through */
    case MSR_IA32_VMX_TRUE_PINBASED_CTLS:
    case MSR_IA32_VMX_TRUE_PROCBASED_CTLS:
    case MSR_IA32_VMX_TRUE_ENTRY_CTLS:
    case MSR_IA32_VMX_TRUE_EXIT_CTLS:
        /*
         * Return true for bits that can be one, but do not have to be one.
         * The SDM tells us which bits could have a "must be one" setting,
         * so we can do the opposite transformation in make_vmx_msr_value.
         */
        must_be_one = (uint32_t)value;
        can_be_one = (uint32_t)(value >> 32);
        return can_be_one & ~must_be_one;

    default:
        return value;
    }

	return 0;
}


static uint64_t x86_cpu_get_supported_feature_word(FeatureWord w,
                                                   bool migratable_only)
{                                                  
    FeatureWordInfo *wi = &feature_word_info[w];
    uint64_t r = 0; 
    
    switch (wi->type) {
    case CPUID_FEATURE_WORD:
        r = kvm_arch_get_supported_cpuid(wi->cpuid.eax,
                                                        wi->cpuid.ecx,
                                                        wi->cpuid.reg);
        break;                                          
    case MSR_FEATURE_WORD:
        r = kvm_arch_get_supported_msr_feature(wi->msr.index);
        break;
    }

    if (migratable_only) {
        r &= x86_cpu_get_migratable_flags(w);
    }

    return r;
}

/* Calculate XSAVE components based on the configured CPU feature flags */
static void x86_cpu_enable_xsave_components(CPUX86State *env)
{
    int i;
    uint64_t mask;

    if (!(env->features[FEAT_1_ECX] & CPUID_EXT_XSAVE)) {
        return;
    }

    mask = 0;
    for (i = 0; i < ARRAY_SIZE(x86_ext_save_areas); i++) {
        const ExtSaveArea *esa = &x86_ext_save_areas[i];
        if (env->features[esa->feature] & esa->bits) {
            mask |= (1ULL << i);
        }
    }

    env->features[FEAT_XSAVE_COMP_LO] = mask;
    env->features[FEAT_XSAVE_COMP_HI] = mask >> 32;
}

static void x86_cpu_adjust_level(uint32_t *min, uint32_t value)
{
    if (*min < value) {
        *min = value;
    }
}

static void x86_cpu_adjust_feat_level(CPUX86State *env, FeatureWord w)
{
    FeatureWordInfo *fi = &feature_word_info[w];
    uint32_t eax = fi->cpuid.eax;
    uint32_t region = eax & 0xF0000000;

    if (!env->features[w]) {
        return;
    }

    switch (region) {
    case 0x00000000:
        x86_cpu_adjust_level(&env->cpuid_min_level, eax);
    break;
    case 0x80000000:
        x86_cpu_adjust_level(&env->cpuid_min_xlevel, eax);
    break;
    case 0xC0000000:
        x86_cpu_adjust_level(&env->cpuid_min_xlevel2, eax);
    break;
    }

    if (eax == 7) {
        x86_cpu_adjust_level(&env->cpuid_min_level_func7,
                             fi->cpuid.ecx);
    }
}


static void x86_cpu_expand_features(CPUX86State *env)
{
    FeatureWord w;
    int i;

    /*TODO: Now cpu->max_features doesn't overwrite features
     * set using QOM properties, and we can convert
     * plus_features & minus_features to global properties
     * inside x86_cpu_parse_featurestr() too.
     */
    for (w = 0; w < FEATURE_WORDS; w++) {
            /* Override only features that weren't set explicitly
             * by the user.
             */
        env->features[w] |=
                x86_cpu_get_supported_feature_word(w, true) &
                ~env->user_features[w] &
                ~feature_word_info[w].no_autoenable_flags;
    }

    for (i = 0; i < ARRAY_SIZE(feature_dependencies); i++) {
        FeatureDep *d = &feature_dependencies[i];
        if (!(env->features[d->from.index] & d->from.mask)) {
            uint64_t unavailable_features = env->features[d->to.index] & d->to.mask;

            /* Not an error unless the dependent feature was added explicitly.  */
    		env->features[d->to.index] &=
				~(unavailable_features & env->user_features[d->to.index]);

            env->user_features[d->to.index] |= unavailable_features;
            env->features[d->to.index] &= ~unavailable_features;
        }
    }

    x86_cpu_enable_xsave_components(env);

    /* CPUID[EAX=7,ECX=0].EBX always increased level automatically: */
    x86_cpu_adjust_feat_level(env, FEAT_7_0_EBX);
    x86_cpu_adjust_feat_level(env, FEAT_1_EDX);
    x86_cpu_adjust_feat_level(env, FEAT_1_ECX);
    x86_cpu_adjust_feat_level(env, FEAT_6_EAX);
    x86_cpu_adjust_feat_level(env, FEAT_7_0_ECX);
    x86_cpu_adjust_feat_level(env, FEAT_7_1_EAX);
    x86_cpu_adjust_feat_level(env, FEAT_8000_0001_EDX);
    x86_cpu_adjust_feat_level(env, FEAT_8000_0001_ECX);
    x86_cpu_adjust_feat_level(env, FEAT_8000_0007_EDX);
    x86_cpu_adjust_feat_level(env, FEAT_8000_0008_EBX);
    x86_cpu_adjust_feat_level(env, FEAT_C000_0001_EDX);
    x86_cpu_adjust_feat_level(env, FEAT_SVM);
    x86_cpu_adjust_feat_level(env, FEAT_XSAVE);

    /* Intel Processor Trace requires CPUID[0x14] */
    if ((env->features[FEAT_7_0_EBX] & CPUID_7_0_EBX_INTEL_PT)) {
        x86_cpu_adjust_level(&env->cpuid_min_level, 0x14);
    }

    /* SVM requires CPUID[0x8000000A] */
    if (env->features[FEAT_8000_0001_ECX] & CPUID_EXT3_SVM) {
        x86_cpu_adjust_level(&env->cpuid_min_xlevel, 0x8000000A);
    }

    /* Set cpuid_*level* based on cpuid_min_*level, if not explicitly set */
    env->cpuid_level_func7 = env->cpuid_min_level_func7;
    env->cpuid_level = env->cpuid_min_level;
    env->cpuid_xlevel = env->cpuid_min_xlevel;
    env->cpuid_xlevel2 = env->cpuid_min_xlevel2;
}

static void x86_cpu_filter_features(CPUX86State *env)
{
    FeatureWord w;

    for (w = 0; w < FEATURE_WORDS; w++) {
        uint64_t host_feat =
            x86_cpu_get_supported_feature_word(w, false);
        uint64_t requested_features = env->features[w];
        uint64_t unavailable_features = requested_features & ~host_feat;
		env->features[w] &= ~unavailable_features;
    }

    if ((env->features[FEAT_7_0_EBX] & CPUID_7_0_EBX_INTEL_PT)) {
        uint32_t eax_0 = kvm_arch_get_supported_cpuid(0x14, 0, R_EAX);
        uint32_t ebx_0 = kvm_arch_get_supported_cpuid(0x14, 0, R_EBX);
        uint32_t ecx_0 = kvm_arch_get_supported_cpuid(0x14, 0, R_ECX);
        uint32_t eax_1 = kvm_arch_get_supported_cpuid(0x14, 1, R_EAX);
        uint32_t ebx_1 = kvm_arch_get_supported_cpuid(0x14, 1, R_EBX);

        if (!eax_0 ||
           ((ebx_0 & INTEL_PT_MINIMAL_EBX) != INTEL_PT_MINIMAL_EBX) ||
           ((ecx_0 & INTEL_PT_MINIMAL_ECX) != INTEL_PT_MINIMAL_ECX) ||
           ((eax_1 & INTEL_PT_MTC_BITMAP) != INTEL_PT_MTC_BITMAP) ||
           ((eax_1 & INTEL_PT_ADDR_RANGES_NUM_MASK) <
                                           INTEL_PT_ADDR_RANGES_NUM) ||
           ((ebx_1 & (INTEL_PT_PSB_BITMAP | INTEL_PT_CYCLE_BITMAP)) !=
                (INTEL_PT_PSB_BITMAP | INTEL_PT_CYCLE_BITMAP)) ||
           (ecx_0 & INTEL_PT_IP_LIP)) {
            /*
             * Processor Trace capabilities aren't configurable, so if the
             * host can't emulate the capabilities we report on
             * cpu_x86_cpuid(), intel-pt can't be enabled on the current host.
             */
			env->features[FEAT_7_0_EBX] &= ~CPUID_7_0_EBX_INTEL_PT;
        }
    }
}

static void mce_init(CPUX86State *env)
{
    unsigned int bank;

    if (((env->cpuid_version >> 8) & 0xf) >= 6
        && (env->features[FEAT_1_EDX] & (CPUID_MCE | CPUID_MCA)) ==
            (CPUID_MCE | CPUID_MCA)) {
        env->mcg_cap = MCE_CAP_DEF | MCE_BANKS_DEF |
                        (MCG_LMCE_P);
        env->mcg_ctl = ~(uint64_t)0;
        for (bank = 0; bank < MCE_BANKS_DEF; bank++) {
            env->mce_banks[bank * 4] = ~(uint64_t)0;
        }
    }
}

static int nodes_in_socket(int nr_cores)
{
    int nodes;

    nodes = DIV_ROUND_UP(nr_cores, MAX_CORES_IN_NODE);

   /* Hardware does not support config with 3 nodes, return 4 in that case */
    return (nodes == 3) ? 4 : nodes;
}

static int cores_in_core_complex(int nr_cores)
{
    int nodes;

    /* Check if we can fit all the cores in one core complex */
    if (nr_cores <= MAX_CORES_IN_CCX) {
        return nr_cores;
    }
    /* Get the number of nodes required to build this config */
    nodes = nodes_in_socket(nr_cores);

    /*
     * Divide the cores accros all the core complexes
     * Return rounded up value
     */
    return DIV_ROUND_UP(nr_cores, nodes * MAX_CCX);
}

/* Encode cache info for CPUID[8000001D] */
static void encode_cache_cpuid8000001d(CPUCacheInfo *cache, CPUX86State *env, 
                                uint32_t *eax, uint32_t *ebx,
                                uint32_t *ecx, uint32_t *edx)
{
    uint32_t l3_cores;

    *eax = CACHE_TYPE(cache->type) | CACHE_LEVEL(cache->level) |
               (cache->self_init ? CACHE_SELF_INIT_LEVEL : 0);

    /* L3 is shared among multiple cores */
    if (cache->level == 3) { 
        l3_cores = cores_in_core_complex(env->nr_cores);
        *eax |= ((l3_cores * env->nr_threads) - 1) << 14;
    } else {
        *eax |= ((env->nr_threads - 1) << 14); 
    }    

    *ebx = (cache->line_size - 1) |
           ((cache->partitions - 1) << 12) |
           ((cache->associativity - 1) << 22);

    *ecx = cache->sets - 1;

    *edx = (cache->no_invd_sharing ? CACHE_NO_INVD_SHARING : 0) |
           (cache->inclusive ? CACHE_INCLUSIVE : 0) |
           (cache->complex_indexing ? CACHE_COMPLEX_IDX : 0);
}

static void build_core_topology(int nr_cores, int core_id,
                                struct core_topology *topo)
{
    int nodes, cores_in_ccx;

    /* First get the number of nodes required */
    nodes = nodes_in_socket(nr_cores);

    cores_in_ccx = cores_in_core_complex(nr_cores);

    topo->node_id = core_id / (cores_in_ccx * MAX_CCX);
    topo->ccx_id = (core_id % (cores_in_ccx * MAX_CCX)) / cores_in_ccx;
    topo->core_id = core_id % cores_in_ccx;
    topo->num_nodes = nodes;
}

static void encode_topo_cpuid8000001e(CPUX86State *env,
                                       uint32_t *eax, uint32_t *ebx,
                                       uint32_t *ecx, uint32_t *edx)
{
    struct core_topology topo = {0};
    unsigned long nodes;
    int shift;

    build_core_topology(env->nr_cores, env->core_id, &topo);
    *eax = env->apic_id;

    if (env->nr_threads - 1) {
        *ebx = ((env->nr_threads - 1) << 8) | (topo.node_id << 3) |
                (topo.ccx_id << 2) | topo.core_id;
    } else {
        *ebx = (topo.node_id << 4) | (topo.ccx_id << 3) | topo.core_id;
    }
    if (topo.num_nodes <= 4) {
        *ecx = ((topo.num_nodes - 1) << 8) | (env->socket_id << 2) |
                topo.node_id;
    } else {
        nodes = topo.num_nodes - 1;
        shift = find_last_bit(&nodes, 8);
        *ecx = ((topo.num_nodes - 1) << 8) | (env->socket_id << (shift + 1)) |
                topo.node_id;
    }
    *edx = 0;
}



static uint8_t cpuid2_cache_descriptor(CPUCacheInfo *cache)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(cpuid2_cache_descriptors); i++) {
        struct CPUID2CacheDescriptorInfo *d = &cpuid2_cache_descriptors[i];
        if (d->level == cache->level && d->type == cache->type &&
            d->size == cache->size && d->line_size == cache->line_size &&
            d->associativity == cache->associativity) {
                return i;
            }
    }

    return CACHE_DESCRIPTOR_UNAVAILABLE;
}

static void encode_cache_cpuid4(CPUCacheInfo *cache,
                                int num_apic_ids, int num_cores,
                                uint32_t *eax, uint32_t *ebx,
                                uint32_t *ecx, uint32_t *edx)
{                               
    *eax = CACHE_TYPE(cache->type) |
           CACHE_LEVEL(cache->level) |
           (cache->self_init ? CACHE_SELF_INIT_LEVEL : 0) |
           ((num_cores - 1) << 26) |
           ((num_apic_ids - 1) << 14);
           
    /* We don't implement fully-associative caches */
    *ebx = (cache->line_size - 1) |
           ((cache->partitions - 1) << 12) |
           ((cache->associativity - 1) << 22);

    *ecx = cache->sets - 1;
    
    *edx = (cache->no_invd_sharing ? CACHE_NO_INVD_SHARING : 0) |
           (cache->inclusive ? CACHE_INCLUSIVE : 0) |
           (cache->complex_indexing ? CACHE_COMPLEX_IDX : 0);
} 

static void encode_cache_cpuid80000006(CPUCacheInfo *l2,
                                       CPUCacheInfo *l3,
                                       uint32_t *ecx, uint32_t *edx)
{
    *ecx = ((l2->size / 1024) << 16) |
           (AMD_ENC_ASSOC(l2->associativity) << 12) |
           (l2->lines_per_tag << 8) | (l2->line_size);

    if (l3) {
        *edx = ((l3->size / (512 * 1024)) << 18) |
               (AMD_ENC_ASSOC(l3->associativity) << 12) |
               (l3->lines_per_tag << 8) | (l3->line_size);
    } else {
        *edx = 0;
    }
}

static uint32_t encode_cache_cpuid80000005(CPUCacheInfo *cache)
{
    return ((cache->size / 1024) << 24) | (cache->associativity << 16) |
           (cache->lines_per_tag << 8) | (cache->line_size);
}

static void cpu_x86_cpuid(CPUX86State *env, uint32_t index, uint32_t count,
                   uint32_t *eax, uint32_t *ebx,
                   uint32_t *ecx, uint32_t *edx)
{
    uint32_t die_offset;
    uint32_t limit;

    /* Calculate & apply limits for different index ranges */
    if (index >= 0xC0000000) {
        limit = env->cpuid_xlevel2;
    } else if (index >= 0x80000000) {
        limit = env->cpuid_xlevel;
    } else if (index >= 0x40000000) {
        limit = 0x40000001;
    } else {
        limit = env->cpuid_level;
    }

    if (index > limit) {
        /* Intel documentation states that invalid EAX input will
         * return the same information as EAX=cpuid_level
         * (Intel SDM Vol. 2A - Instruction Set Reference - CPUID)
         */
        index = env->cpuid_level;
    }

    switch(index) {
    case 0:
        *eax = env->cpuid_level;
        *ebx = env->cpuid_vendor1;
        *edx = env->cpuid_vendor2;
        *ecx = env->cpuid_vendor3;
        break;
    case 1:
        *eax = env->cpuid_version;
        *ebx = (env->apic_id << 24) |
               8 << 8; /* CLFLUSH size in quad words, Linux wants it. */
        *ecx = env->features[FEAT_1_ECX];
        if ((*ecx & CPUID_EXT_XSAVE) && (env->cr[4] & CR4_OSXSAVE_MASK)) {
            *ecx |= CPUID_EXT_OSXSAVE;
        }
        *edx = env->features[FEAT_1_EDX];
        if (env->nr_cores * env->nr_threads > 1) {
            *ebx |= (env->nr_cores * env->nr_threads) << 16;
            *edx |= CPUID_HT;
        }
        break;
    case 2:
        *eax = 1; /* Number of CPUID[EAX=2] calls required */
        *ebx = 0;
        *ecx = cpuid2_cache_descriptor(env->cache_info_cpuid2.l3_cache);
        *edx = (cpuid2_cache_descriptor(env->cache_info_cpuid2.l1d_cache) << 16) |
               (cpuid2_cache_descriptor(env->cache_info_cpuid2.l1i_cache) <<  8) |
               (cpuid2_cache_descriptor(env->cache_info_cpuid2.l2_cache));
        break;
    case 4:
        /* cache info: needed for Core compatibility */
            *eax = 0;
            switch (count) {
            case 0: /* L1 dcache info */
                encode_cache_cpuid4(env->cache_info_cpuid4.l1d_cache,
                                    1, env->nr_cores,
                                    eax, ebx, ecx, edx);
                break;
            case 1: /* L1 icache info */
                encode_cache_cpuid4(env->cache_info_cpuid4.l1i_cache,
                                    1, env->nr_cores,
                                    eax, ebx, ecx, edx);
                break;
            case 2: /* L2 cache info */
                encode_cache_cpuid4(env->cache_info_cpuid4.l2_cache,
                                    env->nr_threads, env->nr_cores,
                                    eax, ebx, ecx, edx);
                break;
            case 3: /* L3 cache info */
                die_offset = apicid_die_offset(1,
                                        env->nr_cores, env->nr_threads);
                encode_cache_cpuid4(env->cache_info_cpuid4.l3_cache,
                                    (1 << die_offset), env->nr_cores,
                                    eax, ebx, ecx, edx);
                break;
                /* fall through */
            default: /* end of info */
                *eax = *ebx = *ecx = *edx = 0;
                break;
            }
        break;
    case 5:
        /* MONITOR/MWAIT Leaf */
        *eax = 0; /* Smallest monitor-line size in bytes */
        *ebx = 0; /* Largest monitor-line size in bytes */
    	/* mwait extended info: needed for Core compatibility */
    	/* We always wake on interrupt even if host does not have the capability */
        *ecx = CPUID_MWAIT_EMX | CPUID_MWAIT_IBE; /* flags */
        *edx = 0; /* mwait substates */
        break;
    case 6:
        /* Thermal and Power Leaf */
        *eax = env->features[FEAT_6_EAX];
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        break;
    case 7:
        /* Structured Extended Feature Flags Enumeration Leaf */
        if (count == 0) {
            /* Maximum ECX value for sub-leaves */
            *eax = env->cpuid_level_func7;
            *ebx = env->features[FEAT_7_0_EBX]; /* Feature flags */
            *ecx = env->features[FEAT_7_0_ECX]; /* Feature flags */
            if ((*ecx & CPUID_7_0_ECX_PKU) && env->cr[4] & CR4_PKE_MASK) {
                *ecx |= CPUID_7_0_ECX_OSPKE;
            }
            *edx = env->features[FEAT_7_0_EDX]; /* Feature flags */
        } else if (count == 1) {
            *eax = env->features[FEAT_7_1_EAX];
            *ebx = 0;
            *ecx = 0;
            *edx = 0;
        } else {
            *eax = 0;
            *ebx = 0;
            *ecx = 0;
            *edx = 0;
        }
        break;
    case 9:
        /* Direct Cache Access Information Leaf */
        *eax = 0; /* Bits 0-31 in DCA_CAP MSR */
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        break;
    case 0xA:
        /* Architectural Performance Monitoring Leaf */
            *eax = 0;
            *ebx = 0;
            *ecx = 0;
            *edx = 0;
        break;
    case 0xB:

        *ecx = count & 0xff;
        *edx = env->apic_id;

        switch (count) {
        case 0:
            *eax = apicid_core_offset(1,
                                      env->nr_cores, env->nr_threads);
            *ebx = env->nr_threads;
            *ecx |= CPUID_TOPOLOGY_LEVEL_SMT;
            break;
        case 1:
            *eax = apicid_pkg_offset(1,
                                     env->nr_cores, env->nr_threads);
            *ebx = env->nr_cores * env->nr_threads;
            *ecx |= CPUID_TOPOLOGY_LEVEL_CORE;
            break;
        default:
            *eax = 0;
            *ebx = 0;
            *ecx |= CPUID_TOPOLOGY_LEVEL_INVALID;
        }

        *ebx &= 0xffff; /* The count doesn't need to be reliable. */
        break;
    case 0x1F:
        /* V2 Extended Topology Enumeration Leaf */
        if (1 < 2) {
            *eax = *ebx = *ecx = *edx = 0;
            break;
        }

        *ecx = count & 0xff;
        *edx = env->apic_id;
        switch (count) {
        case 0:
            *eax = apicid_core_offset(1, env->nr_cores,
                                                    env->nr_threads);
            *ebx = env->nr_threads;
            *ecx |= CPUID_TOPOLOGY_LEVEL_SMT;
            break;
        case 1:
            *eax = apicid_die_offset(1, env->nr_cores,
                                                   env->nr_threads);
            *ebx = env->nr_cores * env->nr_threads;
            *ecx |= CPUID_TOPOLOGY_LEVEL_CORE;
            break;
        case 2:
            *eax = apicid_pkg_offset(1, env->nr_cores,
                                                   env->nr_threads);
            *ebx = 1 * env->nr_cores * env->nr_threads;
            *ecx |= CPUID_TOPOLOGY_LEVEL_DIE;
            break;
        default:
            *eax = 0;
            *ebx = 0;
            *ecx |= CPUID_TOPOLOGY_LEVEL_INVALID;
        }
        *ebx &= 0xffff; /* The count doesn't need to be reliable. */
        break;
    case 0xD: {
        /* Processor Extended State */
        *eax = 0;
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        if (!(env->features[FEAT_1_ECX] & CPUID_EXT_XSAVE)) {
            break;
        }

        if (count == 0) {
            *ecx = xsave_area_size(x86_cpu_xsave_components(env));
            *eax = env->features[FEAT_XSAVE_COMP_LO];
            *edx = env->features[FEAT_XSAVE_COMP_HI];
            /*
             * The initial value of xcr0 and ebx == 0, On host without kvm
             * commit 412a3c41(e.g., CentOS 6), the ebx's value always == 0
             * even through guest update xcr0, this will crash some legacy guest
             * (e.g., CentOS 6), So set ebx == ecx to workaroud it.
             */
            *ebx = *ecx;
        } else if (count == 1) {
            *eax = env->features[FEAT_XSAVE];
        } else if (count < ARRAY_SIZE(x86_ext_save_areas)) {
            if ((x86_cpu_xsave_components(env) >> count) & 1) {
                const ExtSaveArea *esa = &x86_ext_save_areas[count];
                *eax = esa->size;
                *ebx = esa->offset;
            }
        }
        break;
    }
    case 0x14: {
        /* Intel Processor Trace Enumeration */
        *eax = 0;
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        if (!(env->features[FEAT_7_0_EBX] & CPUID_7_0_EBX_INTEL_PT)) {
            break;
        }

        if (count == 0) {
            *eax = INTEL_PT_MAX_SUBLEAF;
            *ebx = INTEL_PT_MINIMAL_EBX;
            *ecx = INTEL_PT_MINIMAL_ECX;
        } else if (count == 1) {
            *eax = INTEL_PT_MTC_BITMAP | INTEL_PT_ADDR_RANGES_NUM;
            *ebx = INTEL_PT_PSB_BITMAP | INTEL_PT_CYCLE_BITMAP;
        }
        break;
    }
    case 0x40000000:
        /*
         * CPUID code in kvm_arch_init_vcpu() ignores stuff
         * set here, but we restrict to TCG none the less.
         */
        *eax = 0;
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        break;
    case 0x40000001:
        *eax = 0;
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        break;
    case 0x80000000:
        *eax = env->cpuid_xlevel;
        *ebx = env->cpuid_vendor1;
        *edx = env->cpuid_vendor2;
        *ecx = env->cpuid_vendor3;
        break;
    case 0x80000001:
        *eax = env->cpuid_version;
        *ebx = 0;
        *ecx = env->features[FEAT_8000_0001_ECX];
        *edx = env->features[FEAT_8000_0001_EDX];

        /* The Linux kernel checks for the CMPLegacy bit and
         * discards multiple thread information if it is set.
         * So don't set it here for Intel to make Linux guests happy.
         */
        if (env->nr_cores * env->nr_threads > 1) {
            if (env->cpuid_vendor1 != CPUID_VENDOR_INTEL_1 ||
                env->cpuid_vendor2 != CPUID_VENDOR_INTEL_2 ||
                env->cpuid_vendor3 != CPUID_VENDOR_INTEL_3) {
                *ecx |= 1 << 1;    /* CmpLegacy bit */
            }
        }
        break;
    case 0x80000002:
    case 0x80000003:
    case 0x80000004:
        *eax = env->cpuid_model[(index - 0x80000002) * 4 + 0];
        *ebx = env->cpuid_model[(index - 0x80000002) * 4 + 1];
        *ecx = env->cpuid_model[(index - 0x80000002) * 4 + 2];
        *edx = env->cpuid_model[(index - 0x80000002) * 4 + 3];
        break;
    case 0x80000005:
        *eax = (L1_DTLB_2M_ASSOC << 24) | (L1_DTLB_2M_ENTRIES << 16) | \
               (L1_ITLB_2M_ASSOC <<  8) | (L1_ITLB_2M_ENTRIES);
        *ebx = (L1_DTLB_4K_ASSOC << 24) | (L1_DTLB_4K_ENTRIES << 16) | \
               (L1_ITLB_4K_ASSOC <<  8) | (L1_ITLB_4K_ENTRIES);
        *ecx = encode_cache_cpuid80000005(env->cache_info_amd.l1d_cache);
        *edx = encode_cache_cpuid80000005(env->cache_info_amd.l1i_cache);
        break;
    case 0x80000006:
        *eax = (AMD_ENC_ASSOC(L2_DTLB_2M_ASSOC) << 28) | \
               (L2_DTLB_2M_ENTRIES << 16) | \
               (AMD_ENC_ASSOC(L2_ITLB_2M_ASSOC) << 12) | \
               (L2_ITLB_2M_ENTRIES);
        *ebx = (AMD_ENC_ASSOC(L2_DTLB_4K_ASSOC) << 28) | \
               (L2_DTLB_4K_ENTRIES << 16) | \
               (AMD_ENC_ASSOC(L2_ITLB_4K_ASSOC) << 12) | \
               (L2_ITLB_4K_ENTRIES);
        encode_cache_cpuid80000006(env->cache_info_amd.l2_cache,
                                   env->cache_info_amd.l3_cache,
                                   ecx, edx);
        break;
    case 0x80000007:
        *eax = 0;
        *ebx = 0;
        *ecx = 0;
        *edx = env->features[FEAT_8000_0007_EDX];
        break;
    case 0x80000008:
        /* virtual & phys address size in low 2 bytes. */
        if (env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_LM) {
            /* 64 bit processor */
            *eax = env->phys_bits; /* configurable physical bits */
            if  (env->features[FEAT_7_0_ECX] & CPUID_7_0_ECX_LA57) {
                *eax |= 0x00003900; /* 57 bits virtual */
            } else {
                *eax |= 0x00003000; /* 48 bits virtual */
            }
        } else {
            *eax = env->phys_bits;
        }
        *ebx = env->features[FEAT_8000_0008_EBX];
        *ecx = 0;
        *edx = 0;
        if (env->nr_cores * env->nr_threads > 1) {
            *ecx |= (env->nr_cores * env->nr_threads) - 1;
        }
        break;
    case 0x8000000A:
        if (env->features[FEAT_8000_0001_ECX] & CPUID_EXT3_SVM) {
            *eax = 0x00000001; /* SVM Revision */
            *ebx = 0x00000010; /* nr of ASIDs */
            *ecx = 0;
            *edx = env->features[FEAT_SVM]; /* optional features */
        } else {
            *eax = 0;
            *ebx = 0;
            *ecx = 0;
            *edx = 0;
        }
        break;
    case 0x8000001D:
        *eax = 0;
        switch (count) {
        case 0: /* L1 dcache info */
            encode_cache_cpuid8000001d(env->cache_info_amd.l1d_cache, env,
                                       eax, ebx, ecx, edx);
            break;
        case 1: /* L1 icache info */
            encode_cache_cpuid8000001d(env->cache_info_amd.l1i_cache, env,
                                       eax, ebx, ecx, edx);
            break;
        case 2: /* L2 cache info */
            encode_cache_cpuid8000001d(env->cache_info_amd.l2_cache, env,
                                       eax, ebx, ecx, edx);
            break;
        case 3: /* L3 cache info */
            encode_cache_cpuid8000001d(env->cache_info_amd.l3_cache, env,
                                       eax, ebx, ecx, edx);
            break;
        default: /* end of info */
            *eax = *ebx = *ecx = *edx = 0;
            break;
        }
        break;
    case 0x8000001E:
        encode_topo_cpuid8000001e(env,
                                  eax, ebx, ecx, edx);
        break;
    case 0xC0000000:
        *eax = env->cpuid_xlevel2;
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        break;
    case 0xC0000001:
        /* Support for VIA CPU's CPUID instruction */
        *eax = env->cpuid_version;
        *ebx = 0;
        *ecx = 0;
        *edx = env->features[FEAT_C000_0001_EDX];
        break;
    case 0xC0000002:
    case 0xC0000003:
    case 0xC0000004:
        /* Reserved for the future, and now filled with zero */
        *eax = 0;
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        break;
    case 0x8000001F:
        *eax = 0;
        *ebx = 0;
        *ebx |= 0;
        *ecx = 0;
        *edx = 0;
        break;
    default:
        /* reserved values: zero */
        *eax = 0;
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        break;
    }
}

static bool tsc_is_stable_and_known(CPUX86State *env)
{
    if (!env->tsc_khz) {
        return false;
    }
    return (env->features[FEAT_8000_0007_EDX] & CPUID_APM_INVTSC);
}

static void kvm_get_mce_cap_supported(uint64_t *mcg_cap, int *banks)
{
	*banks = KVM_MAX_MCE_BANKS;
	*mcg_cap = kvm_mce_cap_supported;
}

static int init_vcpu_cpuid2(struct kvm_vcpu *vcpu)
{
	int r;
	struct kvm_vcpu_arch *arch = &vcpu->arch;
	uint32_t cpuid_i = 0;
	struct kvm_cpuid_entry2 *c;
    uint32_t signature[3];
    int kvm_base = KVM_CPUID_SIGNATURE;
	CPUX86State *env;
	uint8_t ch;
	uint32_t limit, i, j, len;
	uint32_t unused;
    char vendor[CPUID_VENDOR_SZ + 1] = { 0 }; 
    char model_id[CPUID_MODEL_ID_SZ + 1] = { 0 }; 
    int family, model, stepping;

	env = kzalloc(sizeof(CPUX86State), GFP_KERNEL);
	arch->env = env;

	env->apic_id = vcpu->vcpu_id;
	init_env_possible_cpus(env, vcpu->kvm);

	host_vendor_fms(vendor, &family, &model, &stepping);
	cpu_x86_fill_model_id(model_id);

    //setup vendor
    env->cpuid_vendor1 = 0;
    env->cpuid_vendor2 = 0;
    env->cpuid_vendor3 = 0;
    for (i = 0; i < 4; i++) {
        env->cpuid_vendor1 |= ((uint8_t)vendor[i    ]) << (8 * i);
        env->cpuid_vendor2 |= ((uint8_t)vendor[i + 4]) << (8 * i);
        env->cpuid_vendor3 |= ((uint8_t)vendor[i + 8]) << (8 * i);
    }

    //setup family
    env->cpuid_version = 0;
    if (family > 0x0f) {
        env->cpuid_version |= 0xf00 | ((family - 0x0f) << 20);
    } else {
        env->cpuid_version |= family << 8;
    }

    //setup model
    env->cpuid_version &= ~0xf00f0;
    env->cpuid_version |= ((model & 0xf) << 4) | ((model >> 4) << 16);

    //setup stepping
    env->cpuid_version &= ~0xf;
    env->cpuid_version |= stepping & 0xf;

    //setup model-id
    len = strlen(model_id);
    memset(env->cpuid_model, 0, 48);
    for (i = 0; i < 48; i++) {
        if (i >= len) {
            ch = '\0';
        } else {
            ch = (uint8_t)model_id[i];
        }
        env->cpuid_model[i >> 2] |= ch << (8 * (i & 3));
    }

	env->cpuid_min_level =
                kvm_arch_get_supported_cpuid(0x0, 0, R_EAX);
    env->cpuid_min_xlevel =
                kvm_arch_get_supported_cpuid(0x80000000, 0, R_EAX);
    env->cpuid_min_xlevel2 =
                kvm_arch_get_supported_cpuid(0xC0000000, 0, R_EAX);


    x86_cpu_expand_features(env);


	x86_cpu_filter_features(env);

    /* On AMD CPUs, some CPUID[8000_0001].EDX bits must match the bits on
     * CPUID[1].EDX.
     */
    if (IS_AMD_CPU(env)) {
        env->features[FEAT_8000_0001_EDX] &= ~CPUID_EXT2_AMD_ALIASES;
        env->features[FEAT_8000_0001_EDX] |= (env->features[FEAT_1_EDX] & CPUID_EXT2_AMD_ALIASES);
    }

    if (env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_LM) {
        env->phys_bits = 40;
    } else {
        if (env->features[FEAT_1_EDX] & CPUID_PSE36) {
            env->phys_bits = 36;
        } else {
            env->phys_bits = 32;
        }    
    } 

    env->cache_info_cpuid2.l1d_cache = &legacy_l1d_cache;
    env->cache_info_cpuid2.l1i_cache = &legacy_l1i_cache;
    env->cache_info_cpuid2.l2_cache = &legacy_l2_cache_cpuid2;
    env->cache_info_cpuid2.l3_cache = &legacy_l3_cache;

    env->cache_info_cpuid4.l1d_cache = &legacy_l1d_cache;
    env->cache_info_cpuid4.l1i_cache = &legacy_l1i_cache;
    env->cache_info_cpuid4.l2_cache = &legacy_l2_cache;
    env->cache_info_cpuid4.l3_cache = &legacy_l3_cache;

    env->cache_info_amd.l1d_cache = &legacy_l1d_cache_amd;
    env->cache_info_amd.l1i_cache = &legacy_l1i_cache_amd;
    env->cache_info_amd.l2_cache = &legacy_l2_cache_amd;
    env->cache_info_amd.l3_cache = &legacy_l3_cache;

	mce_init(env);

	env->tsc_khz = vcpu->arch.virtual_tsc_khz;

    memcpy(signature, "KVMKVMKVM\0\0\0", 12);
	c = &arch->cpuid_entries[cpuid_i++];
    c->function = KVM_CPUID_SIGNATURE | kvm_base;
    c->eax = KVM_CPUID_FEATURES | kvm_base;
    c->ebx = signature[0];
    c->ecx = signature[1];
    c->edx = signature[2];

    c = &arch->cpuid_entries[cpuid_i++];
    c->function = KVM_CPUID_FEATURES | kvm_base;
    c->eax = env->features[FEAT_KVM];
    c->edx = env->features[FEAT_KVM_HINTS];

	cpu_x86_cpuid(env, 0, 0, &limit, &unused, &unused, &unused);

    for (i = 0; i <= limit; i++) {
        if (cpuid_i == KVM_MAX_CPUID_ENTRIES) {
            printk("unsupported level value: 0x%x\n", limit);
            goto out;
        }
        c = &arch->cpuid_entries[cpuid_i++];

        switch (i) {
        case 2: {
            /* Keep reading function 2 till all the input is received */
            int times;

            c->function = i;
            c->flags = KVM_CPUID_FLAG_STATEFUL_FUNC |
                       KVM_CPUID_FLAG_STATE_READ_NEXT;
            cpu_x86_cpuid(env, i, 0, &c->eax, &c->ebx, &c->ecx, &c->edx);
            times = c->eax & 0xff;

            for (j = 1; j < times; ++j) {
                if (cpuid_i == KVM_MAX_CPUID_ENTRIES) {
                    printk("cpuid_data is full, no space for "
                            "cpuid(eax:2):eax & 0xf = 0x%x\n", times);
                    goto out;
                }
                c = &arch->cpuid_entries[cpuid_i++];
                c->function = i;
                c->flags = KVM_CPUID_FLAG_STATEFUL_FUNC;
                cpu_x86_cpuid(env, i, 0, &c->eax, &c->ebx, &c->ecx, &c->edx);
            }
            break;
        }
        case 0x1f:
            if (1 < 2) {
                break;
            }
        case 4:
        case 0xb:
        case 0xd:
            for (j = 0; ; j++) {
                if (i == 0xd && j == 64) {
                    break;
                }

                if (i == 0x1f && j == 64) {
                    break;
                }

                c->function = i;
                c->flags = KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
                c->index = j;
                cpu_x86_cpuid(env, i, j, &c->eax, &c->ebx, &c->ecx, &c->edx);

                if (i == 4 && c->eax == 0) {
                    break;
                }
                if (i == 0xb && !(c->ecx & 0xff00)) {
                    break;
                }
                if (i == 0x1f && !(c->ecx & 0xff00)) {
                    break;
                }
                if (i == 0xd && c->eax == 0) {
                    continue;
                }
                if (cpuid_i == KVM_MAX_CPUID_ENTRIES) {
                    printk("cpuid_data is full, no space for "
                            "cpuid(eax:0x%x,ecx:0x%x)\n", i, j);
                    goto out;
                }
                c = &arch->cpuid_entries[cpuid_i++];
            }
            break;
        case 0x7:
        case 0x14: {
            uint32_t times;

            c->function = i;
            c->index = 0;
            c->flags = KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
            cpu_x86_cpuid(env, i, 0, &c->eax, &c->ebx, &c->ecx, &c->edx);
            times = c->eax;

            for (j = 1; j <= times; ++j) {
                if (cpuid_i == KVM_MAX_CPUID_ENTRIES) {
                    printk("cpuid_data is full, no space for "
                                "cpuid(eax:0x%x,ecx:0x%x)\n", i, j);
                    goto out;
                }
                c = &arch->cpuid_entries[cpuid_i++];
                c->function = i;
                c->index = j;
                c->flags = KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
                cpu_x86_cpuid(env, i, j, &c->eax, &c->ebx, &c->ecx, &c->edx);
            }
            break;
        }
        default:
            c->function = i;
            c->flags = 0;
            cpu_x86_cpuid(env, i, 0, &c->eax, &c->ebx, &c->ecx, &c->edx);
            if (!c->eax && !c->ebx && !c->ecx && !c->edx) {
                /*
                 * KVM already returns all zeroes if a CPUID entry is missing,
                 * so we can omit it and avoid hitting KVM's 80-entry limit.
                 */
                cpuid_i--;
            }
            break;
        }
    }

    if (limit >= 0x0a) {
        uint32_t eax, edx;

        cpu_x86_cpuid(env, 0x0a, 0, &eax, &unused, &unused, &edx);

        has_architectural_pmu_version = eax & 0xff;
        if (has_architectural_pmu_version > 0) {
            num_architectural_pmu_gp_counters = (eax & 0xff00) >> 8;

            /* Shouldn't be more than 32, since that's the number of bits
             * available in EBX to tell us _which_ counters are available.
             * Play it safe.
             */
            if (num_architectural_pmu_gp_counters > MAX_GP_COUNTERS) {
                num_architectural_pmu_gp_counters = MAX_GP_COUNTERS;
            }

            if (has_architectural_pmu_version > 1) {
                num_architectural_pmu_fixed_counters = edx & 0x1f;

                if (num_architectural_pmu_fixed_counters > MAX_FIXED_COUNTERS) {
                    num_architectural_pmu_fixed_counters = MAX_FIXED_COUNTERS;
                }
            }
        }
    }

    cpu_x86_cpuid(env, 0x80000000, 0, &limit, &unused, &unused, &unused);

    for (i = 0x80000000; i <= limit; i++) {
        if (cpuid_i == KVM_MAX_CPUID_ENTRIES) {
            printk("unsupported xlevel value: 0x%x\n", limit);
            goto out;
        }
        c = &arch->cpuid_entries[cpuid_i++];

        switch (i) {
        case 0x8000001d:
            /* Query for all AMD cache information leaves */
            for (j = 0; ; j++) {
                c->function = i;
                c->flags = KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
                c->index = j;
                cpu_x86_cpuid(env, i, j, &c->eax, &c->ebx, &c->ecx, &c->edx);

                if (c->eax == 0) {
                    break;
                }
                if (cpuid_i == KVM_MAX_CPUID_ENTRIES) {
                    printk("cpuid_data is full, no space for "
                            "cpuid(eax:0x%x,ecx:0x%x)\n", i, j);
                    goto out;
                }
                c = &arch->cpuid_entries[cpuid_i++];
            }
            break;
        default:
            c->function = i;
            c->flags = 0;
            cpu_x86_cpuid(env, i, 0, &c->eax, &c->ebx, &c->ecx, &c->edx);
            if (!c->eax && !c->ebx && !c->ecx && !c->edx) {
                /*
                 * KVM already returns all zeroes if a CPUID entry is missing,
                 * so we can omit it and avoid hitting KVM's 80-entry limit.
                 */
                cpuid_i--;
            }
            break;
        }
    }

    /* Call Centaur's CPUID instructions they are supported. */
    if (env->cpuid_xlevel2 > 0) {
        cpu_x86_cpuid(env, 0xC0000000, 0, &limit, &unused, &unused, &unused);

        for (i = 0xC0000000; i <= limit; i++) {
            if (cpuid_i == KVM_MAX_CPUID_ENTRIES) {
                printk("unsupported xlevel2 value: 0x%x\n", limit);
                goto out;
            }
            c = &arch->cpuid_entries[cpuid_i++];

            c->function = i;
            c->flags = 0;
            cpu_x86_cpuid(env, i, 0, &c->eax, &c->ebx, &c->ecx, &c->edx);
        }
    }

    if (((env->cpuid_version >> 8)&0xF) >= 6
        && (env->features[FEAT_1_EDX] & (CPUID_MCE | CPUID_MCA)) ==
           (CPUID_MCE | CPUID_MCA)) {
        uint64_t mcg_cap, unsupported_caps;
        int banks;
        int ret;

        kvm_get_mce_cap_supported(&mcg_cap, &banks);

        if (banks < (env->mcg_cap & MCG_CAP_BANKS_MASK)) {
            printk("kvm: Unsupported MCE bank count (QEMU = %d, KVM = %d)",
                         (int)(env->mcg_cap & MCG_CAP_BANKS_MASK), banks);
            goto out;
        }

        unsupported_caps = env->mcg_cap & ~(mcg_cap | MCG_CAP_BANKS_MASK);
        if (unsupported_caps) {
            if (unsupported_caps & MCG_LMCE_P) {
                printk("kvm: LMCE not supported");
                goto out;
            }
            printk("Unsupported MCG_CAP bits: 0x%llx", unsupported_caps);
        }

        env->mcg_cap &= mcg_cap | MCG_CAP_BANKS_MASK;
        ret = kvm_vcpu_ioctl_x86_setup_mce(vcpu, env->mcg_cap);
        if (ret < 0) {
            goto out;
        }
    }

	arch->cpuid_nent = cpuid_i;

    c = cpuid_find_entry_arch(arch, 1, 0);
    if (c) {
        has_msr_feature_control = !!(c->ecx & CPUID_EXT_VMX) ||
                                  !!(c->ecx & CPUID_EXT_SMX);
    }

    if (env->mcg_cap & MCG_LMCE_P) {
        has_msr_mcg_ext_ctl = has_msr_feature_control = true;
    }

    if (kvm_base == KVM_CPUID_SIGNATURE
        /* TSC clock must be stable and known for this feature. */
        && tsc_is_stable_and_known(env)) {

        c = &arch->cpuid_entries[cpuid_i++];
        c->function = KVM_CPUID_SIGNATURE | 0x10;
        c->eax = env->tsc_khz;
        /* LAPIC resolution of 1ns (freq: 1GHz) is hardcoded in KVM's
         * APIC_BUS_CYCLE_NS */
        c->ebx = 1000000;
        c->ecx = c->edx = 0;

        c = cpuid_find_entry_arch(arch, kvm_base, 0);
        c->eax = MAX(c->eax, KVM_CPUID_SIGNATURE | 0x10);
    }


    env->xsave_buf = kmalloc(4096, GFP_KERNEL);
    memset(env->xsave_buf, 0, sizeof(struct kvm_xsave));

    #define MSR_BUF_SIZE 4096
    env->kvm_msr_buf = kmalloc(MSR_BUF_SIZE, GFP_KERNEL);

    if (!(env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_RDTSCP)) {
        has_msr_tsc_aux = false;
    }

out:
	arch->cpuid_nent = cpuid_i;

	kvm_apic_set_version(vcpu);
	kvm_x86_ops->cpuid_update(vcpu);
	r = kvm_update_cpuid(vcpu);

	return r;
}



int kvm_get_supported_msrs(void)
{
	int i;
    int ret = 0;
	struct kvm_msr_list *msr_list;

	msr_list = vzalloc(sizeof(struct kvm_msr_list)
		+ (sizeof(u32) * (num_msrs_to_save + num_emulated_msrs)));
	if (msr_list == NULL)
		return -1;

	memcpy(msr_list->indices, &msrs_to_save,
		num_msrs_to_save * sizeof(u32));

	memcpy(msr_list->indices + num_msrs_to_save,
		&emulated_msrs, num_emulated_msrs * sizeof(u32));
	
    for (i = 0; i < msr_list->nmsrs; i++) {
        switch (msr_list->indices[i]) {
            case MSR_STAR:
                has_msr_star = true;
                break;
            case MSR_VM_HSAVE_PA:
                has_msr_hsave_pa = true;
                break;
            case MSR_TSC_AUX:
                has_msr_tsc_aux = true;
                break;
            case MSR_IA32_TSC_ADJUST:
                has_msr_tsc_adjust = true;
                break;
            case MSR_IA32_TSCDEADLINE:
                has_msr_tsc_deadline = true;
                break;
            case MSR_IA32_SMBASE:
                has_msr_smbase = true;
                break;
            case MSR_SMI_COUNT:
                has_msr_smi_count = true;
                break;
            case MSR_IA32_MISC_ENABLE:
                has_msr_misc_enable = true;
                break;
            case MSR_IA32_BNDCFGS:
                has_msr_bndcfgs = true;
                break;
            case MSR_IA32_XSS:
                has_msr_xss = true;
                break;
            case MSR_IA32_UMWAIT_CONTROL:
                has_msr_umwait = true;
                break;
            case HV_X64_MSR_CRASH_CTL:
                has_msr_hv_crash = true;
                break;
            case HV_X64_MSR_RESET:
                has_msr_hv_reset = true;
                break;
            case HV_X64_MSR_VP_INDEX:
                has_msr_hv_vpindex = true;
                break;
            case HV_X64_MSR_VP_RUNTIME:
                has_msr_hv_runtime = true;
                break;
            case HV_X64_MSR_SCONTROL:
                has_msr_hv_synic = true;
                break;
            case HV_X64_MSR_STIMER0_CONFIG:
                has_msr_hv_stimer = true;
                break;
            case HV_X64_MSR_TSC_FREQUENCY:
                has_msr_hv_frequencies = true;
                break;
            case HV_X64_MSR_REENLIGHTENMENT_CONTROL:
                has_msr_hv_reenlightenment = true;
                break;
            case MSR_IA32_SPEC_CTRL:
                has_msr_spec_ctrl = true;
                break;
            case MSR_IA32_TSX_CTRL:
                has_msr_tsx_ctrl = true;
                break;
            case MSR_VIRT_SSBD:
                has_msr_virt_ssbd = true;
                break;
            case MSR_IA32_ARCH_CAPABILITIES:
                has_msr_arch_capabs = true;
                break;
            case MSR_IA32_CORE_CAPABILITY:
                has_msr_core_capabs = true;
                break;
            case MSR_IA32_VMX_VMFUNC:
                has_msr_vmx_vmfunc = true;
                break;
        }
	}

	vfree(msr_list);

	return ret;
}

int kvm_get_supported_feature_msrs(void)
{
    int ret = 0;

    if (kvm_feature_msrs != NULL) {
        return 0;
    }

	kvm_feature_msrs = vzalloc(sizeof(struct kvm_msr_list)
		+ (sizeof(u32) * (num_msrs_to_save + num_emulated_msrs)));
	if (kvm_feature_msrs == NULL)
		return -1;

	kvm_feature_msrs->nmsrs = num_msr_based_features;

	memcpy(kvm_feature_msrs->indices,
		&msr_based_features, num_msr_based_features * sizeof(u32));

	return ret;
}


static struct kvm_cpuid2 *get_supported_cpuid(void)
{
    struct kvm_cpuid2 *cpuid = NULL;
	static struct kvm_cpuid2 *cpuid_cache;
	struct kvm_cpuid_entry2 *cpuid_entries;
	int limit, nent = 0, r, i;
	u32 func;
	static const struct kvm_cpuid_param param[] = {
		{ .func = 0, .has_leaf_count = true },
		{ .func = 0x80000000, .has_leaf_count = true },
		{ .func = 0xC0000000, .qualifier = is_centaur_cpu, .has_leaf_count = true },
		{ .func = KVM_CPUID_SIGNATURE },
		{ .func = KVM_CPUID_FEATURES },
	};

    if (cpuid_cache != NULL) {
        return cpuid_cache;
    }

	cpuid = kzalloc(sizeof(struct kvm_cpuid2)
		+ (sizeof(struct kvm_cpuid_entry2) * KVM_MAX_CPUID_ENTRIES), GFP_KERNEL);
	if (!cpuid)
		goto out;

	cpuid->nent = KVM_MAX_CPUID_ENTRIES;
	cpuid_entries = cpuid->entries;

	r = 0;
	for (i = 0; i < ARRAY_SIZE(param); i++) {
		const struct kvm_cpuid_param *ent = &param[i];

		if (ent->qualifier && !ent->qualifier(ent))
			continue;

		r = do_cpuid_ent(&cpuid_entries[nent], ent->func, ent->idx,
				&nent, cpuid->nent, KVM_GET_SUPPORTED_CPUID);

		if (r)
			goto out_free;

		if (!ent->has_leaf_count)
			continue;

		limit = cpuid_entries[nent - 1].eax;
		for (func = ent->func + 1; func <= limit && nent < cpuid->nent && r == 0; ++func)
			r = do_cpuid_ent(&cpuid_entries[nent], func, ent->idx,
				     &nent, cpuid->nent, KVM_GET_SUPPORTED_CPUID);

		if (r)
			goto out_free;
	}

	cpuid->nent = nent;
    cpuid_cache = cpuid;

	return cpuid;

out_free:
	vfree(cpuid);
out:
	return NULL;
}


static void cpu_x86_update_cr0(CPUX86State *env, uint32_t new_cr0)
{
    int pe_state;

    if (!(env->cr[0] & CR0_PG_MASK) && (new_cr0 & CR0_PG_MASK) &&
        (env->efer & MSR_EFER_LME)) {
        /* enter in long mode */
        /* XXX: generate an exception */
        if (!(env->cr[4] & CR4_PAE_MASK))
            return;

        env->efer |= MSR_EFER_LMA;
        env->hflags |= HF_LMA_MASK;
    } else if ((env->cr[0] & CR0_PG_MASK) && !(new_cr0 & CR0_PG_MASK) &&
               (env->efer & MSR_EFER_LMA)) {
        /* exit long mode */
        env->efer &= ~MSR_EFER_LMA;
        env->hflags &= ~(HF_LMA_MASK | HF_CS64_MASK);
        env->eip &= 0xffffffff;
    }

    env->cr[0] = new_cr0 | CR0_ET_MASK;

    /* update PE flag in hidden flags */
    pe_state = (env->cr[0] & CR0_PE_MASK);
    env->hflags = (env->hflags & ~HF_PE_MASK) | (pe_state << HF_PE_SHIFT);
    /* ensure that ADDSEG is always set in real mode */
    env->hflags |= ((pe_state ^ 1) << HF_ADDSEG_SHIFT);
    /* update FPU flags */
    env->hflags = (env->hflags & ~(HF_MP_MASK | HF_EM_MASK | HF_TS_MASK)) |
        ((new_cr0 << (HF_MP_SHIFT - 1)) & (HF_MP_MASK | HF_EM_MASK | HF_TS_MASK));
}


static uint64_t
gdt_entry(uint16_t flags, uint32_t base, uint32_t limit)
{
   return (((((uint64_t)base) & 0xff000000ULL) << (56 - 24))
        | ((((uint64_t)flags) & 0x0000f0ffULL) << 40)
        | ((((uint64_t)limit) & 0x000f0000ULL) << (48 - 16))
        | ((((uint64_t)base)  & 0x00ffffffULL) << 16)
        | (((uint64_t)limit)  & 0x0000ffffULL));
}


static void write_gdt_table(struct kvm_vcpu *vcpu, uint64_t *gdt, int length)
{
	struct gfn_to_hva_cache ghc;

	kvm_gfn_to_hva_cache_init(vcpu->kvm, &ghc, BOOT_GDT_OFFSET, length);

    memcpy((void*)ghc.hva, gdt, length);
}

static void write_idt_value(struct kvm_vcpu *vcpu, uint64_t val)
{
	struct gfn_to_hva_cache ghc;

	kvm_gfn_to_hva_cache_init(vcpu->kvm, &ghc, BOOT_IDT_OFFSET, 8);

    *(uint64_t *)ghc.hva = val;
}

static void setup_page_tables(struct kvm_vcpu *vcpu)
{   
    int i;
	struct gfn_to_hva_cache ghc;
    uint64_t *pml4; 
    uint64_t *pdpt;
    uint64_t *pd;

	kvm_gfn_to_hva_cache_init(vcpu->kvm, &ghc, PML4_START, 0x3000);

    pml4 = (uint64_t *)ghc.hva; 
    pdpt = (uint64_t *)(ghc.hva + 0x1000);
    pd = (uint64_t *)(ghc.hva + 0x2000);
    
    *pml4 = ((uint64_t)PDPTE_START) | 0x03;
    *pdpt = ((uint64_t)PDE_START) | 0x03;
    
    for (i = 0; i < 512; i++) {
        pd[i] = (i << 21) + 0x83;
    }
}

static void cpu_sync_bndcs_hflags(CPUX86State *env)
{
    uint32_t hflags = env->hflags;
    uint32_t hflags2 = env->hflags2;
    uint32_t bndcsr;

    if ((hflags & HF_CPL_MASK) == 3) {
        bndcsr = env->bndcs_regs.cfgu;
    } else {
        bndcsr = env->msr_bndcfgs;
    }

    if ((env->cr[4] & CR4_OSXSAVE_MASK)
        && (env->xcr0 & XSTATE_BNDCSR_MASK)
        && (bndcsr & BNDCFG_ENABLE)) {
        hflags |= HF_MPX_EN_MASK;
    } else {
        hflags &= ~HF_MPX_EN_MASK;
    }

    if (bndcsr & BNDCFG_BNDPRESERVE) {
        hflags2 |= HF2_MPX_PR_MASK;
    } else {
        hflags2 &= ~HF2_MPX_PR_MASK;
    }

    env->hflags = hflags;
    env->hflags2 = hflags2;
}


static inline void cpu_x86_load_seg_cache(CPUX86State *env,
                                          int seg_reg, unsigned int selector,
                                          uint64_t base,
                                          unsigned int limit,
                                          unsigned int flags)
{
    SegmentCache *sc;
    unsigned int new_hflags;

    sc = &env->segs[seg_reg];
    sc->selector = selector;
    sc->base = base;
    sc->limit = limit;
    sc->flags = flags;

    /* update the hidden flags */
    if (seg_reg == R_CS) {
            if ((env->hflags & HF_LMA_MASK) && (flags & DESC_L_MASK)) {
                /* long mode */
                env->hflags |= HF_CS32_MASK | HF_SS32_MASK | HF_CS64_MASK;
                env->hflags &= ~(HF_ADDSEG_MASK);
            } else {
                /* legacy / compatibility case */
                new_hflags = (env->segs[R_CS].flags & DESC_B_MASK)
                    >> (DESC_B_SHIFT - HF_CS32_SHIFT);
                env->hflags = (env->hflags & ~(HF_CS32_MASK | HF_CS64_MASK)) |
                    new_hflags;
            }
    }

    if (seg_reg == R_SS) {
            int cpl = (flags >> DESC_DPL_SHIFT) & 3;
            env->hflags = (env->hflags & ~HF_CPL_MASK) | cpl;
            /* Possibly switch between BNDCFGS and BNDCFGU */
            cpu_sync_bndcs_hflags(env);
    }

    new_hflags = (env->segs[R_SS].flags & DESC_B_MASK)
            >> (DESC_B_SHIFT - HF_SS32_SHIFT);

    if (env->hflags & HF_CS64_MASK) {
            /* zero base assumed for DS, ES and SS in long mode */
    } else if (!(env->cr[0] & CR0_PE_MASK) ||
                   (env->eflags & VM_MASK) ||
                   !(env->hflags & HF_CS32_MASK)) {
            /* XXX: try to avoid this test. The problem comes from the
               fact that is real mode or vm86 mode we only modify the
               'base' and 'selector' fields of the segment cache to go
               faster. A solution may be to force addseg to one in
               translate-i386.c. */
            new_hflags |= HF_ADDSEG_MASK;
    } else {
            new_hflags |= ((env->segs[R_DS].base |
                            env->segs[R_ES].base |
                            env->segs[R_SS].base) != 0) <<
                HF_ADDSEG_SHIFT;
    }

    env->hflags = (env->hflags &
                       ~(HF_SS32_MASK | HF_ADDSEG_MASK)) | new_hflags;
}

static void cpu_x86_update_cr4(CPUX86State *env, uint32_t new_cr4)
{
    uint32_t hflags;

    /* Clear bits we're going to recompute.  */
    hflags = env->hflags & ~(HF_OSFXSR_MASK | HF_SMAP_MASK);

    /* SSE handling */
    if (!(env->features[FEAT_1_EDX] & CPUID_SSE)) {
        new_cr4 &= ~CR4_OSFXSR_MASK;
    }
    if (new_cr4 & CR4_OSFXSR_MASK) {
        hflags |= HF_OSFXSR_MASK;
    }

    if (!(env->features[FEAT_7_0_EBX] & CPUID_7_0_EBX_SMAP)) {
        new_cr4 &= ~CR4_SMAP_MASK;
    }
    if (new_cr4 & CR4_SMAP_MASK) {
        hflags |= HF_SMAP_MASK;
    }

    if (!(env->features[FEAT_7_0_ECX] & CPUID_7_0_ECX_PKU)) {
        new_cr4 &= ~CR4_PKE_MASK;
    }

    env->cr[4] = new_cr4;
    env->hflags = hflags;

    cpu_sync_bndcs_hflags(env);
}

//hardcode temporary
extern uint64_t kernel_entry;

#define LONGMODE_BOOT 1

static void reset_vcpu_env_regs(struct kvm_vcpu *vcpu)
{
	int i;
	uint64_t cr4;
	CPUX86State *env;

	env = (CPUX86State *)vcpu->arch.env;

	env->hflags2 |= HF2_GIF_MASK;

    if (LONGMODE_BOOT && 0 == env->apic_id) {
        cpu_x86_update_cr0(env, (CR0_PG_MASK | CR0_PE_MASK));
    } else {
        cpu_x86_update_cr0(env, 0x60000010);
	}

	env->smbase = 0x30000;
    env->msr_smi_count = 0;

    if (LONGMODE_BOOT && 0 == env->apic_id) {
        uint64_t gdt[4];

        gdt[0] = gdt_entry(0, 0, 0),            // NULL
        gdt[1] = gdt_entry(0xa09b, 0, 0xfffff), // CODE
        gdt[2] = gdt_entry(0xc093, 0, 0xfffff), // DATA
        gdt[3] = gdt_entry(0x808b, 0, 0xfffff), // TSS

        //write gdt table to guest memory
        write_gdt_table(vcpu, gdt, sizeof(gdt));
        env->gdt.base = BOOT_GDT_OFFSET;
        env->gdt.limit = sizeof(gdt) - 1;

        //write idt table to guest memory
        write_idt_value(vcpu, 0);
        env->idt.base = BOOT_IDT_OFFSET;
        env->idt.limit = sizeof(uint64_t) - 1;

        cpu_x86_load_seg_cache(env, R_CS, 1 * 8, 0, 0xfffff, 0xa09b << 8);
        cpu_x86_load_seg_cache(env, R_DS, 2 * 8, 0, 0xfffff, 0xc093 << 8);
        cpu_x86_load_seg_cache(env, R_ES, 2 * 8, 0, 0xfffff, 0xc093 << 8);
        cpu_x86_load_seg_cache(env, R_FS, 2 * 8, 0, 0xfffff, 0xc093 << 8);
        cpu_x86_load_seg_cache(env, R_GS, 2 * 8, 0, 0xfffff, 0xc093 << 8);
        cpu_x86_load_seg_cache(env, R_SS, 2 * 8, 0, 0xfffff, 0xc093 << 8);

        env->tr.selector = 3 * 8;
        env->tr.base = 0;
        env->tr.limit = 0xfffff;
        env->tr.flags = 0x808b << 8;

        env->regs[R_ESP] = BOOT_STACK_POINTER;
        env->regs[R_EBP] = BOOT_STACK_POINTER;
        env->eip = kernel_entry;
        env->regs[R_ESI] = ZERO_PAGE_START;

        setup_page_tables(vcpu);
        env->cr[3] = PML4_START;
    } else {
        env->idt.limit = 0xffff;
        env->gdt.limit = 0xffff;
        env->ldt.limit = 0xffff;
        env->ldt.flags = DESC_P_MASK | (2 << DESC_TYPE_SHIFT);
        env->tr.limit = 0xffff;
        env->tr.flags = DESC_P_MASK | (11 << DESC_TYPE_SHIFT);

        cpu_x86_load_seg_cache(env, R_CS, 0xf000, 0xffff0000, 0xffff,
                           DESC_P_MASK | DESC_S_MASK | DESC_CS_MASK |
                           DESC_R_MASK | DESC_A_MASK);
        cpu_x86_load_seg_cache(env, R_DS, 0, 0, 0xffff,
                           DESC_P_MASK | DESC_S_MASK | DESC_W_MASK |
                           DESC_A_MASK);
        cpu_x86_load_seg_cache(env, R_ES, 0, 0, 0xffff,
                           DESC_P_MASK | DESC_S_MASK | DESC_W_MASK |
                           DESC_A_MASK);
        cpu_x86_load_seg_cache(env, R_SS, 0, 0, 0xffff,
                           DESC_P_MASK | DESC_S_MASK | DESC_W_MASK |
                           DESC_A_MASK);
        cpu_x86_load_seg_cache(env, R_FS, 0, 0, 0xffff,
                           DESC_P_MASK | DESC_S_MASK | DESC_W_MASK |
                           DESC_A_MASK);
        cpu_x86_load_seg_cache(env, R_GS, 0, 0, 0xffff,
                           DESC_P_MASK | DESC_S_MASK | DESC_W_MASK |
                           DESC_A_MASK);

        env->eip = 0xfff0;
    }

    env->regs[R_EDX] = env->cpuid_version;
    env->eflags = 0x2;


    /* FPU init */
    for (i = 0; i < 8; i++) {
        env->fptags[i] = 1;
    }
	env->fpuc = 0x37f;
	
    env->mxcsr = 0x1f80;
    /* All units are in INIT state.  */
    env->xstate_bv = 0;

    env->pat = 0x0007040600070406ULL;
    env->msr_ia32_misc_enable = MSR_IA32_MISC_ENABLE_DEFAULT;
    if (env->features[FEAT_1_ECX] & CPUID_EXT_MONITOR) {
        env->msr_ia32_misc_enable |= MSR_IA32_MISC_ENABLE_MWAIT;
    }


    memset(env->dr, 0, sizeof(env->dr));
    env->dr[6] = DR6_FIXED_1;
    env->dr[7] = DR7_FIXED_1;

    if (LONGMODE_BOOT && 0 == env->apic_id)
        cr4 = X86_CR4_PAE;
    else
        cr4 = 0;

    env->xcr0 = XSTATE_FP_MASK;
    cpu_x86_update_cr4(env, cr4);

    if (LONGMODE_BOOT && 0 == env->apic_id)
        env->efer |= EFER_LME | EFER_LMA;

    env->mtrr_deftype = 0;
    memset(env->mtrr_var, 0, sizeof(env->mtrr_var));
    memset(env->mtrr_fixed, 0, sizeof(env->mtrr_fixed));

	env->xcr0 = 1;

	env->mp_state = env->apic_id == 0 ? KVM_MP_STATE_RUNNABLE :
                                          KVM_MP_STATE_UNINITIALIZED;

	env->poll_control_msr = 1;
}

static void x86_cpu_xsave_all_areas(CPUX86State *env, X86XSaveArea *xsave)
{
    uint16_t cwd, swd, twd;
    int i;
    memset(xsave, 0, sizeof(X86XSaveArea));
    twd = 0;
    swd = env->fpus & ~(7 << 11);
    swd |= (env->fpstt & 7) << 11;
    cwd = env->fpuc;
    for (i = 0; i < 8; ++i) {
        twd |= (!env->fptags[i]) << i;
    }
    xsave->legacy.fcw = cwd;
    xsave->legacy.fsw = swd;
    xsave->legacy.ftw = twd;
    xsave->legacy.fpop = env->fpop;
    xsave->legacy.fpip = env->fpip;
    xsave->legacy.fpdp = env->fpdp;
    memcpy(&xsave->legacy.fpregs, env->fpregs,
            sizeof env->fpregs);
    xsave->legacy.mxcsr = env->mxcsr;
    xsave->header.xstate_bv = env->xstate_bv;
    memcpy(&xsave->bndreg_state.bnd_regs, env->bnd_regs,
            sizeof env->bnd_regs);
    xsave->bndcsr_state.bndcsr = env->bndcs_regs;
    memcpy(&xsave->opmask_state.opmask_regs, env->opmask_regs,
            sizeof env->opmask_regs);

    for (i = 0; i < CPU_NB_REGS; i++) {
        uint8_t *xmm = xsave->legacy.xmm_regs[i];
        uint8_t *ymmh = xsave->avx_state.ymmh[i];
        uint8_t *zmmh = xsave->zmm_hi256_state.zmm_hi256[i];
        stq_p(xmm,     env->xmm_regs[i].ZMM_Q(0));
        stq_p(xmm+8,   env->xmm_regs[i].ZMM_Q(1));
        stq_p(ymmh,    env->xmm_regs[i].ZMM_Q(2));
        stq_p(ymmh+8,  env->xmm_regs[i].ZMM_Q(3));
        stq_p(zmmh,    env->xmm_regs[i].ZMM_Q(4));
        stq_p(zmmh+8,  env->xmm_regs[i].ZMM_Q(5));
        stq_p(zmmh+16, env->xmm_regs[i].ZMM_Q(6));
        stq_p(zmmh+24, env->xmm_regs[i].ZMM_Q(7));
    }

    memcpy(&xsave->hi16_zmm_state.hi16_zmm, &env->xmm_regs[16],
            16 * sizeof env->xmm_regs[16]);
    memcpy(&xsave->pkru_state, &env->pkru, sizeof env->pkru);
}

static int put_env_xsave(struct kvm_vcpu *vcpu)
{
	CPUX86State *env = (CPUX86State *)vcpu->arch.env;

	X86XSaveArea *xsave = env->xsave_buf;

	x86_cpu_xsave_all_areas(env, xsave);

	return kvm_vcpu_ioctl_x86_set_xsave(vcpu, (struct kvm_xsave *)xsave);
}

static int put_env_xcrs(struct kvm_vcpu *vcpu)
{
	CPUX86State *env = (CPUX86State *)vcpu->arch.env;
    struct kvm_xcrs xcrs = {};

    xcrs.nr_xcrs = 1;
    xcrs.flags = 0;
    xcrs.xcrs[0].xcr = 0;
    xcrs.xcrs[0].value = env->xcr0;

	return kvm_vcpu_ioctl_x86_set_xcrs(vcpu, &xcrs);
}

static void kvm_getput_reg(uint64_t *dst_reg, uint64_t *src_reg, int set)
{
    if (set) {
        *dst_reg = *src_reg;
    } else {
        *src_reg = *dst_reg;
    }
}

static int put_env_regs(struct kvm_vcpu *vcpu)
{
	CPUX86State *env = (CPUX86State *)vcpu->arch.env;
	struct kvm_regs regs;

    kvm_getput_reg(&regs.rax, &env->regs[R_EAX], 1);
    kvm_getput_reg(&regs.rbx, &env->regs[R_EBX], 1);
    kvm_getput_reg(&regs.rcx, &env->regs[R_ECX], 1);
    kvm_getput_reg(&regs.rdx, &env->regs[R_EDX], 1);
    kvm_getput_reg(&regs.rsi, &env->regs[R_ESI], 1);
    kvm_getput_reg(&regs.rdi, &env->regs[R_EDI], 1);
    kvm_getput_reg(&regs.rsp, &env->regs[R_ESP], 1);
    kvm_getput_reg(&regs.rbp, &env->regs[R_EBP], 1);
    kvm_getput_reg(&regs.r8, &env->regs[8], 1);
    kvm_getput_reg(&regs.r9, &env->regs[9], 1);
    kvm_getput_reg(&regs.r10, &env->regs[10], 1);
    kvm_getput_reg(&regs.r11, &env->regs[11], 1);
    kvm_getput_reg(&regs.r12, &env->regs[12], 1);
    kvm_getput_reg(&regs.r13, &env->regs[13], 1);
    kvm_getput_reg(&regs.r14, &env->regs[14], 1);
    kvm_getput_reg(&regs.r15, &env->regs[15], 1);

    kvm_getput_reg(&regs.rflags, &env->eflags, 1);
    kvm_getput_reg(&regs.rip, &env->eip, 1);

	return kvm_arch_vcpu_ioctl_set_regs(vcpu, &regs);
}

static void set_v8086_seg(struct kvm_segment *lhs, const SegmentCache *rhs)
{
    lhs->selector = rhs->selector;
    lhs->base = rhs->base;
    lhs->limit = rhs->limit;
    lhs->type = 3;
    lhs->present = 1;
    lhs->dpl = 3;
    lhs->db = 0;
    lhs->s = 1;
    lhs->l = 0;
    lhs->g = 0;
    lhs->avl = 0;
    lhs->unusable = 0;
}

static void set_seg(struct kvm_segment *lhs, const SegmentCache *rhs)
{
    unsigned flags = rhs->flags;
    lhs->selector = rhs->selector;
    lhs->base = rhs->base;
    lhs->limit = rhs->limit;
    lhs->type = (flags >> DESC_TYPE_SHIFT) & 15;
    lhs->present = (flags & DESC_P_MASK) != 0;
    lhs->dpl = (flags >> DESC_DPL_SHIFT) & 3;
    lhs->db = (flags >> DESC_B_SHIFT) & 1;
    lhs->s = (flags & DESC_S_MASK) != 0;
    lhs->l = (flags >> DESC_L_SHIFT) & 1;
    lhs->g = (flags & DESC_G_MASK) != 0;
    lhs->avl = (flags & DESC_AVL_MASK) != 0;
    lhs->unusable = !lhs->present;
    lhs->padding = 0;
}

static int put_env_sregs(struct kvm_vcpu *vcpu)
{
	CPUX86State *env = (CPUX86State *)vcpu->arch.env;
	struct kvm_sregs sregs;

	memset(sregs.interrupt_bitmap, 0, sizeof(sregs.interrupt_bitmap));

	if ((env->eflags & VM_MASK)) {
        set_v8086_seg(&sregs.cs, &env->segs[R_CS]);
        set_v8086_seg(&sregs.ds, &env->segs[R_DS]);
        set_v8086_seg(&sregs.es, &env->segs[R_ES]);
        set_v8086_seg(&sregs.fs, &env->segs[R_FS]);
        set_v8086_seg(&sregs.gs, &env->segs[R_GS]);
        set_v8086_seg(&sregs.ss, &env->segs[R_SS]);
    } else {
        set_seg(&sregs.cs, &env->segs[R_CS]);
        set_seg(&sregs.ds, &env->segs[R_DS]);
        set_seg(&sregs.es, &env->segs[R_ES]);
        set_seg(&sregs.fs, &env->segs[R_FS]);
        set_seg(&sregs.gs, &env->segs[R_GS]);
        set_seg(&sregs.ss, &env->segs[R_SS]);
    }

    set_seg(&sregs.tr, &env->tr);
    set_seg(&sregs.ldt, &env->ldt);

    sregs.idt.limit = env->idt.limit;
    sregs.idt.base = env->idt.base;
    memset(sregs.idt.padding, 0, sizeof sregs.idt.padding);
    sregs.gdt.limit = env->gdt.limit;
    sregs.gdt.base = env->gdt.base;
    memset(sregs.gdt.padding, 0, sizeof sregs.gdt.padding);

    sregs.cr0 = env->cr[0];
    sregs.cr2 = env->cr[2];
    sregs.cr3 = env->cr[3];
    sregs.cr4 = env->cr[4];

    sregs.cr8 = 0;
    sregs.apic_base = env->apic_id == 0 ? 0xfee00900 : 0xfee00800;

    sregs.efer = env->efer;

	return kvm_arch_vcpu_ioctl_set_sregs(vcpu, &sregs);
}

static void kvm_msr_entry_add(CPUX86State *env, uint32_t index, uint64_t value)
{
    struct kvm_msrs *msrs = env->kvm_msr_buf;
    struct kvm_msr_entry *entry = &msrs->entries[msrs->nmsrs];

    entry->index = index;
    entry->reserved = 0;
    entry->data = value;
    msrs->nmsrs++;
}

static uint64_t make_vmx_msr_value(uint32_t index, uint32_t features)
{
    uint32_t default1, can_be_one, can_be_zero;
    uint32_t must_be_one;

    switch (index) {
    case MSR_IA32_VMX_TRUE_PINBASED_CTLS:
        default1 = 0x00000016;
        break;
    case MSR_IA32_VMX_TRUE_PROCBASED_CTLS:
        default1 = 0x0401e172;
        break;
    case MSR_IA32_VMX_TRUE_ENTRY_CTLS:
        default1 = 0x000011ff;
        break;
    case MSR_IA32_VMX_TRUE_EXIT_CTLS:
        default1 = 0x00036dff;
        break;
    case MSR_IA32_VMX_PROCBASED_CTLS2:
        default1 = 0;
        break;
    default:
		return 0;
    }
    /* If a feature bit is set, the control can be either set or clear.
     * Otherwise the value is limited to either 0 or 1 by default1.
     */
    can_be_one = features | default1;
    can_be_zero = features | ~default1;
    must_be_one = ~can_be_zero;

    /*
     * Bit 0:31 -> 0 if the control bit can be zero (i.e. 1 if it must be one).
     * Bit 32:63 -> 1 if the control bit can be one.
     */
    return must_be_one | (((uint64_t)can_be_one) << 32);
}



static void kvm_msr_entry_add_vmx(CPUX86State *env, FeatureWordArray f)
{
    uint64_t kvm_vmx_basic;
    uint64_t kvm_vmx_misc;
	uint64_t kvm_vmx_ept_vpid;
	uint64_t fixed_vmx_exit;
	uint64_t fixed_vmx_basic;
	uint64_t fixed_vmx_misc;
    uint64_t fixed_vmx_ept_mask;
    uint64_t fixed_vmx_ept_vpid;

    kvm_vmx_basic = kvm_arch_get_supported_msr_feature(MSR_IA32_VMX_BASIC);

    if (!kvm_vmx_basic) {
        /* If the kernel doesn't support VMX feature (kvm_intel.nested=0),
         * then kvm_vmx_basic will be 0 and KVM_SET_MSR will fail.
         */
        return;
    }

    kvm_vmx_misc =
        kvm_arch_get_supported_msr_feature(MSR_IA32_VMX_MISC);
    kvm_vmx_ept_vpid =
        kvm_arch_get_supported_msr_feature(MSR_IA32_VMX_EPT_VPID_CAP);

    /*
     * If the guest is 64-bit, a value of 1 is allowed for the host address
     * space size vmexit control.
     */
    fixed_vmx_exit = f[FEAT_8000_0001_EDX] & CPUID_EXT2_LM
        ? (uint64_t)VMX_VM_EXIT_HOST_ADDR_SPACE_SIZE << 32 : 0;

    fixed_vmx_basic = kvm_vmx_basic &
        (MSR_VMX_BASIC_VMCS_REVISION_MASK |
         MSR_VMX_BASIC_VMXON_REGION_SIZE_MASK |
         MSR_VMX_BASIC_VMCS_MEM_TYPE_MASK);

    /*
     * Same for bits 0-4 and 25-27.  Bits 16-24 (CR3 target count) can
     * change in the future but are always zero for now, clear them to be
     * future proof.  Bits 32-63 in theory could change, though KVM does
     * not support dual-monitor treatment and probably never will; mask
     * them out as well.
     */
    fixed_vmx_misc = kvm_vmx_misc &
        (MSR_VMX_MISC_PREEMPTION_TIMER_SHIFT_MASK |
         MSR_VMX_MISC_MAX_MSR_LIST_SIZE_MASK);

    /*
     * EPT memory types should not change either, so we do not bother
     * adding features for them.
     */
    fixed_vmx_ept_mask =
            (f[FEAT_VMX_SECONDARY_CTLS] & VMX_SECONDARY_EXEC_ENABLE_EPT ?
             MSR_VMX_EPT_UC | MSR_VMX_EPT_WB : 0);
    fixed_vmx_ept_vpid = kvm_vmx_ept_vpid & fixed_vmx_ept_mask;

    kvm_msr_entry_add(env, MSR_IA32_VMX_TRUE_PROCBASED_CTLS,
                      make_vmx_msr_value(MSR_IA32_VMX_TRUE_PROCBASED_CTLS,
                                         f[FEAT_VMX_PROCBASED_CTLS]));
    kvm_msr_entry_add(env, MSR_IA32_VMX_TRUE_PINBASED_CTLS,
                      make_vmx_msr_value(MSR_IA32_VMX_TRUE_PINBASED_CTLS,
                                         f[FEAT_VMX_PINBASED_CTLS]));
    kvm_msr_entry_add(env, MSR_IA32_VMX_TRUE_EXIT_CTLS,
                      make_vmx_msr_value(MSR_IA32_VMX_TRUE_EXIT_CTLS,
                                         f[FEAT_VMX_EXIT_CTLS]) | fixed_vmx_exit);
    kvm_msr_entry_add(env, MSR_IA32_VMX_TRUE_ENTRY_CTLS,
                      make_vmx_msr_value(MSR_IA32_VMX_TRUE_ENTRY_CTLS,
                                         f[FEAT_VMX_ENTRY_CTLS]));
    kvm_msr_entry_add(env, MSR_IA32_VMX_PROCBASED_CTLS2,
                      make_vmx_msr_value(MSR_IA32_VMX_PROCBASED_CTLS2,
                                         f[FEAT_VMX_SECONDARY_CTLS]));
    kvm_msr_entry_add(env, MSR_IA32_VMX_EPT_VPID_CAP,
                      f[FEAT_VMX_EPT_VPID_CAPS] | fixed_vmx_ept_vpid);
    kvm_msr_entry_add(env, MSR_IA32_VMX_BASIC,
                      f[FEAT_VMX_BASIC] | fixed_vmx_basic);
    kvm_msr_entry_add(env, MSR_IA32_VMX_MISC,
                      f[FEAT_VMX_MISC] | fixed_vmx_misc);

    if (has_msr_vmx_vmfunc) {
        kvm_msr_entry_add(env, MSR_IA32_VMX_VMFUNC, f[FEAT_VMX_VMFUNC]);
    }

    /*
     * Just to be safe, write these with constant values.  The CRn_FIXED1
     * MSRs are generated by KVM based on the vCPU's CPUID.
     */
    kvm_msr_entry_add(env, MSR_IA32_VMX_CR0_FIXED0, CR0_PE_MASK | CR0_PG_MASK | CR0_NE_MASK);

    kvm_msr_entry_add(env, MSR_IA32_VMX_CR4_FIXED0, CR4_VMXE_MASK);

    kvm_msr_entry_add(env, MSR_IA32_VMX_VMCS_ENUM, VMCS12_MAX_FIELD_INDEX << 1);
}


static int put_env_msrs(struct kvm_vcpu *vcpu)
{
	CPUX86State *env = (CPUX86State *)vcpu->arch.env;
    int i;
    int ret;

	memset(env->kvm_msr_buf, 0, MSR_BUF_SIZE);

    kvm_msr_entry_add(env, MSR_IA32_SYSENTER_CS, env->sysenter_cs);
    kvm_msr_entry_add(env, MSR_IA32_SYSENTER_ESP, env->sysenter_esp);
    kvm_msr_entry_add(env, MSR_IA32_SYSENTER_EIP, env->sysenter_eip);
    kvm_msr_entry_add(env, MSR_IA32_CR_PAT, env->pat);
    if (has_msr_star) {
        kvm_msr_entry_add(env, MSR_STAR, env->star);
    }
    if (has_msr_hsave_pa) {
        kvm_msr_entry_add(env, MSR_VM_HSAVE_PA, env->vm_hsave);
    }
    if (has_msr_tsc_aux) {
        kvm_msr_entry_add(env, MSR_TSC_AUX, env->tsc_aux);
    }
    if (has_msr_tsc_adjust) {
        kvm_msr_entry_add(env, MSR_IA32_TSC_ADJUST, env->tsc_adjust);
    }
    if (has_msr_misc_enable) {
        kvm_msr_entry_add(env, MSR_IA32_MISC_ENABLE,
                          env->msr_ia32_misc_enable);
    }
    if (has_msr_smbase) {
        kvm_msr_entry_add(env, MSR_IA32_SMBASE, env->smbase);
    }
    if (has_msr_smi_count) {
        kvm_msr_entry_add(env, MSR_SMI_COUNT, env->msr_smi_count);
    }
    if (has_msr_bndcfgs) {
        kvm_msr_entry_add(env, MSR_IA32_BNDCFGS, env->msr_bndcfgs);
    }
    if (has_msr_xss) {
        kvm_msr_entry_add(env, MSR_IA32_XSS, env->xss);
    }
    if (has_msr_umwait) {
        kvm_msr_entry_add(env, MSR_IA32_UMWAIT_CONTROL, env->umwait);
    }
    if (has_msr_spec_ctrl) {
        kvm_msr_entry_add(env, MSR_IA32_SPEC_CTRL, env->spec_ctrl);
    }
    if (has_msr_tsx_ctrl) {
        kvm_msr_entry_add(env, MSR_IA32_TSX_CTRL, env->tsx_ctrl);
    }
    if (has_msr_virt_ssbd) {
        kvm_msr_entry_add(env, MSR_VIRT_SSBD, env->virt_ssbd);
    }

    kvm_msr_entry_add(env, MSR_CSTAR, env->cstar);
    kvm_msr_entry_add(env, MSR_KERNEL_GS_BASE, env->kernelgsbase);
    kvm_msr_entry_add(env, MSR_SYSCALL_MASK, env->fmask);
    kvm_msr_entry_add(env, MSR_LSTAR, env->lstar);

    /* If host supports feature MSR, write down. */
    if (has_msr_arch_capabs) {
        kvm_msr_entry_add(env, MSR_IA32_ARCH_CAPABILITIES,
                          env->features[FEAT_ARCH_CAPABILITIES]);
    }

    if (has_msr_core_capabs) {
        kvm_msr_entry_add(env, MSR_IA32_CORE_CAPABILITY,
                          env->features[FEAT_CORE_CAPABILITY]);
    }

    kvm_msr_entry_add(env, MSR_IA32_TSC, env->tsc);
    kvm_msr_entry_add(env, MSR_KVM_SYSTEM_TIME, env->system_time_msr);
    kvm_msr_entry_add(env, MSR_KVM_WALL_CLOCK, env->wall_clock_msr);
    if (env->features[FEAT_KVM] & (1 << KVM_FEATURE_ASYNC_PF)) {
        kvm_msr_entry_add(env, MSR_KVM_ASYNC_PF_EN, env->async_pf_en_msr);
    }
    if (env->features[FEAT_KVM] & (1 << KVM_FEATURE_PV_EOI)) {
        kvm_msr_entry_add(env, MSR_KVM_PV_EOI_EN, env->pv_eoi_en_msr);
    }
    if (env->features[FEAT_KVM] & (1 << KVM_FEATURE_STEAL_TIME)) {
        kvm_msr_entry_add(env, MSR_KVM_STEAL_TIME, env->steal_time_msr);
    }

    if (env->features[FEAT_KVM] & (1 << KVM_FEATURE_POLL_CONTROL)) {
        kvm_msr_entry_add(env, MSR_KVM_POLL_CONTROL, env->poll_control_msr);
    }

    if (has_architectural_pmu_version > 0) {
            if (has_architectural_pmu_version > 1) {
                /* Stop the counter.  */
                kvm_msr_entry_add(env, MSR_CORE_PERF_FIXED_CTR_CTRL, 0);
                kvm_msr_entry_add(env, MSR_CORE_PERF_GLOBAL_CTRL, 0);
            }

            /* Set the counter values.  */
            for (i = 0; i < num_architectural_pmu_fixed_counters; i++) {
                kvm_msr_entry_add(env, MSR_CORE_PERF_FIXED_CTR0 + i,
                                  env->msr_fixed_counters[i]);
            }
            for (i = 0; i < num_architectural_pmu_gp_counters; i++) {
                kvm_msr_entry_add(env, MSR_P6_PERFCTR0 + i,
                                  env->msr_gp_counters[i]);
                kvm_msr_entry_add(env, MSR_P6_EVNTSEL0 + i,
                                  env->msr_gp_evtsel[i]);
            }
            if (has_architectural_pmu_version > 1) {
                kvm_msr_entry_add(env, MSR_CORE_PERF_GLOBAL_STATUS,
                                  env->msr_global_status);
                kvm_msr_entry_add(env, MSR_CORE_PERF_GLOBAL_OVF_CTRL,
                                  env->msr_global_ovf_ctrl);

                /* Now start the PMU.  */
                kvm_msr_entry_add(env, MSR_CORE_PERF_FIXED_CTR_CTRL,
                                  env->msr_fixed_ctr_ctrl);
                kvm_msr_entry_add(env, MSR_CORE_PERF_GLOBAL_CTRL,
                                  env->msr_global_ctrl);
            }
    }

    if (env->apic_id == 0) {
            if (has_msr_hv_hypercall) {
                kvm_msr_entry_add(env, HV_X64_MSR_GUEST_OS_ID,
                                  env->msr_hv_guest_os_id);
                kvm_msr_entry_add(env, HV_X64_MSR_HYPERCALL,
                                  env->msr_hv_hypercall);
            }
    }

    if (has_msr_hv_crash) {
            int j;

            for (j = 0; j < HV_CRASH_PARAMS; j++)
                kvm_msr_entry_add(env, HV_X64_MSR_CRASH_P0 + j,
                                  env->msr_hv_crash_params[j]);

            kvm_msr_entry_add(env, HV_X64_MSR_CRASH_CTL, HV_CRASH_CTL_NOTIFY);
    }
    if (has_msr_hv_runtime) {
            kvm_msr_entry_add(env, HV_X64_MSR_VP_RUNTIME, env->msr_hv_runtime);
    }

    if (has_msr_hv_stimer) {
        int j;

        for (j = 0; j < ARRAY_SIZE(env->msr_hv_stimer_config); j++) {
            kvm_msr_entry_add(env, HV_X64_MSR_STIMER0_CONFIG + j * 2,
                                env->msr_hv_stimer_config[j]);
        }

        for (j = 0; j < ARRAY_SIZE(env->msr_hv_stimer_count); j++) {
                kvm_msr_entry_add(env, HV_X64_MSR_STIMER0_COUNT + j * 2,
                                env->msr_hv_stimer_count[j]);
        }
    }

    if (env->features[FEAT_1_EDX] & CPUID_MTRR) {
            uint64_t phys_mask = MAKE_64BIT_MASK(0, env->phys_bits);

            kvm_msr_entry_add(env, MSR_MTRRdefType, env->mtrr_deftype);
            kvm_msr_entry_add(env, MSR_MTRRfix64K_00000, env->mtrr_fixed[0]);
            kvm_msr_entry_add(env, MSR_MTRRfix16K_80000, env->mtrr_fixed[1]);
            kvm_msr_entry_add(env, MSR_MTRRfix16K_A0000, env->mtrr_fixed[2]);
            kvm_msr_entry_add(env, MSR_MTRRfix4K_C0000, env->mtrr_fixed[3]);
            kvm_msr_entry_add(env, MSR_MTRRfix4K_C8000, env->mtrr_fixed[4]);
            kvm_msr_entry_add(env, MSR_MTRRfix4K_D0000, env->mtrr_fixed[5]);
            kvm_msr_entry_add(env, MSR_MTRRfix4K_D8000, env->mtrr_fixed[6]);
            kvm_msr_entry_add(env, MSR_MTRRfix4K_E0000, env->mtrr_fixed[7]);
            kvm_msr_entry_add(env, MSR_MTRRfix4K_E8000, env->mtrr_fixed[8]);
            kvm_msr_entry_add(env, MSR_MTRRfix4K_F0000, env->mtrr_fixed[9]);
            kvm_msr_entry_add(env, MSR_MTRRfix4K_F8000, env->mtrr_fixed[10]);
            for (i = 0; i < MSR_MTRRcap_VCNT; i++) {
                /* The CPU GPs if we write to a bit above the physical limit of
                 * the host CPU (and KVM emulates that)
                 */
                uint64_t mask = env->mtrr_var[i].mask;
                mask &= phys_mask;

                kvm_msr_entry_add(env, MSR_MTRRphysBase(i),
                                  env->mtrr_var[i].base);
                kvm_msr_entry_add(env, MSR_MTRRphysMask(i), mask);
            }
    }
    if (env->features[FEAT_7_0_EBX] & CPUID_7_0_EBX_INTEL_PT) {
            int addr_num = kvm_arch_get_supported_cpuid(0x14, 1, R_EAX) & 0x7;

            kvm_msr_entry_add(env, MSR_IA32_RTIT_CTL,
                            env->msr_rtit_ctrl);
            kvm_msr_entry_add(env, MSR_IA32_RTIT_STATUS,
                            env->msr_rtit_status);
            kvm_msr_entry_add(env, MSR_IA32_RTIT_OUTPUT_BASE,
                            env->msr_rtit_output_base);
            kvm_msr_entry_add(env, MSR_IA32_RTIT_OUTPUT_MASK,
                            env->msr_rtit_output_mask);
            kvm_msr_entry_add(env, MSR_IA32_RTIT_CR3_MATCH,
                            env->msr_rtit_cr3_match);
            for (i = 0; i < addr_num; i++) {
                kvm_msr_entry_add(env, MSR_IA32_RTIT_ADDR0_A + i,
                            env->msr_rtit_addrs[i]);
            }
    }
    if (kvm_feature_msrs && (env->features[FEAT_1_ECX] & CPUID_EXT_VMX)) {
            kvm_msr_entry_add_vmx(env, env->features);
    }

    if (env->mcg_cap) {
        int i;

        kvm_msr_entry_add(env, MSR_MCG_STATUS, env->mcg_status);
        kvm_msr_entry_add(env, MSR_MCG_CTL, env->mcg_ctl);
        if (has_msr_mcg_ext_ctl) {
            kvm_msr_entry_add(env, MSR_MCG_EXT_CTL, env->mcg_ext_ctl);
        }
        for (i = 0; i < (env->mcg_cap & 0xff) * 4; i++) {
            kvm_msr_entry_add(env, MSR_MC0_CTL + i, env->mce_banks[i]);
        }
    }

	ret = __msr_io(vcpu, env->kvm_msr_buf, env->kvm_msr_buf->entries, do_set_msr);
    if (ret < 0) {
        return ret;
    }

    return 0;
}

static int put_env_events(struct kvm_vcpu *vcpu)
{
	CPUX86State *env = (CPUX86State *)vcpu->arch.env;
	struct kvm_vcpu_events events = {};

    events.flags = 0;

    events.exception.nr = -1;
    events.exception.injected = 0;
    events.exception.has_error_code = 0;
    events.exception.error_code = 0;

    events.interrupt.injected =  0;
    events.interrupt.nr = -1;
    events.interrupt.soft = 0;

    events.nmi.injected = 0;
    events.nmi.pending = 0;
    events.nmi.masked = !!(env->hflags2 & HF2_NMI_MASK);

    events.sipi_vector = 0;

    if (has_msr_smbase) {
        events.smi.smm = !!(env->hflags & HF_SMM_MASK);
        events.smi.smm_inside_nmi = !!(env->hflags2 & HF2_SMM_INSIDE_NMI_MASK);
        /* As soon as these are moved to the kernel, remove them
         * from cs->interrupt_request.
         */
        events.smi.pending = 0;
        events.smi.latched_init = 0;

        /* Stop SMI delivery on old machine types to avoid a reboot
         * on an inward migration of an old VM.
         */
        events.flags |= KVM_VCPUEVENT_VALID_SMM;
    }

    events.flags |= KVM_VCPUEVENT_VALID_NMI_PENDING;
    if (env->mp_state == KVM_MP_STATE_SIPI_RECEIVED) {
        events.flags |= KVM_VCPUEVENT_VALID_SIPI_VECTOR;
    }

	return kvm_vcpu_ioctl_x86_set_vcpu_events(vcpu,  &events);
}

static int put_env_mp_state(struct kvm_vcpu *vcpu)
{
	CPUX86State *env = (CPUX86State *)vcpu->arch.env;
	struct kvm_mp_state mp_state = {.mp_state = env->mp_state };

	return kvm_arch_vcpu_ioctl_set_mpstate(vcpu, &mp_state);
}

static int put_env_debugregs(struct kvm_vcpu *vcpu)
{
	CPUX86State *env = (CPUX86State *)vcpu->arch.env;
    struct kvm_debugregs dbgregs;
    int i;

    memset(&dbgregs, 0, sizeof(dbgregs));
    for (i = 0; i < 4; i++) {
        dbgregs.db[i] = env->dr[i];
    }
    dbgregs.dr6 = env->dr[6];
    dbgregs.dr7 = env->dr[7];
    dbgregs.flags = 0;

	return kvm_vcpu_ioctl_x86_set_debugregs(vcpu, &dbgregs);
}

static inline void kvm_apic_set_reg(struct kvm_lapic_state *kapic,
                                    int reg_id, uint32_t val)
{
    *((uint32_t *)(kapic->regs + (reg_id << 4))) = val;
}

static void kvm_put_apic_state(CPUX86State *env, struct kvm_lapic_state *kapic)
{
    int i;

    memset(kapic, 0, sizeof(*kapic));

    kvm_apic_set_reg(kapic, 0x2, env->apic_id << 24);

    kvm_apic_set_reg(kapic, 0x8, 0); //tpr
    kvm_apic_set_reg(kapic, 0xd, 0 << 24); //log_dest
    kvm_apic_set_reg(kapic, 0xe, 0xf << 28 | 0x0fffffff); //dest_mode
    kvm_apic_set_reg(kapic, 0xf, 0xff); //spurious_vec

    for (i = 0; i < 8; i++) {
        kvm_apic_set_reg(kapic, 0x10 + i, 0); //isr[i]
        kvm_apic_set_reg(kapic, 0x18 + i, 0); //tmr[i]
        kvm_apic_set_reg(kapic, 0x20 + i, 0); //irr[i]
    }

    kvm_apic_set_reg(kapic, 0x28, 0); //esr
    kvm_apic_set_reg(kapic, 0x30, 0); //icr[0]
    kvm_apic_set_reg(kapic, 0x31, 0); //icr[1]

    for (i = 0; i < 6; i++) {
        kvm_apic_set_reg(kapic, 0x32 + i, APIC_LVT_MASKED); //lvt[i]
    }

    kvm_apic_set_reg(kapic, 0x38, 0); //initial_count
    kvm_apic_set_reg(kapic, 0x3e, 0); //divide_conf
}

static int put_lapic_state(struct kvm_vcpu *vcpu)
{
	CPUX86State *env = (CPUX86State *)vcpu->arch.env;
	struct kvm_lapic_state kapic;
	uint64_t apicbase = 0;
	int ret = 0;

	apicbase = APIC_DEFAULT_ADDRESS | MSR_IA32_APICBASE_ENABLE;
    if (env->apic_id == 0) {
        apicbase |= MSR_IA32_APICBASE_BSP;
    } else {
        apicbase &= ~MSR_IA32_APICBASE_BSP;
    }

	ret = do_set_msr(vcpu, MSR_IA32_APICBASE, &apicbase);
	if (ret)
		printk(">>>>fail=%d %s:%d\n", ret,  __func__, __LINE__);

    kvm_put_apic_state(env, &kapic);

	ret = kvm_vcpu_ioctl_set_lapic(vcpu, &kapic);
	if (ret)
		printk(">>>>fail=%d %s:%d\n", ret,  __func__, __LINE__);

	return ret;
}

static int put_vcpu_env_registers(struct kvm_vcpu *vcpu)
{
	int ret = 0;
	CPUX86State *env = (CPUX86State *)vcpu->arch.env;

	if (has_msr_feature_control) {
		ret = do_set_msr(vcpu, MSR_IA32_FEATURE_CONTROL,
			&env->msr_ia32_feature_control);
		if (ret)
			printk(">>>>fail=%d %s:%d\n", ret,  __func__, __LINE__);
	}

	if (env->tsc_khz > 0 &&  env->tsc_khz < kvm_max_guest_tsc_khz)
		kvm_set_tsc_khz(vcpu, env->tsc_khz);

	ret = put_env_regs(vcpu);
	if (ret)
		printk(">>>>fail=%d %s:%d\n", ret, __func__, __LINE__);

	ret = put_env_xsave(vcpu);
	if (ret)
		printk(">>>>fail=%d %s:%d\n", ret, __func__, __LINE__);

	ret = put_env_xcrs(vcpu);	
	if (ret)
		printk(">>>>fail=%d %s:%d\n", ret, __func__, __LINE__);

	ret = put_env_sregs(vcpu);	
	if (ret)
		printk(">>>>fail=%d %s:%d\n", ret, __func__, __LINE__);

    ret = put_env_msrs(vcpu);
    if (ret < 0)
		printk(">>>>fail=%d %s:%d\n", ret, __func__, __LINE__);

	ret = put_env_events(vcpu);
    if (ret < 0)
		printk(">>>>fail=%d %s:%d\n", ret, __func__, __LINE__);

	ret = put_env_mp_state(vcpu);
    if (ret < 0)
		printk(">>>>fail=%d %s:%d\n", ret, __func__, __LINE__);

    if (!has_msr_tsc_deadline) {
		ret = do_set_msr(vcpu, MSR_IA32_FEATURE_CONTROL, &env->tsc_deadline);
		if (ret)
			printk(">>>>fail=%d %s:%d\n", ret, __func__, __LINE__);
    }

	ret = put_env_debugregs(vcpu);
    if (ret < 0)
		printk(">>>>fail=%d %s:%d\n", ret, __func__, __LINE__);

	ret = put_lapic_state(vcpu);
    if (ret < 0)
		printk(">>>>fail=%d %s:%d\n", ret, __func__, __LINE__);

	return ret;
}

int init_vcpu_virt_regs(struct kvm_vcpu *vcpu)
{
	int r = 0;

	init_vcpu_cpuid2(vcpu);

	reset_vcpu_env_regs(vcpu);

	put_vcpu_env_registers(vcpu);

	return r;
}

