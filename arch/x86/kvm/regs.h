#ifndef ARCH_X86_KVM_CPU_H
#define ARCH_X86_KVM_CPU_H

#define MAX_RTIT_ADDRS                  8

#define HV_SINT_COUNT                         16
#define HV_STIMER_COUNT                       4

/* segment descriptor fields */
#define DESC_G_SHIFT    23
#define DESC_G_MASK     (1 << DESC_G_SHIFT)
#define DESC_B_SHIFT    22
#define DESC_B_MASK     (1 << DESC_B_SHIFT)
#define DESC_L_SHIFT    21 /* x86_64 only : 64 bit code segment */
#define DESC_L_MASK     (1 << DESC_L_SHIFT)
#define DESC_AVL_SHIFT  20
#define DESC_AVL_MASK   (1 << DESC_AVL_SHIFT)
#define DESC_P_SHIFT    15
#define DESC_P_MASK     (1 << DESC_P_SHIFT)
#define DESC_DPL_SHIFT  13
#define DESC_DPL_MASK   (3 << DESC_DPL_SHIFT)
#define DESC_S_SHIFT    12
#define DESC_S_MASK     (1 << DESC_S_SHIFT)
#define DESC_TYPE_SHIFT 8
#define DESC_TYPE_MASK  (15 << DESC_TYPE_SHIFT)
#define DESC_A_MASK     (1 << 8)

#define DESC_CS_MASK    (1 << 11) /* 1=code segment 0=data segment */
#define DESC_C_MASK     (1 << 10) /* code: conforming */
#define DESC_R_MASK     (1 << 9)  /* code: readable */

#define DESC_E_MASK     (1 << 10) /* data: expansion direction */
#define DESC_W_MASK     (1 << 9)  /* data: writable */ 

#define MAX(a, b) (((a) > (b)) ? (a) : (b))

#define CPUID_FP87 (1U << 0)
#define CPUID_VME  (1U << 1)
#define CPUID_DE   (1U << 2)
#define CPUID_PSE  (1U << 3)
#define CPUID_TSC  (1U << 4)
#define CPUID_MSR  (1U << 5)
#define CPUID_PAE  (1U << 6)
#define CPUID_MCE  (1U << 7)
#define CPUID_CX8  (1U << 8)
#define CPUID_APIC (1U << 9)
#define CPUID_SEP  (1U << 11) /* sysenter/sysexit */
#define CPUID_MTRR (1U << 12)
#define CPUID_PGE  (1U << 13)
#define CPUID_MCA  (1U << 14)
#define CPUID_CMOV (1U << 15)
#define CPUID_PAT  (1U << 16)
#define CPUID_PSE36   (1U << 17)
#define CPUID_PN   (1U << 18)
#define CPUID_CLFLUSH (1U << 19)
#define CPUID_DTS (1U << 21)
#define CPUID_ACPI (1U << 22)
#define CPUID_MMX  (1U << 23)
#define CPUID_FXSR (1U << 24)
#define CPUID_SSE  (1U << 25)
#define CPUID_SSE2 (1U << 26)
#define CPUID_SS (1U << 27)
#define CPUID_HT (1U << 28)
#define CPUID_TM (1U << 29)
#define CPUID_IA64 (1U << 30)
#define CPUID_PBE (1U << 31)




#define CPUID_EXT_SSE3     (1U << 0)
#define CPUID_EXT_PCLMULQDQ (1U << 1)
#define CPUID_EXT_DTES64   (1U << 2)
#define CPUID_EXT_MONITOR  (1U << 3)
#define CPUID_EXT_DSCPL    (1U << 4)
#define CPUID_EXT_VMX      (1U << 5)
#define CPUID_EXT_SMX      (1U << 6)
#define CPUID_EXT_EST      (1U << 7)
#define CPUID_EXT_TM2      (1U << 8)
#define CPUID_EXT_SSSE3    (1U << 9)
#define CPUID_EXT_CID      (1U << 10)
#define CPUID_EXT_FMA      (1U << 12)
#define CPUID_EXT_CX16     (1U << 13)
#define CPUID_EXT_XTPR     (1U << 14)
#define CPUID_EXT_PDCM     (1U << 15)
#define CPUID_EXT_PCID     (1U << 17)
#define CPUID_EXT_DCA      (1U << 18)
#define CPUID_EXT_SSE41    (1U << 19)
#define CPUID_EXT_SSE42    (1U << 20)
#define CPUID_EXT_X2APIC   (1U << 21)            
#define CPUID_EXT_MOVBE    (1U << 22)
#define CPUID_EXT_POPCNT   (1U << 23)
#define CPUID_EXT_TSC_DEADLINE_TIMER (1U << 24)
#define CPUID_EXT_AES      (1U << 25)            
#define CPUID_EXT_XSAVE    (1U << 26)
#define CPUID_EXT_OSXSAVE  (1U << 27)
#define CPUID_EXT_AVX      (1U << 28)
#define CPUID_EXT_F16C     (1U << 29)
#define CPUID_EXT_RDRAND   (1U << 30)
#define CPUID_EXT_HYPERVISOR  (1U << 31)

#define CPUID_EXT2_FPU     (1U << 0)
#define CPUID_EXT2_VME     (1U << 1)
#define CPUID_EXT2_DE      (1U << 2)
#define CPUID_EXT2_PSE     (1U << 3)
#define CPUID_EXT2_TSC     (1U << 4)
#define CPUID_EXT2_MSR     (1U << 5)
#define CPUID_EXT2_PAE     (1U << 6)
#define CPUID_EXT2_MCE     (1U << 7)
#define CPUID_EXT2_CX8     (1U << 8)
#define CPUID_EXT2_APIC    (1U << 9)
#define CPUID_EXT2_SYSCALL (1U << 11)
#define CPUID_EXT2_MTRR    (1U << 12)
#define CPUID_EXT2_PGE     (1U << 13)
#define CPUID_EXT2_MCA     (1U << 14)
#define CPUID_EXT2_CMOV    (1U << 15)
#define CPUID_EXT2_PAT     (1U << 16)
#define CPUID_EXT2_PSE36   (1U << 17)
#define CPUID_EXT2_MP      (1U << 19)
#define CPUID_EXT2_NX      (1U << 20)
#define CPUID_EXT2_MMXEXT  (1U << 22)
#define CPUID_EXT2_MMX     (1U << 23)
#define CPUID_EXT2_FXSR    (1U << 24)
#define CPUID_EXT2_FFXSR   (1U << 25)
#define CPUID_EXT2_PDPE1GB (1U << 26)
#define CPUID_EXT2_RDTSCP  (1U << 27)
#define CPUID_EXT2_LM      (1U << 29)
#define CPUID_EXT2_3DNOWEXT (1U << 30)
#define CPUID_EXT2_3DNOW   (1U << 31)

#define CPUID_EXT2_AMD_ALIASES (CPUID_EXT2_FPU | CPUID_EXT2_VME | \
                                CPUID_EXT2_DE | CPUID_EXT2_PSE | \
                                CPUID_EXT2_TSC | CPUID_EXT2_MSR | \
                                CPUID_EXT2_PAE | CPUID_EXT2_MCE | \
                                CPUID_EXT2_CX8 | CPUID_EXT2_APIC | \
                                CPUID_EXT2_MTRR | CPUID_EXT2_PGE | \
                                CPUID_EXT2_MCA | CPUID_EXT2_CMOV | \
                                CPUID_EXT2_PAT | CPUID_EXT2_PSE36 | \
                                CPUID_EXT2_MMX | CPUID_EXT2_FXSR)


#define CPUID_EXT3_LAHF_LM (1U << 0)
#define CPUID_EXT3_CMP_LEG (1U << 1)
#define CPUID_EXT3_SVM     (1U << 2)
#define CPUID_EXT3_EXTAPIC (1U << 3)
#define CPUID_EXT3_CR8LEG  (1U << 4)
#define CPUID_EXT3_ABM     (1U << 5)
#define CPUID_EXT3_SSE4A   (1U << 6) 
#define CPUID_EXT3_MISALIGNSSE (1U << 7)
#define CPUID_EXT3_3DNOWPREFETCH (1U << 8)
#define CPUID_EXT3_OSVW    (1U << 9)
#define CPUID_EXT3_IBS     (1U << 10) 
#define CPUID_EXT3_XOP     (1U << 11)
#define CPUID_EXT3_SKINIT  (1U << 12)
#define CPUID_EXT3_WDT     (1U << 13) 
#define CPUID_EXT3_LWP     (1U << 15)
#define CPUID_EXT3_FMA4    (1U << 16)
#define CPUID_EXT3_TCE     (1U << 17)
#define CPUID_EXT3_NODEID  (1U << 19)
#define CPUID_EXT3_TBM     (1U << 21)
#define CPUID_EXT3_TOPOEXT (1U << 22)
#define CPUID_EXT3_PERFCORE (1U << 23)
#define CPUID_EXT3_PERFNB  (1U << 24)

/* Support RDFSBASE/RDGSBASE/WRFSBASE/WRGSBASE */
#define CPUID_7_0_EBX_FSGSBASE          (1U << 0)
/* 1st Group of Advanced Bit Manipulation Extensions */
#define CPUID_7_0_EBX_BMI1              (1U << 3)
/* Hardware Lock Elision */
#define CPUID_7_0_EBX_HLE               (1U << 4)
/* Intel Advanced Vector Extensions 2 */
#define CPUID_7_0_EBX_AVX2              (1U << 5)
/* Supervisor-mode Execution Prevention */
#define CPUID_7_0_EBX_SMEP              (1U << 7)
/* 2nd Group of Advanced Bit Manipulation Extensions */
#define CPUID_7_0_EBX_BMI2              (1U << 8)
/* Enhanced REP MOVSB/STOSB */
#define CPUID_7_0_EBX_ERMS              (1U << 9)
/* Invalidate Process-Context Identifier */
#define CPUID_7_0_EBX_INVPCID           (1U << 10)
/* Restricted Transactional Memory */
#define CPUID_7_0_EBX_RTM               (1U << 11)
/* Memory Protection Extension */
#define CPUID_7_0_EBX_MPX               (1U << 14)
/* AVX-512 Foundation */
#define CPUID_7_0_EBX_AVX512F           (1U << 16)
/* AVX-512 Doubleword & Quadword Instruction */
#define CPUID_7_0_EBX_AVX512DQ          (1U << 17)
/* Read Random SEED */
#define CPUID_7_0_EBX_RDSEED            (1U << 18)
/* ADCX and ADOX instructions */
#define CPUID_7_0_EBX_ADX               (1U << 19)
/* Supervisor Mode Access Prevention */
#define CPUID_7_0_EBX_SMAP              (1U << 20)
/* AVX-512 Integer Fused Multiply Add */
#define CPUID_7_0_EBX_AVX512IFMA        (1U << 21)
/* Persistent Commit */
#define CPUID_7_0_EBX_PCOMMIT           (1U << 22)
/* Flush a Cache Line Optimized */
#define CPUID_7_0_EBX_CLFLUSHOPT        (1U << 23)
/* Cache Line Write Back */
#define CPUID_7_0_EBX_CLWB              (1U << 24)
/* Intel Processor Trace */
#define CPUID_7_0_EBX_INTEL_PT          (1U << 25)
/* AVX-512 Prefetch */
#define CPUID_7_0_EBX_AVX512PF          (1U << 26)
/* AVX-512 Exponential and Reciprocal */
#define CPUID_7_0_EBX_AVX512ER          (1U << 27)
/* AVX-512 Conflict Detection */
#define CPUID_7_0_EBX_AVX512CD          (1U << 28)
/* SHA1/SHA256 Instruction Extensions */
#define CPUID_7_0_EBX_SHA_NI            (1U << 29)
/* AVX-512 Byte and Word Instructions */
#define CPUID_7_0_EBX_AVX512BW          (1U << 30)
/* AVX-512 Vector Length Extensions */
#define CPUID_7_0_EBX_AVX512VL          (1U << 31)

/* AVX-512 Vector Byte Manipulation Instruction */
#define CPUID_7_0_ECX_AVX512_VBMI       (1U << 1)
/* User-Mode Instruction Prevention */
#define CPUID_7_0_ECX_UMIP              (1U << 2)
/* Protection Keys for User-mode Pages */
#define CPUID_7_0_ECX_PKU               (1U << 3)
/* OS Enable Protection Keys */
#define CPUID_7_0_ECX_OSPKE             (1U << 4)
/* UMONITOR/UMWAIT/TPAUSE Instructions */
#define CPUID_7_0_ECX_WAITPKG           (1U << 5)
/* Additional AVX-512 Vector Byte Manipulation Instruction */
#define CPUID_7_0_ECX_AVX512_VBMI2      (1U << 6)
/* Galois Field New Instructions */
#define CPUID_7_0_ECX_GFNI              (1U << 8)
/* Vector AES Instructions */
#define CPUID_7_0_ECX_VAES              (1U << 9)
/* Carry-Less Multiplication Quadword */
#define CPUID_7_0_ECX_VPCLMULQDQ        (1U << 10)
/* Vector Neural Network Instructions */
#define CPUID_7_0_ECX_AVX512VNNI        (1U << 11)
/* Support for VPOPCNT[B,W] and VPSHUFBITQMB */
#define CPUID_7_0_ECX_AVX512BITALG      (1U << 12)
/* POPCNT for vectors of DW/QW */
#define CPUID_7_0_ECX_AVX512_VPOPCNTDQ  (1U << 14)
/* 5-level Page Tables */
#define CPUID_7_0_ECX_LA57              (1U << 16)
/* Read Processor ID */
#define CPUID_7_0_ECX_RDPID             (1U << 22)
/* Cache Line Demote Instruction */
#define CPUID_7_0_ECX_CLDEMOTE          (1U << 25)
/* Move Doubleword as Direct Store Instruction */
#define CPUID_7_0_ECX_MOVDIRI           (1U << 27)
/* Move 64 Bytes as Direct Store Instruction */
#define CPUID_7_0_ECX_MOVDIR64B         (1U << 28)

/* AVX512 Neural Network Instructions */
#define CPUID_7_0_EDX_AVX512_4VNNIW     (1U << 2)
/* AVX512 Multiply Accumulation Single Precision */
#define CPUID_7_0_EDX_AVX512_4FMAPS     (1U << 3)
/* Speculation Control */
#define CPUID_7_0_EDX_SPEC_CTRL         (1U << 26)
/* Arch Capabilities */
#define CPUID_7_0_EDX_ARCH_CAPABILITIES (1U << 29)
/* Core Capability */
#define CPUID_7_0_EDX_CORE_CAPABILITY   (1U << 30)
/* Speculative Store Bypass Disable */
#define CPUID_7_0_EDX_SPEC_CTRL_SSBD    (1U << 31)

/* AVX512 BFloat16 Instruction */
#define CPUID_7_1_EAX_AVX512_BF16       (1U << 5)

/* CLZERO instruction */
#define CPUID_8000_0008_EBX_CLZERO      (1U << 0)
/* Always save/restore FP error pointers */
#define CPUID_8000_0008_EBX_XSAVEERPTR  (1U << 2)
/* Write back and do not invalidate cache */
#define CPUID_8000_0008_EBX_WBNOINVD    (1U << 9)
/* Indirect Branch Prediction Barrier */
#define CPUID_8000_0008_EBX_IBPB        (1U << 12)


#define CPUID_XSAVE_XSAVEOPT   (1U << 0)
#define CPUID_XSAVE_XSAVEC     (1U << 1)
#define CPUID_XSAVE_XGETBV1    (1U << 2)
#define CPUID_XSAVE_XSAVES     (1U << 3)

#define CPUID_6_EAX_ARAT       (1U << 2)

/* CPUID[0x80000007].EDX flags: */
#define CPUID_APM_INVTSC       (1U << 8)

#define CPUID_VENDOR_SZ      12

#define CPUID_VENDOR_INTEL_1 0x756e6547 /* "Genu" */
#define CPUID_VENDOR_INTEL_2 0x49656e69 /* "ineI" */
#define CPUID_VENDOR_INTEL_3 0x6c65746e /* "ntel" */
#define CPUID_VENDOR_INTEL "GenuineIntel"

#define CPUID_VENDOR_AMD_1   0x68747541 /* "Auth" */
#define CPUID_VENDOR_AMD_2   0x69746e65 /* "enti" */
#define CPUID_VENDOR_AMD_3   0x444d4163 /* "cAMD" */
#define CPUID_VENDOR_AMD   "AuthenticAMD"

#define CPUID_VENDOR_VIA   "CentaurHauls"

#define CPUID_VENDOR_HYGON    "HygonGenuine"

#define IS_INTEL_CPU(env) ((env)->cpuid_vendor1 == CPUID_VENDOR_INTEL_1 && \
                           (env)->cpuid_vendor2 == CPUID_VENDOR_INTEL_2 && \
                           (env)->cpuid_vendor3 == CPUID_VENDOR_INTEL_3)
#define IS_AMD_CPU(env) ((env)->cpuid_vendor1 == CPUID_VENDOR_AMD_1 && \
                         (env)->cpuid_vendor2 == CPUID_VENDOR_AMD_2 && \
                         (env)->cpuid_vendor3 == CPUID_VENDOR_AMD_3)

#define CPUID_MWAIT_IBE     (1U << 1) /* Interrupts can exit capability */
#define CPUID_MWAIT_EMX     (1U << 0) /* enumeration supported */

/* CPUID[0xB].ECX level types */
#define CPUID_TOPOLOGY_LEVEL_INVALID  (0U << 8)
#define CPUID_TOPOLOGY_LEVEL_SMT      (1U << 8)
#define CPUID_TOPOLOGY_LEVEL_CORE     (2U << 8)
#define CPUID_TOPOLOGY_LEVEL_DIE      (5U << 8)


#define XSTATE_FP_BIT                   0
#define XSTATE_SSE_BIT                  1
#define XSTATE_YMM_BIT                  2
#define XSTATE_BNDREGS_BIT              3
#define XSTATE_BNDCSR_BIT               4
#define XSTATE_OPMASK_BIT               5
#define XSTATE_ZMM_Hi256_BIT            6
#define XSTATE_Hi16_ZMM_BIT             7
#define XSTATE_PKRU_BIT                 9

#define XSTATE_FP_MASK                  (1ULL << XSTATE_FP_BIT)
#define XSTATE_SSE_MASK                 (1ULL << XSTATE_SSE_BIT)
#define XSTATE_YMM_MASK                 (1ULL << XSTATE_YMM_BIT)
#define XSTATE_BNDREGS_MASK             (1ULL << XSTATE_BNDREGS_BIT)
#define XSTATE_BNDCSR_MASK              (1ULL << XSTATE_BNDCSR_BIT)
#define XSTATE_OPMASK_MASK              (1ULL << XSTATE_OPMASK_BIT)
#define XSTATE_ZMM_Hi256_MASK           (1ULL << XSTATE_ZMM_Hi256_BIT)
#define XSTATE_Hi16_ZMM_MASK            (1ULL << XSTATE_Hi16_ZMM_BIT)
#define XSTATE_PKRU_MASK                (1ULL << XSTATE_PKRU_BIT)

#define MSR_IA32_CORE_CAPABILITY        0xcf
#define MSR_IA32_VMX_BASIC              0x00000480
#define MSR_IA32_VMX_PINBASED_CTLS      0x00000481
#define MSR_IA32_VMX_PROCBASED_CTLS     0x00000482
#define MSR_IA32_VMX_EXIT_CTLS          0x00000483
#define MSR_IA32_VMX_ENTRY_CTLS         0x00000484
#define MSR_IA32_VMX_MISC               0x00000485
#define MSR_IA32_VMX_CR0_FIXED0         0x00000486
#define MSR_IA32_VMX_CR0_FIXED1         0x00000487
#define MSR_IA32_VMX_CR4_FIXED0         0x00000488
#define MSR_IA32_VMX_CR4_FIXED1         0x00000489
#define MSR_IA32_VMX_VMCS_ENUM          0x0000048a
#define MSR_IA32_VMX_PROCBASED_CTLS2    0x0000048b
#define MSR_IA32_VMX_EPT_VPID_CAP       0x0000048c
#define MSR_IA32_VMX_TRUE_PINBASED_CTLS  0x0000048d
#define MSR_IA32_VMX_TRUE_PROCBASED_CTLS 0x0000048e
#define MSR_IA32_VMX_TRUE_EXIT_CTLS      0x0000048f
#define MSR_IA32_VMX_TRUE_ENTRY_CTLS     0x00000490
#define MSR_IA32_VMX_VMFUNC             0x00000491

#define MSR_IA32_UMWAIT_CONTROL         0xe1
#define MSR_VMX_BASIC_DUAL_MONITOR                   (1ULL << 49)
#define MSR_VIRT_SSBD                   0xc001011f
#define HV_X64_MSR_REENLIGHTENMENT_CONTROL      0x40000106

/* VMX controls */
#define VMX_CPU_BASED_VIRTUAL_INTR_PENDING          0x00000004
#define VMX_CPU_BASED_USE_TSC_OFFSETING             0x00000008
#define VMX_CPU_BASED_HLT_EXITING                   0x00000080
#define VMX_CPU_BASED_INVLPG_EXITING                0x00000200
#define VMX_CPU_BASED_MWAIT_EXITING                 0x00000400
#define VMX_CPU_BASED_RDPMC_EXITING                 0x00000800
#define VMX_CPU_BASED_RDTSC_EXITING                 0x00001000
#define VMX_CPU_BASED_CR3_LOAD_EXITING              0x00008000
#define VMX_CPU_BASED_CR3_STORE_EXITING             0x00010000
#define VMX_CPU_BASED_CR8_LOAD_EXITING              0x00080000
#define VMX_CPU_BASED_CR8_STORE_EXITING             0x00100000
#define VMX_CPU_BASED_TPR_SHADOW                    0x00200000
#define VMX_CPU_BASED_VIRTUAL_NMI_PENDING           0x00400000
#define VMX_CPU_BASED_MOV_DR_EXITING                0x00800000
#define VMX_CPU_BASED_UNCOND_IO_EXITING             0x01000000
#define VMX_CPU_BASED_USE_IO_BITMAPS                0x02000000
#define VMX_CPU_BASED_MONITOR_TRAP_FLAG             0x08000000
#define VMX_CPU_BASED_USE_MSR_BITMAPS               0x10000000
#define VMX_CPU_BASED_MONITOR_EXITING               0x20000000
#define VMX_CPU_BASED_PAUSE_EXITING                 0x40000000
#define VMX_CPU_BASED_ACTIVATE_SECONDARY_CONTROLS   0x80000000


#define VMX_SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES 0x00000001
#define VMX_SECONDARY_EXEC_ENABLE_EPT               0x00000002
#define VMX_SECONDARY_EXEC_DESC                     0x00000004
#define VMX_SECONDARY_EXEC_RDTSCP                   0x00000008
#define VMX_SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE   0x00000010
#define VMX_SECONDARY_EXEC_ENABLE_VPID              0x00000020
#define VMX_SECONDARY_EXEC_WBINVD_EXITING           0x00000040
#define VMX_SECONDARY_EXEC_UNRESTRICTED_GUEST       0x00000080
#define VMX_SECONDARY_EXEC_APIC_REGISTER_VIRT       0x00000100
#define VMX_SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY    0x00000200
#define VMX_SECONDARY_EXEC_PAUSE_LOOP_EXITING       0x00000400
#define VMX_SECONDARY_EXEC_RDRAND_EXITING           0x00000800
#define VMX_SECONDARY_EXEC_ENABLE_INVPCID           0x00001000
#define VMX_SECONDARY_EXEC_ENABLE_VMFUNC            0x00002000
#define VMX_SECONDARY_EXEC_SHADOW_VMCS              0x00004000
#define VMX_SECONDARY_EXEC_ENCLS_EXITING            0x00008000
#define VMX_SECONDARY_EXEC_RDSEED_EXITING           0x00010000
#define VMX_SECONDARY_EXEC_ENABLE_PML               0x00020000
#define VMX_SECONDARY_EXEC_XSAVES                   0x00100000

#define VMX_PIN_BASED_EXT_INTR_MASK                 0x00000001
#define VMX_PIN_BASED_NMI_EXITING                   0x00000008
#define VMX_PIN_BASED_VIRTUAL_NMIS                  0x00000020
#define VMX_PIN_BASED_VMX_PREEMPTION_TIMER          0x00000040
#define VMX_PIN_BASED_POSTED_INTR                   0x00000080

#define VMX_VM_EXIT_SAVE_DEBUG_CONTROLS             0x00000004
#define VMX_VM_EXIT_HOST_ADDR_SPACE_SIZE            0x00000200
#define VMX_VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL      0x00001000
#define VMX_VM_EXIT_ACK_INTR_ON_EXIT                0x00008000
#define VMX_VM_EXIT_SAVE_IA32_PAT                   0x00040000
#define VMX_VM_EXIT_LOAD_IA32_PAT                   0x00080000
#define VMX_VM_EXIT_SAVE_IA32_EFER                  0x00100000
#define VMX_VM_EXIT_LOAD_IA32_EFER                  0x00200000
#define VMX_VM_EXIT_SAVE_VMX_PREEMPTION_TIMER       0x00400000
#define VMX_VM_EXIT_CLEAR_BNDCFGS                   0x00800000
#define VMX_VM_EXIT_PT_CONCEAL_PIP                  0x01000000
#define VMX_VM_EXIT_CLEAR_IA32_RTIT_CTL             0x02000000

#define VMX_VM_ENTRY_LOAD_DEBUG_CONTROLS            0x00000004
#define VMX_VM_ENTRY_IA32E_MODE                     0x00000200
#define VMX_VM_ENTRY_SMM                            0x00000400
#define VMX_VM_ENTRY_DEACT_DUAL_MONITOR             0x00000800
#define VMX_VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL     0x00002000
#define VMX_VM_ENTRY_LOAD_IA32_PAT                  0x00004000
#define VMX_VM_ENTRY_LOAD_IA32_EFER                 0x00008000
#define VMX_VM_ENTRY_LOAD_BNDCFGS                   0x00010000
#define VMX_VM_ENTRY_PT_CONCEAL_PIP                 0x00020000
#define VMX_VM_ENTRY_LOAD_IA32_RTIT_CTL             0x00040000

#define INTEL_PT_MAX_SUBLEAF     0x1
#define INTEL_PT_MINIMAL_EBX     0xf
#define INTEL_PT_MINIMAL_ECX     0x7
/* generated packets which contain IP payloads have LIP values */
#define INTEL_PT_IP_LIP          (1 << 31)
#define INTEL_PT_ADDR_RANGES_NUM 0x2 /* Number of configurable address ranges */
#define INTEL_PT_ADDR_RANGES_NUM_MASK 0x3
#define INTEL_PT_MTC_BITMAP      (0x0249 << 16) /* Support ART(0,3,6,9) */
#define INTEL_PT_CYCLE_BITMAP    0x1fff         /* Support 0,2^(0~11) */
#define INTEL_PT_PSB_BITMAP      (0x003f << 16) /* Support 2K,4K,8K,16K,32K,64K */



/* CPUID Leaf 4 constants: */

/* EAX: */
#define CACHE_TYPE_D    1
#define CACHE_TYPE_I    2
#define CACHE_TYPE_UNIFIED   3

#define CACHE_LEVEL(l)        (l << 5)

#define CACHE_SELF_INIT_LEVEL (1 << 8)

/* EDX: */
#define CACHE_NO_INVD_SHARING   (1 << 0)
#define CACHE_INCLUSIVE       (1 << 1)
#define CACHE_COMPLEX_IDX     (1 << 2)

#define CACHE_TYPE(t) (((t) == DATA_CACHE) ? CACHE_TYPE_D : \
                       ((t) == INSTRUCTION_CACHE) ? CACHE_TYPE_I : \
                       ((t) == UNIFIED_CACHE) ? CACHE_TYPE_UNIFIED : \
						0 /* Invalid value */)

/* Maximum core complexes in a node */
#define MAX_CCX 2
/* Maximum cores in a core complex */
#define MAX_CORES_IN_CCX 4
/* Maximum cores in a node */
#define MAX_CORES_IN_NODE 8
/* Maximum nodes in a socket */
#define MAX_NODES_PER_SOCKET 4

#define CR4_OSXSAVE_MASK (1U << 18)
#define CR4_PKE_MASK   (1U << 22)

#define KiB     (1L << 10)
#define MiB     (1L << 20)
#define GiB     (1L << 30)
#define TiB     (1L << 40)
#define PiB     (1L << 50)
#define EiB     (1L << 60)


#define MCG_CTL_P       (1ULL<<8)   /* MCG_CAP register available */
#define MCG_SER_P       (1ULL<<24) /* MCA recovery/new status bits */
#define MCG_LMCE_P      (1ULL<<27) /* Local Machine Check Supported */
            
#define MCE_CAP_DEF     (MCG_CTL_P|MCG_SER_P)
#define MCE_BANKS_DEF   10

#define MCG_CAP_BANKS_MASK 0xff






#define HF_CPL_SHIFT         0
#define HF_INHIBIT_IRQ_SHIFT 3
/* 16 or 32 segments */
#define HF_CS32_SHIFT        4
#define HF_SS32_SHIFT        5
/* zero base for DS, ES and SS : can be '0' only in 32 bit CS segment */
#define HF_ADDSEG_SHIFT      6
/* copy of CR0.PE (protected mode) */
#define HF_PE_SHIFT          7
#define HF_TF_SHIFT          8 /* must be same as eflags */
#define HF_MP_SHIFT          9 /* the order must be MP, EM, TS */
#define HF_EM_SHIFT         10
#define HF_TS_SHIFT         11
#define HF_IOPL_SHIFT       12 /* must be same as eflags */
#define HF_LMA_SHIFT        14 /* only used on x86_64: long mode active */
#define HF_CS64_SHIFT       15 /* only used on x86_64: 64 bit code segment  */
#define HF_RF_SHIFT         16 /* must be same as eflags */
#define HF_VM_SHIFT         17 /* must be same as eflags */
#define HF_AC_SHIFT         18 /* must be same as eflags */
#define HF_SMM_SHIFT        19 /* CPU in SMM mode */
#define HF_SVME_SHIFT       20 /* SVME enabled (copy of EFER.SVME) */
#define HF_GUEST_SHIFT      21 /* SVM intercepts are active */
#define HF_OSFXSR_SHIFT     22 /* CR4.OSFXSR */
#define HF_SMAP_SHIFT       23 /* CR4.SMAP */
#define HF_IOBPT_SHIFT      24 /* an io breakpoint enabled */
#define HF_MPX_EN_SHIFT     25 /* MPX Enabled (CR4+XCR0+BNDCFGx) */
#define HF_MPX_IU_SHIFT     26 /* BND registers in-use */



#define HF_CPL_MASK          (3 << HF_CPL_SHIFT)
#define HF_INHIBIT_IRQ_MASK  (1 << HF_INHIBIT_IRQ_SHIFT)
#define HF_CS32_MASK         (1 << HF_CS32_SHIFT)
#define HF_SS32_MASK         (1 << HF_SS32_SHIFT)
#define HF_ADDSEG_MASK       (1 << HF_ADDSEG_SHIFT)
#define HF_PE_MASK           (1 << HF_PE_SHIFT)
#define HF_TF_MASK           (1 << HF_TF_SHIFT)
#define HF_MP_MASK           (1 << HF_MP_SHIFT)
#define HF_EM_MASK           (1 << HF_EM_SHIFT)
#define HF_TS_MASK           (1 << HF_TS_SHIFT)
#define HF_IOPL_MASK         (3 << HF_IOPL_SHIFT) 
#define HF_LMA_MASK          (1 << HF_LMA_SHIFT)
#define HF_CS64_MASK         (1 << HF_CS64_SHIFT)
#define HF_RF_MASK           (1 << HF_RF_SHIFT)
#define HF_VM_MASK           (1 << HF_VM_SHIFT)
#define HF_AC_MASK           (1 << HF_AC_SHIFT)
#define HF_SVME_MASK         (1 << HF_SVME_SHIFT)
#define HF_OSFXSR_MASK       (1 << HF_OSFXSR_SHIFT)
#define HF_SMAP_MASK         (1 << HF_SMAP_SHIFT)
#define HF_IOBPT_MASK        (1 << HF_IOBPT_SHIFT)
#define HF_MPX_EN_MASK       (1 << HF_MPX_EN_SHIFT)
#define HF_MPX_IU_MASK       (1 << HF_MPX_IU_SHIFT)


/* hflags2 */

#define HF2_GIF_SHIFT            0 /* if set CPU takes interrupts */
#define HF2_HIF_SHIFT            1 /* value of IF_MASK when entering SVM */
#define HF2_NMI_SHIFT            2 /* CPU serving NMI */
#define HF2_VINTR_SHIFT          3 /* value of V_INTR_MASKING bit */
#define HF2_SMM_INSIDE_NMI_SHIFT 4 /* CPU serving SMI nested inside NMI */
#define HF2_MPX_PR_SHIFT         5 /* BNDCFGx.BNDPRESERVE */
#define HF2_NPT_SHIFT            6 /* Nested Paging enabled */
#define HF2_IGNNE_SHIFT          7 /* Ignore CR0.NE=0 */
    
#define HF2_GIF_MASK            (1 << HF2_GIF_SHIFT)
#define HF2_HIF_MASK            (1 << HF2_HIF_SHIFT)
#define HF2_NMI_MASK            (1 << HF2_NMI_SHIFT)
#define HF2_VINTR_MASK          (1 << HF2_VINTR_SHIFT)
#define HF2_SMM_INSIDE_NMI_MASK (1 << HF2_SMM_INSIDE_NMI_SHIFT)
#define HF2_MPX_PR_MASK         (1 << HF2_MPX_PR_SHIFT)
#define HF2_NPT_MASK            (1 << HF2_NPT_SHIFT)
#define HF2_IGNNE_MASK          (1 << HF2_IGNNE_SHIFT)

#define TF_MASK                 0x00000100
#define IF_MASK                 0x00000200
#define DF_MASK                 0x00000400
#define IOPL_MASK               0x00003000
#define NT_MASK                 0x00004000
#define RF_MASK                 0x00010000
#define VM_MASK                 0x00020000
#define AC_MASK                 0x00040000
#define VIF_MASK                0x00080000
#define VIP_MASK                0x00100000
#define ID_MASK                 0x00200000


#define CR0_PE_SHIFT 0
#define CR0_MP_SHIFT 1
        
#define CR0_PE_MASK  (1U << 0)
#define CR0_MP_MASK  (1U << 1)
#define CR0_EM_MASK  (1U << 2)
#define CR0_TS_MASK  (1U << 3)
#define CR0_ET_MASK  (1U << 4)
#define CR0_NE_MASK  (1U << 5)
#define CR0_WP_MASK  (1U << 16)
#define CR0_AM_MASK  (1U << 18)
#define CR0_PG_MASK  (1U << 31)

#define CR4_VME_MASK  (1U << 0)
#define CR4_PVI_MASK  (1U << 1)
#define CR4_TSD_MASK  (1U << 2)
#define CR4_DE_MASK   (1U << 3)
#define CR4_PSE_MASK  (1U << 4)
#define CR4_PAE_MASK  (1U << 5)
#define CR4_MCE_MASK  (1U << 6)
#define CR4_PGE_MASK  (1U << 7)
#define CR4_PCE_MASK  (1U << 8)
#define CR4_OSFXSR_SHIFT 9
#define CR4_OSFXSR_MASK (1U << CR4_OSFXSR_SHIFT)
#define CR4_OSXMMEXCPT_MASK  (1U << 10)
#define CR4_LA57_MASK   (1U << 12)
#define CR4_VMXE_MASK   (1U << 13)
#define CR4_SMXE_MASK   (1U << 14)
#define CR4_FSGSBASE_MASK (1U << 16)
#define CR4_PCIDE_MASK  (1U << 17)
#define CR4_OSXSAVE_MASK (1U << 18)
#define CR4_SMEP_MASK   (1U << 20)
#define CR4_SMAP_MASK   (1U << 21)
#define CR4_PKE_MASK   (1U << 22)

#define DR6_BD          (1 << 13)
#define DR6_BS          (1 << 14)
#define DR6_BT          (1 << 15)

#define DR7_GD          (1 << 13)
#define DR7_TYPE_SHIFT  16
#define DR7_LEN_SHIFT   18
#define DR7_FIXED_1     0x00000400
#define DR7_GLOBAL_BP_MASK   0xaa
#define DR7_LOCAL_BP_MASK    0x55
#define DR7_MAX_BP           4
#define DR7_TYPE_BP_INST     0x0
#define DR7_TYPE_DATA_WR     0x1
#define DR7_TYPE_IO_RW       0x2
#define DR7_TYPE_DATA_RW     0x3


#define PG_PRESENT_BIT  0
#define PG_RW_BIT       1
#define PG_USER_BIT     2
#define PG_PWT_BIT      3
#define PG_PCD_BIT      4
#define PG_ACCESSED_BIT 5
#define PG_DIRTY_BIT    6
#define PG_PSE_BIT      7
#define PG_GLOBAL_BIT   8
#define PG_PSE_PAT_BIT  12
#define PG_PKRU_BIT     59
#define PG_NX_BIT       63

#define PG_PRESENT_MASK  (1 << PG_PRESENT_BIT)
#define PG_RW_MASK       (1 << PG_RW_BIT)
#define PG_USER_MASK     (1 << PG_USER_BIT)
#define PG_PWT_MASK      (1 << PG_PWT_BIT)
#define PG_PCD_MASK      (1 << PG_PCD_BIT)
#define PG_ACCESSED_MASK (1 << PG_ACCESSED_BIT)
#define PG_DIRTY_MASK    (1 << PG_DIRTY_BIT)
#define PG_PSE_MASK      (1 << PG_PSE_BIT)
#define PG_GLOBAL_MASK   (1 << PG_GLOBAL_BIT)
#define PG_PSE_PAT_MASK  (1 << PG_PSE_PAT_BIT)
#define PG_ADDRESS_MASK  0x000ffffffffff000LL
#define PG_HI_RSVD_MASK  (PG_ADDRESS_MASK & ~PHYS_ADDR_MASK)
#define PG_HI_USER_MASK  0x7ff0000000000000LL
#define PG_PKRU_MASK     (15ULL << PG_PKRU_BIT)
#define PG_NX_MASK       (1ULL << PG_NX_BIT)

#define PG_ERROR_W_BIT     1

#define PG_ERROR_P_MASK    0x01
#define PG_ERROR_W_MASK    (1 << PG_ERROR_W_BIT)
#define PG_ERROR_U_MASK    0x04
#define PG_ERROR_RSVD_MASK 0x08
#define PG_ERROR_I_D_MASK  0x10
#define PG_ERROR_PK_MASK   0x20

#define MSR_IA32_UMWAIT_CONTROL         0xe1
#define MSR_IA32_CORE_CAPABILITY        0xcf
#define MSR_KVM_POLL_CONTROL    0x4b564d05

#define HV_CRASH_PARAMS    (HV_X64_MSR_CRASH_P4 - HV_X64_MSR_CRASH_P0 + 1)
#define HV_CRASH_CTL_NOTIFY                     (1ull << 63)

#define MAKE_64BIT_MASK(shift, length) \
    (((~0ULL) >> (64 - (length))) << (shift))

#define MSR_MTRRcap_VCNT                8

#define MSR_MTRRphysBase(reg)           (0x200 + 2 * (reg))
#define MSR_MTRRphysMask(reg)           (0x200 + 2 * (reg) + 1)

#define MSR_MCG_CAP                     0x179
#define MSR_MCG_STATUS                  0x17a
#define MSR_MCG_CTL                     0x17b
#define MSR_MCG_EXT_CTL                 0x4d0
#define MSR_MC0_CTL                     0x400

#define VMX_VM_EXIT_SAVE_DEBUG_CONTROLS             0x00000004
#define VMX_VM_EXIT_HOST_ADDR_SPACE_SIZE            0x00000200
#define VMX_VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL      0x00001000
#define VMX_VM_EXIT_ACK_INTR_ON_EXIT                0x00008000
#define VMX_VM_EXIT_SAVE_IA32_PAT                   0x00040000
#define VMX_VM_EXIT_LOAD_IA32_PAT                   0x00080000
#define VMX_VM_EXIT_SAVE_IA32_EFER                  0x00100000
#define VMX_VM_EXIT_LOAD_IA32_EFER                  0x00200000
#define VMX_VM_EXIT_SAVE_VMX_PREEMPTION_TIMER       0x00400000
#define VMX_VM_EXIT_CLEAR_BNDCFGS                   0x00800000
#define VMX_VM_EXIT_PT_CONCEAL_PIP                  0x01000000
#define VMX_VM_EXIT_CLEAR_IA32_RTIT_CTL             0x02000000

#define MSR_VMX_BASIC_VMCS_REVISION_MASK             0x7FFFFFFFull
#define MSR_VMX_BASIC_VMXON_REGION_SIZE_MASK         (0x00001FFFull << 32)
#define MSR_VMX_BASIC_VMCS_MEM_TYPE_MASK             (0x003C0000ull << 32)
#define MSR_VMX_BASIC_DUAL_MONITOR                   (1ULL << 49)
#define MSR_VMX_BASIC_INS_OUTS                       (1ULL << 54)
#define MSR_VMX_BASIC_TRUE_CTLS                      (1ULL << 55)

#define MSR_VMX_MISC_PREEMPTION_TIMER_SHIFT_MASK     0x1Full
#define MSR_VMX_MISC_STORE_LMA                       (1ULL << 5)
#define MSR_VMX_MISC_ACTIVITY_HLT                    (1ULL << 6)
#define MSR_VMX_MISC_ACTIVITY_SHUTDOWN               (1ULL << 7)
#define MSR_VMX_MISC_ACTIVITY_WAIT_SIPI              (1ULL << 8)
#define MSR_VMX_MISC_MAX_MSR_LIST_SIZE_MASK          0x0E000000ull
#define MSR_VMX_MISC_VMWRITE_VMEXIT                  (1ULL << 29)
#define MSR_VMX_MISC_ZERO_LEN_INJECT                 (1ULL << 30)

#define MSR_VMX_EPT_EXECONLY                         (1ULL << 0)
#define MSR_VMX_EPT_PAGE_WALK_LENGTH_4               (1ULL << 6)
#define MSR_VMX_EPT_PAGE_WALK_LENGTH_5               (1ULL << 7)
#define MSR_VMX_EPT_UC                               (1ULL << 8)
#define MSR_VMX_EPT_WB                               (1ULL << 14)
#define MSR_VMX_EPT_2MB                              (1ULL << 16)
#define MSR_VMX_EPT_1GB                              (1ULL << 17)
#define MSR_VMX_EPT_INVEPT                           (1ULL << 20)
#define MSR_VMX_EPT_AD_BITS                          (1ULL << 21)
#define MSR_VMX_EPT_ADVANCED_VMEXIT_INFO             (1ULL << 22)
#define MSR_VMX_EPT_INVEPT_SINGLE_CONTEXT            (1ULL << 25)
#define MSR_VMX_EPT_INVEPT_ALL_CONTEXT               (1ULL << 26)
#define MSR_VMX_EPT_INVVPID                          (1ULL << 32)
#define MSR_VMX_EPT_INVVPID_SINGLE_ADDR              (1ULL << 40)
#define MSR_VMX_EPT_INVVPID_SINGLE_CONTEXT           (1ULL << 41)
#define MSR_VMX_EPT_INVVPID_ALL_CONTEXT              (1ULL << 42)
#define MSR_VMX_EPT_INVVPID_SINGLE_CONTEXT_NOGLOBALS (1ULL << 43)

#define VMCS12_MAX_FIELD_INDEX (0x17)

#define MSR_EFER_SCE   (1 << 0)
#define MSR_EFER_LME   (1 << 8)
#define MSR_EFER_LMA   (1 << 10)
#define MSR_EFER_NXE   (1 << 11)
#define MSR_EFER_SVME  (1 << 12)
#define MSR_EFER_FFXSR (1 << 14)

#define MSR_IA32_MISC_ENABLE_DEFAULT    1

#define ASSOC_FULL 0xFF

/* AMD associativity encoding used on CPUID Leaf 0x80000006: */
#define AMD_ENC_ASSOC(a) (a <=   1 ? a   : \
                          a ==   2 ? 0x2 : \
                          a ==   4 ? 0x4 : \
                          a ==   8 ? 0x6 : \
                          a ==  16 ? 0x8 : \
                          a ==  32 ? 0xA : \
                          a ==  48 ? 0xB : \
                          a ==  64 ? 0xC : \
                          a ==  96 ? 0xD : \
                          a == 128 ? 0xE : \
                          a == ASSOC_FULL ? 0xF : \
                          0 /* invalid value */)

/* TLB definitions: */

#define L1_DTLB_2M_ASSOC       1
#define L1_DTLB_2M_ENTRIES   255
#define L1_DTLB_4K_ASSOC       1
#define L1_DTLB_4K_ENTRIES   255

#define L1_ITLB_2M_ASSOC       1
#define L1_ITLB_2M_ENTRIES   255
#define L1_ITLB_4K_ASSOC       1
#define L1_ITLB_4K_ENTRIES   255

#define L2_DTLB_2M_ASSOC       0 /* disabled */
#define L2_DTLB_2M_ENTRIES     0 /* disabled */
#define L2_DTLB_4K_ASSOC       4
#define L2_DTLB_4K_ENTRIES   512

#define L2_ITLB_2M_ASSOC       0 /* disabled */
#define L2_ITLB_2M_ENTRIES     0 /* disabled */
#define L2_ITLB_4K_ASSOC       4
#define L2_ITLB_4K_ENTRIES   512

#define MAX_GP_COUNTERS    (MSR_IA32_PERF_STATUS - MSR_P6_EVNTSEL0)

#define MAX_FIXED_COUNTERS 3

#define MSR_BUF_SIZE 4096

#define CPUID_VENDOR_SZ      12
#define CPUID_MODEL_ID_SZ 48

#define KVM_FEATURE_CLOCKSOURCE2        3
#define KVM_FEATURE_ASYNC_PF        4
#define KVM_FEATURE_STEAL_TIME      5
#define KVM_FEATURE_PV_EOI      6
#define KVM_FEATURE_PV_UNHALT       7
#define KVM_FEATURE_PV_TLB_FLUSH    9
#define KVM_FEATURE_ASYNC_PF_VMEXIT 10
#define KVM_FEATURE_PV_SEND_IPI 11
#define KVM_FEATURE_POLL_CONTROL    12
#define KVM_FEATURE_PV_SCHED_YIELD  13


#define MMREG_UNION(n, bits)        \
    union n {                       \
        uint8_t  _b_##n[(bits)/8];  \
        uint16_t _w_##n[(bits)/16]; \
        uint32_t _l_##n[(bits)/32]; \
        uint64_t _q_##n[(bits)/64]; \
        uint32_t  _s_##n[(bits)/32]; \
        uint64_t  _d_##n[(bits)/64]; \
    }

#define CPU_NB_REGS64 16

#define CPU_NB_REGS CPU_NB_REGS64

#define BNDCFG_ENABLE       1ULL
#define BNDCFG_BNDPRESERVE  2ULL
#define BNDCFG_BDIR_MASK    TARGET_PAGE_MASK

#define NB_OPMASK_REGS 8

#define ZMM_Q(n) _q_ZMMReg[n]

//the folowing only works in LittleEnd
static inline void stq_he_p(void *ptr, uint64_t v)
{
    __builtin_memcpy(ptr, &v, sizeof(v));
}
#define le_bswap(v, size) (v)
static inline void stq_le_p(void *ptr, uint64_t v)
{
    stq_he_p(ptr, le_bswap(v, 64));
}
#define stq_p(p, v) stq_le_p(p, v)

enum {  
    R_EAX = 0,
    R_ECX = 1,
    R_EDX = 2, 
    R_EBX = 3,
    R_ESP = 4,
    R_EBP = 5,
    R_ESI = 6,
    R_EDI = 7,
    R_R8 = 8,
    R_R9 = 9,
    R_R10 = 10,
    R_R11 = 11,
    R_R12 = 12,
    R_R13 = 13,
    R_R14 = 14, 
    R_R15 = 15,

    R_AL = 0,
    R_CL = 1,
    R_DL = 2,
    R_BL = 3,
    R_AH = 4,
    R_CH = 5,
    R_DH = 6,
    R_BH = 7,
};

typedef enum X86Seg {
    R_ES = 0,
    R_CS = 1,
    R_SS = 2,
    R_DS = 3,
    R_FS = 4,
    R_GS = 5,
    R_LDTR = 6,
    R_TR = 7,
} X86Seg;


typedef enum FeatureWordType {
   CPUID_FEATURE_WORD,
   MSR_FEATURE_WORD,
} FeatureWordType;

typedef struct FeatureWordInfo {
    FeatureWordType type;
    /* feature flags names are taken from "Intel Processor Identification and
     * the CPUID Instruction" and AMD's "CPUID Specification".
     * In cases of disagreement between feature naming conventions,
     * aliases may be added.
     */
    const char *feat_names[64];
    union {
        /* If type==CPUID_FEATURE_WORD */
        struct {
            uint32_t eax;   /* Input EAX for CPUID */
            bool needs_ecx; /* CPUID instruction uses ECX as input */
            uint32_t ecx;   /* Input ECX value for CPUID */
            int reg;        /* output register (R_* constant) */
        } cpuid;
        /* If type==MSR_FEATURE_WORD */
        struct {
            uint32_t index;
        } msr;
    };
    uint64_t unmigratable_flags; /* Feature flags known to be unmigratable */
    uint64_t migratable_flags; /* Feature flags known to be migratable */
    /* Features that shouldn't be auto-enabled by "-cpu host" */
    uint64_t no_autoenable_flags;
} FeatureWordInfo;

/* CPUID feature words */
typedef enum FeatureWord {
    FEAT_1_EDX,         /* CPUID[1].EDX */
    FEAT_1_ECX,         /* CPUID[1].ECX */
    FEAT_7_0_EBX,       /* CPUID[EAX=7,ECX=0].EBX */
    FEAT_7_0_ECX,       /* CPUID[EAX=7,ECX=0].ECX */
    FEAT_7_0_EDX,       /* CPUID[EAX=7,ECX=0].EDX */
    FEAT_7_1_EAX,       /* CPUID[EAX=7,ECX=1].EAX */
    FEAT_8000_0001_EDX, /* CPUID[8000_0001].EDX */
    FEAT_8000_0001_ECX, /* CPUID[8000_0001].ECX */
    FEAT_8000_0007_EDX, /* CPUID[8000_0007].EDX */
    FEAT_8000_0008_EBX, /* CPUID[8000_0008].EBX */
    FEAT_C000_0001_EDX, /* CPUID[C000_0001].EDX */
    FEAT_KVM,           /* CPUID[4000_0001].EAX (KVM_CPUID_FEATURES) */
    FEAT_KVM_HINTS,     /* CPUID[4000_0001].EDX */
    FEAT_HYPERV_EAX,    /* CPUID[4000_0003].EAX */
    FEAT_HYPERV_EBX,    /* CPUID[4000_0003].EBX */
    FEAT_HYPERV_EDX,    /* CPUID[4000_0003].EDX */
    FEAT_HV_RECOMM_EAX, /* CPUID[4000_0004].EAX */
    FEAT_HV_NESTED_EAX, /* CPUID[4000_000A].EAX */
    FEAT_SVM,           /* CPUID[8000_000A].EDX */
    FEAT_XSAVE,         /* CPUID[EAX=0xd,ECX=1].EAX */
    FEAT_6_EAX,         /* CPUID[6].EAX */
    FEAT_XSAVE_COMP_LO, /* CPUID[EAX=0xd,ECX=0].EAX */
    FEAT_XSAVE_COMP_HI, /* CPUID[EAX=0xd,ECX=0].EDX */
    FEAT_ARCH_CAPABILITIES,
    FEAT_CORE_CAPABILITY,
    FEAT_VMX_PROCBASED_CTLS,
    FEAT_VMX_SECONDARY_CTLS,
    FEAT_VMX_PINBASED_CTLS,
    FEAT_VMX_EXIT_CTLS,
    FEAT_VMX_ENTRY_CTLS,
    FEAT_VMX_MISC,
    FEAT_VMX_EPT_VPID_CAPS,
    FEAT_VMX_BASIC,
    FEAT_VMX_VMFUNC,
    FEATURE_WORDS,
} FeatureWord;



typedef struct FeatureMask {
    FeatureWord index;
    uint64_t mask;
} FeatureMask;

typedef struct FeatureDep {
    FeatureMask from, to;
} FeatureDep;

typedef struct X86XSaveHeader {
    uint64_t xstate_bv;
    uint64_t xcomp_bv; 
    uint64_t reserve0;
    uint8_t reserved[40];
} X86XSaveHeader;

/* Ext. save area 2: AVX State */
typedef struct XSaveAVX {
    uint8_t ymmh[16][16];
} XSaveAVX;


typedef struct BNDReg {
    uint64_t lb;
    uint64_t ub;
} BNDReg;

/* Ext. save area 3: BNDREG */
typedef struct XSaveBNDREG {
    BNDReg bnd_regs[4]; 
} XSaveBNDREG;

typedef struct BNDCSReg { 
    uint64_t cfgu;
    uint64_t sts;
} BNDCSReg;

/* Ext. save area 4: BNDCSR */
typedef union XSaveBNDCSR {
    BNDCSReg bndcsr;
    uint8_t data[64];
} XSaveBNDCSR;

/* Ext. save area 5: Opmask */
typedef struct XSaveOpmask {
    uint64_t opmask_regs[8];
} XSaveOpmask;

/* Ext. save area 6: ZMM_Hi256 */
typedef struct XSaveZMM_Hi256 {
    uint8_t zmm_hi256[16][32];
} XSaveZMM_Hi256; 

/* Ext. save area 7: Hi16_ZMM */
typedef struct XSaveHi16_ZMM {
    uint8_t hi16_zmm[16][64];
} XSaveHi16_ZMM;

/* Ext. save area 9: PKRU state */
typedef struct XSavePKRU {
    uint32_t pkru;
    uint32_t padding;
} XSavePKRU;


typedef struct {
    uint64_t base;
    uint64_t mask;
} MTRRVar;

typedef struct {
    uint64_t low;
    uint16_t high;
} floatx80;

typedef union {
    uint8_t _b[16];
    uint16_t _w[8];
    uint32_t _l[4];
    uint64_t _q[2];
} XMMReg;

typedef union {
    uint8_t _b[32];
    uint16_t _w[16];
    uint32_t _l[8];
    uint64_t _q[4];
} YMMReg;

typedef MMREG_UNION(ZMMReg, 512) ZMMReg;
typedef MMREG_UNION(MMXReg, 64)  MMXReg;

typedef union {
    floatx80 d __attribute__((aligned(16)));
    MMXReg mmx;
} FPReg;


typedef union X86LegacyXSaveArea {
    struct {
        uint16_t fcw;
        uint16_t fsw;
        uint8_t ftw;
        uint8_t reserved;
        uint16_t fpop;
        uint64_t fpip;
        uint64_t fpdp;
        uint32_t mxcsr;
        uint32_t mxcsr_mask;
        FPReg fpregs[8];
        uint8_t xmm_regs[16][16];
    };
    uint8_t data[512];
} X86LegacyXSaveArea;

typedef struct X86XSaveArea {
	X86LegacyXSaveArea legacy;
    X86XSaveHeader header;
    
    /* Extended save areas: */
    
    /* AVX State: */
    XSaveAVX avx_state;
    uint8_t padding[960 - 576 - sizeof(XSaveAVX)];
    /* MPX State: */
    XSaveBNDREG bndreg_state;
    XSaveBNDCSR bndcsr_state;
    /* AVX-512 State: */
    XSaveOpmask opmask_state;
    XSaveZMM_Hi256 zmm_hi256_state;
    XSaveHi16_ZMM hi16_zmm_state;
    /* PKRU State: */
    XSavePKRU pkru_state;
} X86XSaveArea;

typedef struct ExtSaveArea {
    uint32_t feature, bits;
    uint32_t offset, size;
} ExtSaveArea;


int do_get_msr_feature(struct kvm_vcpu *vcpu, unsigned index, u64 *data);

struct core_topology {
    /* core complex id of the current core index */
    int ccx_id;
    /*
     * Adjusted core index for this core in the topology
     * This can be 0,1,2,3 with max 4 cores in a core complex
     */
    int core_id;
    /* Node id for this core index */
    int node_id;
    /* Number of nodes in this config */
    int num_nodes;
};



typedef uint64_t FeatureWordArray[FEATURE_WORDS];

enum CacheType {
    DATA_CACHE,
    INSTRUCTION_CACHE,
    UNIFIED_CACHE
};

typedef struct CPUCacheInfo {
    enum CacheType type;
    uint8_t level;
    /* Size in bytes */
    uint32_t size;
    /* Line size, in bytes */
    uint16_t line_size;
    /*
     * Associativity.
     * Note: representation of fully-associative caches is not implemented
     */
    uint8_t associativity;
    /* Physical line partitions. CPUID[0x8000001D].EBX, CPUID[4].EBX */
    uint8_t partitions;
    /* Number of sets. CPUID[0x8000001D].ECX, CPUID[4].ECX */
    uint32_t sets;
    /*
     * Lines per tag.
     * AMD-specific: CPUID[0x80000005], CPUID[0x80000006].
     * (Is this synonym to @partitions?)
     */
    uint8_t lines_per_tag;

    /* Self-initializing cache */
    bool self_init;
    /*
     * WBINVD/INVD is not guaranteed to act upon lower level caches of
     * non-originating threads sharing this cache.
     * CPUID[4].EDX[bit 0], CPUID[0x8000001D].EDX[bit 0]
     */
    bool no_invd_sharing;
    /*
     * Cache is inclusive of lower cache levels.
     * CPUID[4].EDX[bit 1], CPUID[0x8000001D].EDX[bit 1].
     */
    bool inclusive;
    /*
     * A complex function is used to index the cache, potentially using all
     * address bits.  CPUID[4].EDX[bit 2].
     */
    bool complex_indexing;
} CPUCacheInfo;

typedef struct CPUCaches {
        CPUCacheInfo *l1d_cache;
        CPUCacheInfo *l1i_cache;
        CPUCacheInfo *l2_cache;
        CPUCacheInfo *l3_cache;
} CPUCaches;

typedef struct SegmentCache {
    uint32_t selector;
    uint64_t base;
    uint32_t limit;
    uint32_t flags;
} SegmentCache;

typedef struct CPUX86State {
    /* Minimum cpuid leaf 7 value */
    uint32_t cpuid_level_func7;
    /* Actual cpuid leaf 7 value */
    uint32_t cpuid_min_level_func7;
    /* Minimum level/xlevel/xlevel2, based on CPU model + features */
    uint32_t cpuid_min_level, cpuid_min_xlevel, cpuid_min_xlevel2;
    /* Actual level/xlevel/xlevel2 value: */
    uint32_t cpuid_level, cpuid_xlevel, cpuid_xlevel2;
    uint32_t cpuid_vendor1;
    uint32_t cpuid_vendor2;
    uint32_t cpuid_vendor3;
    uint32_t cpuid_version;
	uint32_t cpuid_model[12];

    FeatureWordArray features;
    /* Features that were explicitly enabled/disabled */
    FeatureWordArray user_features;

	uint32_t phys_bits;

	CPUCaches cache_info_cpuid2, cache_info_cpuid4, cache_info_amd;

    uint64_t mcg_cap;
    uint64_t mcg_ctl;
	uint64_t mcg_ext_ctl;
    uint64_t mce_banks[10*4];

	int64_t tsc_khz;

	int apic_id;
	int socket_id;
	int core_id;
	int thread_id;

	uint32_t mp_state;

	int nr_cores;
	int nr_threads;

    uint64_t regs[CPU_NB_REGS];
    uint64_t eip;
    uint64_t eflags;

	uint64_t cr[5];

    BNDReg bnd_regs[4];
    BNDCSReg bndcs_regs;
    uint64_t msr_bndcfgs;
    uint64_t efer;

	uint64_t xcr0;

	uint32_t hflags; 
	uint32_t hflags2;
	uint64_t pat;
	uint32_t pkru;
    uint64_t mtrr_fixed[11];
    uint64_t mtrr_deftype;
    MTRRVar mtrr_var[8];
	uint32_t smbase;
	uint64_t msr_smi_count;

	SegmentCache segs[6]; /* selector values */
	SegmentCache tr;
	SegmentCache ldt;
    SegmentCache gdt; /* only base and limit are used */
    SegmentCache idt; /* only base and limit are used */

	uint64_t dr[8];

	unsigned int fpstt;
	uint16_t fpus;
	uint16_t fpuc;
	uint8_t fptags[8];
    FPReg fpregs[8];
    /* KVM-only so far */
    uint16_t fpop;
    uint64_t fpip;
    uint64_t fpdp;

	uint32_t mxcsr;
	uint64_t xstate_bv;
	void *xsave_buf;
	uint64_t opmask_regs[NB_OPMASK_REGS];
	ZMMReg xmm_regs[CPU_NB_REGS == 8 ? 8 : 32];

	/* the following are MSR registers*/
	uint64_t poll_control_msr;
	uint64_t msr_ia32_misc_enable;
	uint64_t mcg_status;
    uint64_t msr_ia32_feature_control;

	struct kvm_msrs *kvm_msr_buf;

    uint32_t sysenter_cs;
    uint64_t sysenter_esp;
    uint64_t sysenter_eip;
    uint64_t star;

    uint64_t vm_hsave;

    uint64_t lstar;
    uint64_t cstar;
    uint64_t fmask;
    uint64_t kernelgsbase;

    uint64_t tsc;
    uint64_t tsc_adjust;
    uint64_t tsc_deadline;
    uint64_t tsc_aux;

    uint64_t xss;
    uint32_t umwait;

    uint32_t tsx_ctrl;

    uint64_t spec_ctrl;
    uint64_t virt_ssbd;

    uint64_t system_time_msr;
    uint64_t wall_clock_msr;
    uint64_t steal_time_msr;
    uint64_t async_pf_en_msr;
    uint64_t pv_eoi_en_msr;

    uint64_t msr_fixed_ctr_ctrl;
    uint64_t msr_global_ctrl;
    uint64_t msr_global_status;
    uint64_t msr_global_ovf_ctrl;
    uint64_t msr_fixed_counters[MAX_FIXED_COUNTERS];
    uint64_t msr_gp_counters[MAX_GP_COUNTERS];
    uint64_t msr_gp_evtsel[MAX_GP_COUNTERS];

	/* Partition-wide HV MSRs, will be updated only on the first vcpu */
    uint64_t msr_hv_hypercall;
    uint64_t msr_hv_guest_os_id;
    uint64_t msr_hv_tsc;

    /* Per-VCPU HV MSRs */
    uint64_t msr_hv_vapic;
    uint64_t msr_hv_crash_params[HV_CRASH_PARAMS];
    uint64_t msr_hv_runtime;
    uint64_t msr_hv_synic_control;
    uint64_t msr_hv_synic_evt_page;
    uint64_t msr_hv_synic_msg_page;
    uint64_t msr_hv_synic_sint[HV_SINT_COUNT];
    uint64_t msr_hv_stimer_config[HV_STIMER_COUNT];
    uint64_t msr_hv_stimer_count[HV_STIMER_COUNT];
    uint64_t msr_hv_reenlightenment_control;
    uint64_t msr_hv_tsc_emulation_control;
    uint64_t msr_hv_tsc_emulation_status;

    uint64_t msr_rtit_ctrl;
    uint64_t msr_rtit_status;
    uint64_t msr_rtit_output_base;
    uint64_t msr_rtit_output_mask;
    uint64_t msr_rtit_cr3_match;
    uint64_t msr_rtit_addrs[MAX_RTIT_ADDRS];

} CPUX86State;


struct CPUID2CacheDescriptorInfo {
    enum CacheType type;
    int level;
    int size;
    int line_size;
    int associativity;
};


static inline uint64_t x86_cpu_xsave_components(CPUX86State *env)
{
    return ((uint64_t)env->features[FEAT_XSAVE_COMP_HI]) << 32 |
           env->features[FEAT_XSAVE_COMP_LO];
}

int kvm_vcpu_ioctl_x86_setup_mce(struct kvm_vcpu *vcpu,	u64 mcg_cap);

int kvm_get_supported_msrs(void);

typedef uint32_t apic_id_t;

typedef struct X86CPUTopoInfo {
    unsigned pkg_id;
    unsigned die_id;
    unsigned core_id;                           
    unsigned smt_id;                            
} X86CPUTopoInfo;

static inline int clz32(uint32_t val)
{
    return val ? __builtin_clz(val) : 32;
}

/* Return the bit width needed for 'count' IDs
 */
static unsigned apicid_bitwidth_for_count(unsigned count)
{
    count -= 1;
    return count ? 32 - clz32(count) : 0;
}

/* Bit width of the SMT_ID (thread ID) field on the APIC ID
 */
static inline unsigned apicid_smt_width(unsigned nr_dies,
                                        unsigned nr_cores,
                                        unsigned nr_threads)
{
    return apicid_bitwidth_for_count(nr_threads);
}

/* Bit width of the Core_ID field
 */
static inline unsigned apicid_core_width(unsigned nr_dies,
                                         unsigned nr_cores,
                                         unsigned nr_threads)
{
    return apicid_bitwidth_for_count(nr_cores);
}

/* Bit width of the Die_ID field */
static inline unsigned apicid_die_width(unsigned nr_dies,
                                        unsigned nr_cores,
                                        unsigned nr_threads)
{
    return apicid_bitwidth_for_count(nr_dies);
}

/* Bit offset of the Core_ID field
 */
static inline unsigned apicid_core_offset(unsigned nr_dies,
                                          unsigned nr_cores,
                                          unsigned nr_threads)
{
    return apicid_smt_width(nr_dies, nr_cores, nr_threads);
}

/* Bit offset of the Die_ID field */
static inline unsigned apicid_die_offset(unsigned nr_dies,
                                          unsigned nr_cores,
                                           unsigned nr_threads)
{
    return apicid_core_offset(nr_dies, nr_cores, nr_threads) +
           apicid_core_width(nr_dies, nr_cores, nr_threads);
}

/* Bit offset of the Pkg_ID (socket ID) field
 */
static inline unsigned apicid_pkg_offset(unsigned nr_dies,
                                         unsigned nr_cores,
                                         unsigned nr_threads)
{
    return apicid_die_offset(nr_dies, nr_cores, nr_threads) +
           apicid_die_width(nr_dies, nr_cores, nr_threads);
}

/* Make APIC ID for the CPU based on Pkg_ID, Core_ID, SMT_ID
 *
 * The caller must make sure core_id < nr_cores and smt_id < nr_threads.
 */
static inline apic_id_t apicid_from_topo_ids(unsigned nr_dies,
                                             unsigned nr_cores,
                                             unsigned nr_threads,
                                             const X86CPUTopoInfo *topo)
{
    return (topo->pkg_id  << apicid_pkg_offset(nr_dies, nr_cores, nr_threads)) |
           (topo->die_id  << apicid_die_offset(nr_dies, nr_cores, nr_threads)) |
          (topo->core_id << apicid_core_offset(nr_dies, nr_cores, nr_threads)) |
           topo->smt_id;
}

/* Calculate thread/core/package IDs for a specific topology,
 * based on (contiguous) CPU index
 */
static inline void x86_topo_ids_from_idx(unsigned nr_dies,
                                         unsigned nr_cores,
                                         unsigned nr_threads,
                                         unsigned cpu_index,
                                         X86CPUTopoInfo *topo)
{
    topo->pkg_id = cpu_index / (nr_dies * nr_cores * nr_threads);
    topo->die_id = cpu_index / (nr_cores * nr_threads) % nr_dies;
    topo->core_id = cpu_index / nr_threads % nr_cores;
    topo->smt_id = cpu_index % nr_threads;
}

/* Calculate thread/core/package IDs for a specific topology,
 * based on APIC ID
 */
static inline void x86_topo_ids_from_apicid(apic_id_t apicid,
                                            unsigned nr_dies,
                                            unsigned nr_cores,
                                            unsigned nr_threads,
                                            X86CPUTopoInfo *topo)
{
    topo->smt_id = apicid &
            ~(0xFFFFFFFFUL << apicid_smt_width(nr_dies, nr_cores, nr_threads));
    topo->core_id =
            (apicid >> apicid_core_offset(nr_dies, nr_cores, nr_threads)) &
            ~(0xFFFFFFFFUL << apicid_core_width(nr_dies, nr_cores, nr_threads));
    topo->die_id =
            (apicid >> apicid_die_offset(nr_dies, nr_cores, nr_threads)) &
            ~(0xFFFFFFFFUL << apicid_die_width(nr_dies, nr_cores, nr_threads));
    topo->pkg_id = apicid >> apicid_pkg_offset(nr_dies, nr_cores, nr_threads);
}

/* Make APIC ID for the CPU 'cpu_index'
 *
 * 'cpu_index' is a sequential, contiguous ID for the CPU.
 */
static inline apic_id_t x86_apicid_from_cpu_idx(unsigned nr_dies,
                                                unsigned nr_cores,
                                                unsigned nr_threads,
                                                unsigned cpu_index)
{
    X86CPUTopoInfo topo;

    x86_topo_ids_from_idx(nr_dies, nr_cores, nr_threads, cpu_index, &topo);

    return apicid_from_topo_ids(nr_dies, nr_cores, nr_threads, &topo);
}

int init_vcpu_virt_regs(struct kvm_vcpu *vcpu);

#define APIC_DEFAULT_ADDRESS 0xfee00000
#define APIC_SPACE_SIZE      0x100000

void destroy_vcpu_regs(struct kvm_vcpu *vcpu);

#endif

