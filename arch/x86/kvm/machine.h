#ifndef ARCH_X86_KVM_MACHINE_H
#define ARCH_X86_KVM_MACHINE_H

#include "vpci.h"
#include "vblk.h"

//the following are hardcode for tempolory
#define CPUS 2
#define DIES 1
#define CORES 2
#define THREADS 1
#define RAM_SIZE 0x80000000
#define KERNEL_PATH "/home/gen/openSource/guen/vmlinux"
#define KERNEL_CMDLINE  "console=ttyS0 root=/dev/sda"


void init_env_possible_cpus(CPUX86State *env, struct kvm *kvm);


void init_virt_machine(struct kvm_vcpu *vcpu);
int create_virt_machine(struct kvm *kvm);
void destroy_virt_machine(struct kvm *kvm);
static inline unsigned long *bitmap_try_new(long nbits)
{
    long len = BITS_TO_LONGS(nbits) * sizeof(unsigned long);
    return kzalloc(len, GFP_KERNEL);
}

static inline unsigned long *bitmap_new(long nbits)
{   
    long len = BITS_TO_LONGS(nbits) * sizeof(unsigned long);

    return kzalloc(len, GFP_KERNEL);
}

void kvm_irqchip_release_virq(struct kvm *kvm, int virq);

int kvm_irqchip_add_msi_route(struct kvm *kvm, int vector, PCIDevice *dev);

int kvm_irqchip_update_msi_route(struct kvm *kvm, int virq, MSIMessage msg,
                                 PCIDevice *dev);

void kvm_irqchip_commit_routes(struct kvm *kvm);
#endif
