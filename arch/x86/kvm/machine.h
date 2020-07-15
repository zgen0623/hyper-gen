#ifndef ARCH_X86_KVM_MACHINE_H
#define ARCH_X86_KVM_MACHINE_H

void init_env_possible_cpus(CPUX86State *env, struct kvm *kvm);


void init_virt_machine(struct kvm_vcpu *vcpu);

#endif
