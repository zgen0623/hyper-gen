#ifndef ARCH_X86_KVM_VSER_H
#define ARCH_X86_KVM_VSER_H

void destroy_vserial(struct kvm *kvm);
void create_vserial(struct kvm *kvm);

#endif
