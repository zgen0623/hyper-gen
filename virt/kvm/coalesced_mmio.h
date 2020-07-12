/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_COALESCED_MMIO_H__
#define __KVM_COALESCED_MMIO_H__

/*
 * KVM coalesced MMIO
 *
 * Copyright (c) 2008 Bull S.A.S.
 *
 *  Author: Laurent Vivier <Laurent.Vivier@bull.net>
 *
 */

static inline int kvm_coalesced_mmio_init(struct kvm *kvm) { return 0; }
static inline void kvm_coalesced_mmio_free(struct kvm *kvm) { }

#endif
