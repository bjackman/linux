/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_MERMAP_H
#define _ASM_X86_MERMAP_H

#include <asm/tlbflush.h>

static inline void arch_mermap_flush_tlb(void)
{
	/*
	 * No shootdown allowed, IRQs may be off. Luckily other CPUs are not
	 * allowed to access our region so the stale mappings are harmless, as
	 * long as they still point to data belonging to this process.
	 */
	flush_tlb_local();
}

#endif /* _ASM_X86_MERMAP_H */
