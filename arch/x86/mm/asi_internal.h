/* SPDX-License-Identifier: GPL-2.0-only */
#include <linux/types.h>
#include <linux/pgtable.h>

#include <asm/page.h>

#ifndef __X86_MM_ASI_INTERNAL_H
#define __X86_MM_ASI_INTERNAL_H

#if IS_ENABLED(CONFIG_KUNIT)

bool follow_physaddr(
	pgd_t *pgd_table, unsigned long virt,
	phys_addr_t *phys, unsigned long *page_size, ulong *flags);
int64_t asi_cpu_stat(int cpu, enum asi_stat_item item);
bool addr_present(pgd_t *pgd, unsigned long addr);
bool asi_class_initialized(enum asi_class_id class_id);

DECLARE_PER_CPU_ALIGNED(asi_taints_t, asi_taints);

#endif /* CONFIG_KUNIT */

#endif /* __X86_MM_ASI_INTERNAL_H */
