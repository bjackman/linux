/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_ASI_H
#define _ASM_X86_ASI_H

#include <linux/align.h>
#include <linux/mm.h>
#include <linux/mmdebug.h>

#include <asm/pgtable_types.h>
#include <asm/set_memory.h>

#ifdef CONFIG_MITIGATION_ADDRESS_SPACE_ISOLATION

extern struct asi __asi_global_nonsensitive;
#define ASI_GLOBAL_NONSENSITIVE	(&__asi_global_nonsensitive)

/*
 * An ASI domain (struct asi) represents a restricted address space. The
 * unrestricted address space (and user address space under PTI) are not
 * represented as a domain.
 */
struct asi {
	pgd_t *pgd;
};

static __always_inline pgd_t *asi_pgd(struct asi *asi)
{
	return asi ? asi->pgd : NULL;
}

void asi_map(struct page *page, int numpages);
void asi_unmap(struct page *page, int numpages);

#endif /* CONFIG_MITIGATION_ADDRESS_SPACE_ISOLATION */

#endif /* _ASM_X86_ASI_H */
