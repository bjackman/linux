/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MERMAP_H
#define _LINUX_MERMAP_H

#include <linux/mm.h>

#ifdef CONFIG_MERMAP

struct mermap {
	bool in_use;
};

int mermap_mm_init(struct mm_struct *mm);
void mermap_mm_teardown(struct mm_struct *mm);

void *mermap_get(struct page *page, unsigned long size, pgprot_t prot);
void mermap_put(const void *vaddr, unsigned long size);
void mermap_cond_put(const void *vaddr, unsigned long size);

#else /* CONFIG_MERMAP */

static inline int mermap_mm_init(struct mm_struct *mm) { return 0; }
static inline void mermap_mm_teardown(struct mm_struct *mm) { }

#endif /* CONFIG_MERMAP */

#endif /* _LINUX_MERMAP_H */
