/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_EPHMAP_H
#define _LINUX_EPHMAP_H

#include <linux/mm.h>

void ephmap_setup(struct mm_struct *mm);
void ephmap_cleanup(struct mm_struct *mm);

void *ephmap_get(struct page *page, unsigned long size);
void ephmap_put(void *vaddr, unsigned long size);

#endif /* _LINUX_EPHMAP_H */
