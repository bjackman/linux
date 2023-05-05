/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _INCLUDE_ASI_H
#define _INCLUDE_ASI_H

#include <asm/pgtable_types.h>

#ifdef CONFIG_MITIGATION_ADDRESS_SPACE_ISOLATION
#include <asm/asi.h>
#else

#define ASI_GLOBAL_NONSENSITIVE NULL

struct asi {};

static inline pgd_t *asi_pgd(struct asi *asi) { return NULL; }

#endif /* CONFIG_MITIGATION_ADDRESS_SPACE_ISOLATION */
#endif /* _INCLUDE_ASI_H */
