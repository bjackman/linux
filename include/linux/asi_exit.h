/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _INCLUDE_ASI_EXIT_H
#define _INCLUDE_ASI_EXIT_H

#include <linux/types.h>

enum asi_exit_reason {
	ASI_EXIT_PAGE_FAULT,
	ASI_EXIT_USER_RET,
	ASI_EXIT_CONTEXT_SWITCH,
	ASI_EXIT_TLB_FLUSH,
	ASI_EXIT_MISC,
	NR_ASI_EXIT_REASONS,
};

/*
 * TODO: Annoying workaround for cyclic header dependency (ASI needs task_struct
 * definition. sched headers include special_insns.h. That needs to call
 * asi_exit()). Can't just forward-declare it in special_insns.h because the
 * definition is different (static inline or not) depending on config.
 *
 * Kicking this can down the road since I expect the header structure to change
 * dramatically during LKML reviews anyway.
 */
#ifdef CONFIG_MITIGATION_ADDRESS_SPACE_ISOLATION
/*
 * Immediately exit the restricted address space if in it. If we did that,
 * return true. Note that the return value is accurate inasmuch as we
 * "performed" an ASI exit, but due to reentrancy it's possible that we return
 * true from a call that didn't actually create an address space transition.
 */
bool asi_exit(enum asi_exit_reason reason);
#else
static inline bool asi_exit(enum asi_exit_reason reason) { return false; }
#endif

#endif /* _INCLUDE_ASI_EXIT_H */