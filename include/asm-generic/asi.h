/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_GENERIC_ASI_H
#define __ASM_GENERIC_ASI_H

#include <linux/types.h>

#ifndef _ASSEMBLY_

/*
 * An ASI class is a type of isolation that can be applied to a process. A
 * process may have a domain for each class.
 */
enum asi_class_id {
#if IS_ENABLED(CONFIG_KVM)
	ASI_CLASS_KVM,
#endif
	ASI_MAX_NUM_CLASSES,
};

typedef u8 asi_taints_t;

#ifndef CONFIG_MITIGATION_ADDRESS_SPACE_ISOLATION

struct asi_hooks {};
struct asi {};

static inline
int asi_init_class(enum asi_class_id class_id,
		       asi_taints_t control_taints, asi_taints_t data_taints)
{
	return 0;
}

static inline void asi_uninit_class(enum asi_class_id class_id) { }

struct mm_struct;
static inline void asi_init_mm_state(struct mm_struct *mm) { }

static inline int asi_init(struct mm_struct *mm, enum asi_class_id class_id,
			   struct asi **out_asi)
{
	return 0;
}

static inline void asi_destroy(struct asi *asi) { }

static inline void asi_enter(struct asi *asi) { }

static inline void asi_relax(void) { }

static inline bool asi_is_relaxed(void) { return true; }

static inline bool asi_is_tense(void) { return false; }

static inline void asi_exit(void) { }

static inline bool asi_is_restricted(void) { return false; }

static inline struct asi *asi_get_current(void) { return NULL; }

struct task_struct;
static inline struct asi *asi_get_target(struct task_struct *p) { return NULL; }

static inline pgd_t *asi_pgd(struct asi *asi) { return NULL; }

static inline void asi_handle_switch_mm(void) { }

static inline int asi_map(struct asi *asi, void *addr, size_t len)
{
	return 0;
}

static inline
void asi_unmap(struct asi *asi, void *addr, size_t len) { }

#endif /* !CONFIG_MITIGATION_ADDRESS_SPACE_ISOLATION */

#endif  /* !_ASSEMBLY_ */

#endif
