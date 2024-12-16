/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _INCLUDE_ASI_H
#define _INCLUDE_ASI_H

#include <asm/pgtable_types.h>

enum asi_class_id {
#if IS_ENABLED(CONFIG_KVM)
	ASI_CLASS_KVM,
#endif
	ASI_MAX_NUM_CLASSES,
};

#ifdef CONFIG_MITIGATION_ADDRESS_SPACE_ISOLATION
#include <asm/asi.h>
#else

#define static_asi_enabled() false
static inline void asi_check_boottime_disable(void) { }

#define ASI_GLOBAL_NONSENSITIVE NULL

struct asi {};
struct asi_taint_policy {};

static inline int asi_init_class(enum asi_class_id class_id,
				 struct asi_taint_policy *taint_policy)
{
	return 0;
}
static inline void asi_uninit_class(enum asi_class_id claass_id) { }

struct mm_struct;
static inline int asi_init(struct mm_struct *mm, enum asi_class_id class_id,
			   struct asi **out_asi)
{
	return 0;
}
static inline void asi_destroy(struct asi *asi) { }

static inline pgd_t *asi_pgd(struct asi *asi) { return NULL; }
static inline void asi_map(struct page *page, int numpages) { }
static inline void asi_unmap(struct page *page, int numpages) { }

static inline void asi_enter(struct asi *asi) { }
static inline void asi_exit(void) { }
static inline void asi_relax(void) { }

static inline struct asi *asi_get_current(void) { return NULL; }
static inline bool asi_in_critical_section(void) { return false; }

static inline void asi_handle_switch_mm(void) { }
static inline void asi_init_mm_state(struct mm_struct *mm) { }

struct thread_struct;
static inline void asi_init_thread_state(struct thread_struct *thread) { }

#endif /* CONFIG_MITIGATION_ADDRESS_SPACE_ISOLATION */
#endif /* _INCLUDE_ASI_H */
