/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_GENERIC_ASI_H
#define __ASM_GENERIC_ASI_H

#include <linux/log2.h>
#include <linux/types.h>

#ifndef _ASSEMBLY_

enum asi_exit_reason {
	ASI_EXIT_PAGE_FAULT,
	ASI_EXIT_USER_RET,
	ASI_EXIT_CONTEXT_SWITCH,
	ASI_EXIT_TLB_FLUSH,
	ASI_EXIT_MISC,
	NR_ASI_EXIT_REASONS,
};

/*
 * An ASI class is a type of isolation that can be applied to a process. A
 * process may have a domain for each class.
 */
enum asi_class_id {
#if IS_ENABLED(CONFIG_KVM)
	ASI_CLASS_KVM,
#endif
	ASI_CLASS_USERSPACE,
#if IS_ENABLED(CONFIG_ASI_KUNIT_TESTS)
	ASI_CLASS_TEST,
#endif
	ASI_MAX_NUM_CLASSES,
};
static_assert(order_base_2(X86_CR3_ASI_PCID_BITS) <= ASI_MAX_NUM_CLASSES);

typedef u8 asi_taints_t;

#ifndef CONFIG_MITIGATION_ADDRESS_SPACE_ISOLATION

#define ASI_GLOBAL_NONSENSITIVE		NULL

struct asi_hooks {};
struct asi {};

static inline
int asi_init_class(enum asi_class_id class_id,
		       asi_taints_t control_taints, asi_taints_t data_taints)
{
	return 0;
}

static inline void asi_uninit_class(enum asi_class_id class_id) { }

static inline void asi_init_userspace_class(void) { }

struct mm_struct;
static inline int asi_init_mm_state(struct mm_struct *mm) { return 0; }

static inline int asi_init(struct mm_struct *mm, enum asi_class_id class_id,
			   struct asi **out_asi)
{
	return 0;
}

static inline void asi_destroy(struct asi *asi) { }

static inline void asi_destroy_userspace(struct mm_struct *mm) { }

static inline void asi_enter(struct asi *asi) { }

static inline void asi_enter_userspace(void) { }

static inline void asi_relax(void) { }

static inline bool asi_is_relaxed(void) { return true; }

static inline bool asi_is_tense(void) { return false; }

static inline bool asi_in_critical_section(void) { return false; }

static inline bool asi_exit(enum asi_exit_reason reason) { return false; }

static inline bool asi_is_restricted(void) { return false; }

static inline struct asi *asi_get_current(void) { return NULL; }

struct task_struct;
static inline struct asi *asi_get_target(struct task_struct *p) { return NULL; }

static inline pgd_t *asi_pgd(struct asi *asi) { return NULL; }

static inline void asi_handle_switch_mm(void) { }

struct thread_struct;
static inline void asi_init_thread_state(struct thread_struct *thread) { }

static inline void asi_intr_enter(void) { }

static inline int asi_intr_nest_depth(void) { return 0; }

static inline void asi_intr_exit(void) { }

static inline int asi_map(struct asi *asi, void *addr, size_t len)
{
	return 0;
}

static inline bool asi_is_mapped(struct asi *asi, void *addr) { return false; }

static inline
void asi_unmap_noflush(struct asi *asi, void *addr, size_t len) { }
static inline
void asi_unmap(struct asi *asi, void *addr, size_t len) { }

static inline
void asi_flush_tlb_range(struct asi *asi, void *addr, size_t len) { }

#define static_asi_enabled() false

static inline void asi_check_boottime_disable(void) { }

static inline void asi_clone_user_pgtbl(struct mm_struct *mm, pgd_t *pgdp) { };

static inline bool asi_maps_user_addr(enum asi_class_id class_id) { return false; }

#endif /* !CONFIG_MITIGATION_ADDRESS_SPACE_ISOLATION */

#endif  /* !_ASSEMBLY_ */

#endif
