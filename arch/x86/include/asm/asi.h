/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_ASI_H
#define _ASM_X86_ASI_H

#include <linux/sched.h>

#include <asm-generic/asi.h>

#include <asm/pgtable_types.h>
#include <asm/percpu.h>
#include <asm/processor.h>

#ifdef CONFIG_MITIGATION_ADDRESS_SPACE_ISOLATION

/*
 * Overview of API usage by ASI clients:
 *
 * Setup: First call asi_init() to create a domain. At present only one domain
 * can be created per mm per class, but it's safe to asi_init() this domain
 * multiple times. For each asi_init() call you must call asi_destroy() AFTER
 * you are certain all CPUs have exited the restricted address space (by
 * calling asi_exit()).
 *
 * Runtime usage:
 *
 * 1. Call asi_enter() to switch to the restricted address space. This can't be
 *    from an interrupt or exception handler and preemption must be disabled.
 *
 * 2. Execute untrusted code.
 *
 * 3. Call asi_relax() to inform the ASI subsystem that untrusted code execution
 *    is finished. This doesn't cause any address space change. This can't be
 *    from an interrupt or exception handler and preemption must be disabled.
 *
 * 4. Either:
 *
 *    a. Go back to 1.
 *
 *    b. Call asi_exit() before returning to userspace. This immediately
 *       switches to the unrestricted address space.
 *
 * The region between 1 and 3 is called the "ASI critical section". During the
 * critical section, it is a bug to access any sensitive data, and you mustn't
 * sleep.
 *
 * The restriction on sleeping is not really a fundamental property of ASI.
 * However for performance reasons it's important that the critical section is
 * absolutely as short as possible. So the ability to do sleepy things like
 * taking mutexes oughtn't to confer any convenience on API users.
 *
 * Similarly to the issue of sleeping, the need to asi_exit in case 4b is not a
 * fundamental property of the system but a limitation of the current
 * implementation. With further work it is possible to context switch
 * from and/or to the restricted address space, and to return to userspace
 * directly from the restricted address space, or _in_ it.
 *
 * Note that the critical section only refers to the direct execution path from
 * asi_enter to asi_relax: it's fine to access sensitive data from exceptions
 * and interrupt handlers that occur during that time. ASI will re-enter the
 * restricted address space before returning from the outermost
 * exception/interrupt.
 *
 * Note: ASI does not modify KPTI behaviour; when ASI and KPTI run together
 * there are 2+N address spaces per task: the unrestricted kernel address space,
 * the user address space, and one restricted (kernel) address space for each of
 * the N ASI classes.
 */

/*
 * ASI uses a per-CPU tainting model to track what mitigation actions are
 * required on domain transitions. Taints exist along two dimensions:
 *
 *  - Who touched the CPU (guest, unprotected kernel, userspace).
 *
 *  - What kind of state might remain: "data" means there might be data owned by
 *    a victim domain left behind in a sidechannel. "Control" means there might
 *    be state controlled by an attacker domain left behind in the branch
 *    predictor.
 *
 *    In principle the same domain can be both attacker and victim, thus we have
 *    both data and control taints for userspace, although there's no point in
 *    trying to protect against attacks from the kernel itself, so there's no
 *    ASI_TAINT_KERNEL_CONTROL.
 */
#define ASI_TAINT_KERNEL_DATA		((asi_taints_t)BIT(0))
#define ASI_TAINT_USER_DATA		((asi_taints_t)BIT(1))
#define ASI_TAINT_GUEST_DATA		((asi_taints_t)BIT(2))
#define ASI_TAINT_OTHER_MM_DATA		((asi_taints_t)BIT(3))
#define ASI_TAINT_USER_CONTROL		((asi_taints_t)BIT(4))
#define ASI_TAINT_GUEST_CONTROL		((asi_taints_t)BIT(5))
#define ASI_TAINT_OTHER_MM_CONTROL	((asi_taints_t)BIT(6))
#define ASI_NUM_TAINTS			6
static_assert(BITS_PER_BYTE * sizeof(asi_taints_t) >= ASI_NUM_TAINTS);

#define ASI_TAINTS_CONTROL_MASK \
	(ASI_TAINT_USER_CONTROL | ASI_TAINT_GUEST_CONTROL | ASI_TAINT_OTHER_MM_CONTROL)

#define ASI_TAINTS_DATA_MASK \
	(ASI_TAINT_KERNEL_DATA | ASI_TAINT_USER_DATA | ASI_TAINT_OTHER_MM_DATA)

#define ASI_TAINTS_GUEST_MASK (ASI_TAINT_GUEST_DATA | ASI_TAINT_GUEST_CONTROL)
#define ASI_TAINTS_USER_MASK (ASI_TAINT_USER_DATA | ASI_TAINT_USER_CONTROL)

/* The taint policy tells ASI how a class interacts with the CPU taints */
struct asi_taint_policy {
	/*
	 * What taints would necessitate a flush when entering the domain, to
	 * protect it from attack by prior domains?
	 */
	asi_taints_t prevent_control;
	/*
	 * What taints would necessetate a flush when entering the domain, to
	 * protect former domains from attack by this domain?
	 */
	asi_taints_t protect_data;
	/* What taints should be set when entering the domain? */
	asi_taints_t set;
};

extern struct asi __asi_global_nonsensitive;
#define ASI_GLOBAL_NONSENSITIVE	(&__asi_global_nonsensitive)

/*
 * An ASI domain (struct asi) represents a restricted address space. The
 * unrestricted address space (and user address space under PTI) are not
 * represented as a domain.
 */
struct asi {
	pgd_t *pgd;
	struct mm_struct *mm;
	int64_t ref_count;
	enum asi_class_id class_id;
};

DECLARE_PER_CPU_ALIGNED(struct asi *, curr_asi);

void asi_init_mm_state(struct mm_struct *mm);

int asi_init_class(enum asi_class_id class_id, struct asi_taint_policy *taint_policy);
void asi_uninit_class(enum asi_class_id class_id);
const char *asi_class_name(enum asi_class_id class_id);

int asi_init(struct mm_struct *mm, enum asi_class_id class_id, struct asi **out_asi);
void asi_destroy(struct asi *asi);

/* Enter an ASI domain (restricted address space) and begin the critical section. */
void asi_enter(struct asi *asi);

/*
 * Leave the "tense" state if we are in it, i.e. end the critical section. We
 * will stay relaxed until the next asi_enter.
 */
void asi_relax(void);

/* Immediately exit the restricted address space if in it */
void asi_exit(void);

int  asi_map(struct asi *asi, void *addr, size_t len);
void asi_unmap(struct asi *asi, void *addr, size_t len);

/* The target is the domain we'll enter when returning to process context. */
static __always_inline struct asi *asi_get_target(struct task_struct *p)
{
	return p->thread.asi_state.target;
}

static __always_inline void asi_set_target(struct task_struct *p,
					   struct asi *target)
{
	p->thread.asi_state.target = target;
}

static __always_inline struct asi *asi_get_current(void)
{
	return this_cpu_read(curr_asi);
}

/* Are we currently in a restricted address space? */
static __always_inline bool asi_is_restricted(void)
{
	return (bool)asi_get_current();
}

/* If we exit/have exited, can we stay that way until the next asi_enter? */
static __always_inline bool asi_is_relaxed(void)
{
	return !asi_get_target(current);
}

/*
 * Is the current task in the critical section?
 *
 * This is just the inverse of !asi_is_relaxed(). We have both functions in order to
 * help write intuitive client code. In particular, asi_is_tense returns false
 * when ASI is disabled, which is judged to make user code more obvious.
 */
static __always_inline bool asi_is_tense(void)
{
	return !asi_is_relaxed();
}

static __always_inline pgd_t *asi_pgd(struct asi *asi)
{
	return asi ? asi->pgd : NULL;
}

#define INIT_MM_ASI(init_mm) \
	.asi_init_lock = __MUTEX_INITIALIZER(init_mm.asi_init_lock),

void asi_handle_switch_mm(void);

void asi_sync_physmap(unsigned long start, unsigned long end);

#endif /* CONFIG_MITIGATION_ADDRESS_SPACE_ISOLATION */

#endif
