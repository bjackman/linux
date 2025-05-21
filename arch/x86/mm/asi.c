// SPDX-License-Identifier: GPL-2.0
#include <linux/compiler_types.h>
#include <linux/export.h>
#include <linux/percpu.h>
#include <linux/spinlock.h>

#include <linux/init.h>
#include <linux/pgtable.h>
#include <linux/syscore_ops.h>

#include <kunit/visibility.h>

#include <asm/asi.h>
#include <asm/cmdline.h>
#include <asm/cpufeature.h>
#include <asm/l1tf.h>
#include <asm/page.h>
#include <asm/pgalloc.h>
#include <asm/mmu_context.h>
#include <asm/traps.h>
#include <asm/pgtable.h>

#include "asi_internal.h"
#include "mm_internal.h"
#include "../../../mm/internal.h"

static struct asi_taint_policy *taint_policies[ASI_MAX_NUM_CLASSES];

const char *asi_class_names[] = {
#if IS_ENABLED(CONFIG_KVM)
	[ASI_CLASS_KVM] = "KVM",
#endif
	[ASI_CLASS_USERSPACE] = "userspace",
};


DEFINE_PER_CPU_ALIGNED(struct asi *, curr_asi);
EXPORT_SYMBOL(curr_asi);

DEFINE_STATIC_KEY_TRUE(asi_sandbox_userspace);

static void asi_stat_inc(enum asi_stat_item index);

static __aligned(PAGE_SIZE) pgd_t asi_global_nonsensitive_pgd[PTRS_PER_PGD];

struct asi __asi_global_nonsensitive = {
	.pgd = asi_global_nonsensitive_pgd,
	.mm = &init_mm,
};
EXPORT_SYMBOL_IF_KUNIT(__asi_global_nonsensitive);

static bool do_l1tf_flush __ro_after_init;

static inline bool asi_class_id_valid(enum asi_class_id class_id)
{
	return class_id >= 0 && class_id < ASI_MAX_NUM_CLASSES;
}

VISIBLE_IF_KUNIT inline bool asi_class_initialized(enum asi_class_id class_id)
{
	if (!boot_cpu_has(X86_FEATURE_ASI))
		return 0;

	if (WARN_ON(!asi_class_id_valid(class_id)))
		return false;

	return !!(taint_policies[class_id]);
}
EXPORT_SYMBOL_IF_KUNIT(asi_class_initialized);

int asi_init_class(enum asi_class_id class_id, struct asi_taint_policy *taint_policy)
{
	if (asi_class_initialized(class_id))
		return -EEXIST;

	WARN_ON(!(taint_policy->prevent_control & ASI_TAINTS_CONTROL_MASK));
	WARN_ON(!(taint_policy->protect_data & ASI_TAINTS_DATA_MASK));

	taint_policies[class_id] = taint_policy;

	return 0;
}
EXPORT_SYMBOL_GPL(asi_init_class);

void __init asi_init_userspace_class(void)
{
	static struct asi_taint_policy policy = {
		/*
		 * Prevent going to userspace with sensitive data potentially
		 * left in sidechannels by code running in the unrestricted
		 * address space, or another MM. Note we don't check for guest
		 * data here. This reflects the assumption that the guest trusts
		 * its VMM (absent fancy HW features, which are orthogonal).
		 */
		.protect_data = ASI_TAINT_KERNEL_DATA | ASI_TAINT_OTHER_MM_DATA,
		/*
		 * Don't go into userspace with control flow state controlled by
		 * other processes, or any KVM guest the process is running.
		 * Note this bit is about protecting userspace from other parts
		 * of the system, while data_taints is about protecting other
		 * parts of the system from the guest.
		 */
		.prevent_control = ASI_TAINT_GUEST_CONTROL | ASI_TAINT_OTHER_MM_CONTROL,
		.set = ASI_TAINT_USER_CONTROL | ASI_TAINT_USER_DATA,
	};
	int err = asi_init_class(ASI_CLASS_USERSPACE, &policy);

	WARN_ON(err);
}

void asi_uninit_class(enum asi_class_id class_id)
{
	if (!boot_cpu_has(X86_FEATURE_ASI))
		return;

	if (!asi_class_initialized(class_id))
		return;

	taint_policies[class_id] = NULL;
}
EXPORT_SYMBOL_GPL(asi_uninit_class);

const char *asi_class_name(enum asi_class_id class_id)
{
	if (WARN_ON_ONCE(!asi_class_id_valid(class_id)))
		return "<invalid>";

	return asi_class_names[class_id];
}

#ifndef mm_inc_nr_p4ds
#define mm_inc_nr_p4ds(mm)	do {} while (false)
#endif

#ifndef mm_dec_nr_p4ds
#define mm_dec_nr_p4ds(mm)	do {} while (false)
#endif

#define pte_offset		pte_offset_kernel

/*
 * asi_p4d_alloc, asi_pud_alloc, asi_pmd_alloc, asi_pte_alloc.
 *
 * These are like the normal xxx_alloc functions, but:
 *
 *  - They use atomic operations instead of taking a spinlock; this allows them
 *    to be used from interrupts. This is necessary because we use the page
 *    allocator from interrupts and the page allocator ultimately calls this
 *    code.
 *  - They support customizing the allocation flags.
 *  - They avoid infinite recursion when the page allocator calls back to
 *    asi_map
 *
 * On the other hand, they do not use the normal page allocation infrastructure,
 * that means that PTE pages do not have the PageTable type nor the PagePgtable
 * flag and we don't increment the meminfo stat (NR_PAGETABLE) as they do.
 *
 * As an optimisation we attempt to map the pagetables in
 * ASI_GLOBAL_NONSENSITIVE, but this can fail, and for simplicity we don't do
 * anything about that. This means it's invalid to access ASI pagetables from a
 * critical section.
 */
static_assert(!IS_ENABLED(CONFIG_PARAVIRT));
#define DEFINE_ASI_PGTBL_ALLOC(base, level)				\
static level##_t * asi_##level##_alloc(struct asi *asi,			\
				       base##_t *base, ulong addr,	\
				       gfp_t flags)			\
{									\
	if (unlikely(base##_none(*base))) {				\
		/* Stop asi_map calls causing recursive allocation */	\
		gfp_t pgtbl_gfp = flags | __GFP_SENSITIVE;		\
		ulong pgtbl = get_zeroed_page(pgtbl_gfp);		\
		phys_addr_t pgtbl_pa;					\
		int err;						\
									\
		if (!pgtbl)						\
			return NULL;					\
									\
		pgtbl_pa = __pa(pgtbl);					\
									\
		if (cmpxchg((ulong *)base, 0,				\
			    pgtbl_pa | _PAGE_TABLE) != 0) {		\
			free_page(pgtbl);				\
			goto out;					\
		}							\
									\
		mm_inc_nr_##level##s(asi->mm);				\
									\
		err = asi_map_gfp(ASI_GLOBAL_NONSENSITIVE,		\
				  (void *)pgtbl, PAGE_SIZE, flags);	\
		if (err)						\
			/* Should be rare. Spooky. */			\
			pr_warn_ratelimited("Created sensitive ASI %s (%pK, maps %luK).\n",\
				#level, (void *)pgtbl, addr);		\
		else							\
			__SetPageGlobalNonSensitive(virt_to_page(pgtbl));\
									\
	}								\
out:									\
	VM_BUG_ON(base##_leaf(*base));					\
	return level##_offset(base, addr);				\
}

DEFINE_ASI_PGTBL_ALLOC(pgd, p4d)
DEFINE_ASI_PGTBL_ALLOC(p4d, pud)
DEFINE_ASI_PGTBL_ALLOC(pud, pmd)
DEFINE_ASI_PGTBL_ALLOC(pmd, pte)

void __init asi_check_boottime_disable(void)
{
	bool enabled = IS_ENABLED(CONFIG_MITIGATION_ADDRESS_SPACE_ISOLATION_DEFAULT_ON);
	char arg[4];
	int ret;

	ret = cmdline_find_option(boot_command_line, "asi", arg, sizeof(arg));
	if (ret == 3 && !strncmp(arg, "off", 3)) {
		enabled = false;
		pr_info("ASI disabled through kernel command line.\n");
	} else if (ret == 2 && !strncmp(arg, "on", 2)) {
		enabled = true;
		pr_info("ASI enabled through kernel command line.\n");
	} else {
		pr_info("ASI %s by default.\n",
			enabled ? "enabled" : "disabled");
	}

	if (enabled)
		setup_force_cpu_cap(X86_FEATURE_ASI);
	else
		return;

	ret = cmdline_find_option(boot_command_line, "asi_userspace", arg, sizeof(arg));
	if (ret == 3 && !strncmp(arg, "off", 3))
		static_branch_disable(&asi_sandbox_userspace);
	else if (ret == 2 && !strncmp(arg, "on", 3))
		static_branch_enable(&asi_sandbox_userspace);
}

/*
 * Map data by sharing sub-PGD pagetables with the unrestricted mapping. This is
 * more efficient than asi_map, but only works when you know the whole top-level
 * page needs to be mapped in the restricted tables. Note that the size of the
 * mappings this creates differs between 4 and 5-level paging.
 */
static void asi_clone_pgd(pgd_t *dst_table, pgd_t *src_table, size_t addr)
{
	pgd_t *src = pgd_offset_pgd(src_table, addr);
	pgd_t *dst = pgd_offset_pgd(dst_table, addr);

	if (!pgd_val(*dst))
		set_pgd(dst, *src);
	else
		WARN_ON_ONCE(pgd_val(*dst) != pgd_val(*src));
}

/*
 * For 4-level paging this is exactly the same as asi_clone_pgd. For 5-level
 * paging it clones one level lower. So this always creates a mapping of the
 * same size.
 */
static void asi_clone_p4d(pgd_t *dst_table, pgd_t *src_table, size_t addr)
{
	pgd_t *src_pgd = pgd_offset_pgd(src_table, addr);
	pgd_t *dst_pgd = pgd_offset_pgd(dst_table, addr);
	p4d_t *src_p4d = p4d_alloc(&init_mm, src_pgd, addr);
	p4d_t *dst_p4d = p4d_alloc(&init_mm, dst_pgd, addr);

	if (!p4d_val(*dst_p4d))
		set_p4d(dst_p4d, *src_p4d);
	else
		WARN_ON_ONCE(p4d_val(*dst_p4d) != p4d_val(*src_p4d));
}

/*
 * percpu_addr is where the linker put the percpu variable. asi_map_percpu finds
 * the place where the percpu allocator copied the data during boot.
 *
 * This is necessary even when the page allocator defaults to
 * global-nonsensitive, because the percpu allocator uses the memblock allocator
 * for early allocations.
 */
static int asi_map_percpu(struct asi *asi, void *percpu_addr, size_t len)
{
	int cpu, err;
	void *ptr;

	for_each_possible_cpu(cpu) {
		ptr = per_cpu_ptr(percpu_addr, cpu);
		err = asi_map(asi, ptr, len);
		if (err)
			return err;
	}

	return 0;
}

#ifdef CONFIG_PM_SLEEP
static int asi_suspend(void)
{
	/*
	 * Must be called after IRQs are disabled and rescheduling is no longer
	 * possible (so that we cannot re-enter ASI before suspending.
	 */
	lockdep_assert_irqs_disabled();

	/*
	 * Suspend operations sometimes save CR3 as part of the saved state,
	 * which is restored later (e.g. do_suspend_lowlevel() in the suspend
	 * path, swsusp_arch_suspend() in the hibernate path, relocate_kernel()
	 * in the kexec path). Saving a restricted CR3 and restoring it later
	 * could leave to improperly entering ASI. Exit ASI before such
	 * operations.
	 */
	asi_exit(ASI_EXIT_MISC);
	return 0;
}

static struct syscore_ops asi_syscore_ops = {
	.suspend = asi_suspend,
};
#endif /* CONFIG_PM_SLEEP */

#if IS_ENABLED(CONFIG_ASI_KUNIT_TESTS)

struct asi_cpu_stats {
	uint64_t stats[NR_ASI_STAT_ITEMS];
};

DEFINE_PER_CPU_ALIGNED(struct asi_cpu_stats, asi_stats);

int64_t asi_cpu_stat(int cpu, enum asi_stat_item item)
{
	return per_cpu(asi_stats, cpu).stats[item];
}
EXPORT_SYMBOL_IF_KUNIT(asi_cpu_stat);

static __always_inline void asi_stat_inc(enum asi_stat_item index)
{
	if (WARN_ON_ONCE(index >= ARRAY_SIZE(asi_stats.stats)))
		return;

	this_cpu_inc(asi_stats.stats[index]);
}

#else
static __always_inline void asi_stat_inc(enum asi_stat_item index) { }
#endif

static int __init asi_global_init(void)
{
	int err;

	if (!boot_cpu_has(X86_FEATURE_ASI))
		return 0;

	/*
	 * Lower-level pagetables for global nonsensitive mappings are shared,
	 * but the PGD has to be copied into each domain during asi_init. To
	 * avoid needing to synchronize new mappings into pre-existing domains
	 * we just pre-allocate all of the relevant level N-1 entries so that
	 * the global nonsensitive PGD already has pointers that can be copied
	 * when new domains get asi_init()ed.
	 */
	preallocate_sub_pgd_pages(asi_global_nonsensitive_pgd,
				  PAGE_OFFSET,
				  PAGE_OFFSET + PFN_PHYS(max_pfn) - 1,
				  "ASI Global Non-sensitive direct map");
	preallocate_sub_pgd_pages(asi_global_nonsensitive_pgd,
				  VMALLOC_START, VMALLOC_END,
				  "ASI Global Non-sensitive vmalloc");
	preallocate_sub_pgd_pages(asi_global_nonsensitive_pgd,
				  MODULES_VADDR, MODULES_END,
				  "ASI Global Non-sensitive module mappings");

	/* Map all kernel text and static data */
	err = asi_map(ASI_GLOBAL_NONSENSITIVE, (void *)__START_KERNEL,
		      (size_t)_end - __START_KERNEL);
	if (WARN_ON(err))
		return err;
	err = asi_map(ASI_GLOBAL_NONSENSITIVE, (void *)FIXADDR_START,
		      FIXADDR_SIZE);
	if (WARN_ON(err))
		return err;
	/* Map all static percpu data */
	err = asi_map_percpu(
		ASI_GLOBAL_NONSENSITIVE,
		__per_cpu_start, __per_cpu_end - __per_cpu_start);
	if (WARN_ON(err))
		return err;

	/*
	 * The next areas are mapped using shared sub-P4D paging structures
	 * (asi_clone_p4d instead of asi_map), since we know the whole P4D will
	 * be mapped.
	 */
	asi_clone_p4d(asi_global_nonsensitive_pgd, init_mm.pgd,
		      CPU_ENTRY_AREA_BASE);
#ifdef CONFIG_X86_ESPFIX64
	asi_clone_p4d(asi_global_nonsensitive_pgd, init_mm.pgd,
		      ESPFIX_BASE_ADDR);
#endif
	/*
	 * The vmemmap area actually _must_ be cloned via shared paging
	 * structures, since mappings can potentially change dynamically when
	 * hugetlbfs pages are created or broken down.
	 *
	 * We always clone 2 PGDs, this is a corrolary of the sizes of struct
	 * page, a page, and the physical address space.
	 */
	WARN_ON(sizeof(struct page) * MAXMEM / PAGE_SIZE != 2 * (1UL << PGDIR_SHIFT));
	asi_clone_pgd(asi_global_nonsensitive_pgd, init_mm.pgd, VMEMMAP_START);
	asi_clone_pgd(asi_global_nonsensitive_pgd, init_mm.pgd,
		      VMEMMAP_START + (1UL << PGDIR_SHIFT));

	if (boot_cpu_has_bug(X86_BUG_L1TF)) {
		int err = l1tf_flush_setup();

		if (err)
			pr_warn("Failed to setup L1TF flushing for ASI (%pe)", ERR_PTR(err));
		else
			do_l1tf_flush = true;
	}

#ifdef CONFIG_PM_SLEEP
	register_syscore_ops(&asi_syscore_ops);
#endif

	return 0;
}
subsys_initcall(asi_global_init)

static void __asi_destroy(struct asi *asi)
{
	WARN_ON_ONCE(asi->ref_count <= 0);
	if (--(asi->ref_count) > 0)
		return;

	free_pages((ulong)asi->pgd, PGD_ALLOCATION_ORDER);
	memset(asi, 0, sizeof(struct asi));
}

static void __asi_init_user_pgds(struct mm_struct *mm, struct asi *asi)
{
	int i;

	if (!asi_maps_user_addr(asi->class_id))
		return;

	/*
	 * The code below must be executed only after the given asi is
	 * available in mm->asi[index] to ensure at least either this
	 * function or __asi_clone_user_pgd() will copy entries in the
	 * unrestricted pgd to the restricted pgd.
	 */
	if (WARN_ON_ONCE(&mm->asi[asi->class_id] != asi))
		return;

	/*
	 * See the comment for __asi_clone_user_pgd() why we hold the lock here.
	 */
	spin_lock(&asi->pgd_lock);

	for (i = 0; i < KERNEL_PGD_BOUNDARY; i++)
		set_pgd(asi->pgd + i, READ_ONCE(*(mm->pgd + i)));

	spin_unlock(&asi->pgd_lock);
}

int asi_init(struct mm_struct *mm, enum asi_class_id class_id, struct asi **out_asi)
{
	struct asi *asi;
	int err = 0;
	uint i;

	if (out_asi)
		*out_asi = NULL;

	if (!boot_cpu_has(X86_FEATURE_ASI))
		return 0;

	if (WARN_ON(!asi_class_initialized(class_id)))
		return -EINVAL;

	asi = &mm->asi[class_id];

	mutex_lock(&mm->asi_init_lock);

	if (asi->ref_count++ > 0)
		goto exit_unlock; /* err is 0 */

	BUG_ON(asi->pgd != NULL);

	/*
	 * For now, we allocate 2 pages to avoid any potential problems with
	 * KPTI code. This won't be needed once KPTI is folded into the ASI
	 * framework.
	 */
	asi->pgd = (pgd_t *)__get_free_pages(
		GFP_KERNEL_ACCOUNT | __GFP_ZERO, PGD_ALLOCATION_ORDER);
	if (!asi->pgd) {
		err = -ENOMEM;
		goto exit_unlock;
	}

	asi->mm = mm;
	asi->class_id = class_id;
	spin_lock_init(&asi->pgd_lock);

	for (i = KERNEL_PGD_BOUNDARY; i < PTRS_PER_PGD; i++)
		set_pgd(asi->pgd + i, asi_global_nonsensitive_pgd[i]);

exit_unlock:
	if (err)
		__asi_destroy(asi);
	else if (out_asi)
		*out_asi = asi;

	__asi_init_user_pgds(mm, asi);
	mutex_unlock(&mm->asi_init_lock);

	return err;
}
EXPORT_SYMBOL_GPL(asi_init);

void asi_destroy(struct asi *asi)
{
	struct mm_struct *mm;

	if (!boot_cpu_has(X86_FEATURE_ASI) || !asi)
		return;

	if (WARN_ON(!asi_class_initialized(asi->class_id)))
		return;

	mm = asi->mm;
	/*
	 * We would need this mutex even if the refcount was atomic as we need
	 * to block concurrent asi_init calls.
	 */
	mutex_lock(&mm->asi_init_lock);
	__asi_destroy(asi);
	mutex_unlock(&mm->asi_init_lock);
}
EXPORT_SYMBOL_GPL(asi_destroy);

DEFINE_PER_CPU_ALIGNED(asi_taints_t, asi_taints);
EXPORT_SYMBOL_IF_KUNIT(asi_taints);

/*
 * Flush out any potentially malicious speculative control flow (e.g. branch
 * predictor) state if necessary when we are entering a new domain (which may be
 * NULL when we are exiting to the restricted address space).
 *
 * This is "backwards-looking" mitigation, the attacker is in the past: we want
 * then when logically transitioning from A to B and B doesn't trust A.
 *
 * This function must tolerate reentrancy.
 */
static __always_inline void maybe_flush_control(struct asi *next_asi)
{
	asi_taints_t taints = this_cpu_read(asi_taints);

	if (next_asi) {
		taints &= taint_policies[next_asi->class_id]->prevent_control;
	} else {
		/*
		 * Going to the unrestricted address space, this has an implicit
		 * policy of flushing all taints.
		 */
		taints &= ASI_TAINTS_CONTROL_MASK;
	}

	if (!taints)
		return;

	/* Clear normal indirect branch predictions, if we haven't */
	if (cpu_feature_enabled(X86_FEATURE_IBPB))
		__wrmsr(MSR_IA32_PRED_CMD, PRED_CMD_IBPB, 0);

	fill_return_buffer();

	this_cpu_and(asi_taints, ~ASI_TAINTS_CONTROL_MASK);
}

/*
 * Flush out any data that might be hanging around in uarch state that can be
 * leaked through sidechannels if necessary when we are entering a new domain.
 *
 * This is "forwards-looking" mitigation, the attacker is in the future: we want
 * this when logically transitioning from A to B and A doesn't trust B.
 *
 * This function must tolerate reentrancy.
 */
static __always_inline void maybe_flush_data(struct asi *next_asi)
{
	asi_taints_t taints = this_cpu_read(asi_taints)
		& taint_policies[next_asi->class_id]->protect_data;

	if (!taints)
		return;

	if (do_l1tf_flush)
		l1tf_flush();

	this_cpu_and(asi_taints, ~ASI_TAINTS_DATA_MASK);
}

void asi_destroy_userspace(struct mm_struct *mm)
{
	VM_BUG_ON(!asi_class_initialized(ASI_CLASS_USERSPACE));
	asi_destroy(&mm->asi[ASI_CLASS_USERSPACE]);
}

noinstr void __asi_enter(void)
{
	u64 asi_cr3;
	u16 pcid;
	struct asi *target = asi_get_target(current);

	/*
	 * This is actually false restriction, it should be fine to be
	 * preemptible during the critical section. But we haven't tested it. We
	 * will also need to disable preemption during this function itself and
	 * perhaps elsewhere. This false restriction shouldn't create any
	 * additional burden for ASI clients anyway: the critical section has
	 * to be as short as possible to avoid unnecessary ASI transitions so
	 * disabling preemption should be fine.
	 */
	VM_BUG_ON(preemptible());
	VM_BUG_ON(current->thread.asi_state.intr_nest_depth != 0);

	if (!target || target == this_cpu_read(curr_asi))
		return;

	VM_BUG_ON(this_cpu_read(cpu_tlbstate.loaded_mm) ==
		  LOADED_MM_SWITCHING);

	/*
	 * Must update curr_asi before writing CR3 to ensure an interrupting
	 * asi_exit sees that it may need to switch address spaces.
	 * This is the real beginning of the ASI critical section.
	 */
	this_cpu_write(curr_asi, target);
	maybe_flush_control(target);

	pcid = asi_pcid(target, this_cpu_read(cpu_tlbstate.loaded_mm_asid));
	asi_cr3 = build_cr3_pcid_noinstr(target->pgd, pcid, tlbstate_lam_cr3_mask(), false);
	write_cr3_raw(asi_cr3);

	maybe_flush_data(target);
	/*
	 * It's fine to set the control taints late like this, since we haven't
	 * actually got to the untrusted code yet. Waiting until now to set the
	 * data taints is less obviously correct: we've mapped in the incoming
	 * domain's secrets now so we can't guarantee they haven't already got
	 * into a sidechannel. However, preemption is off so the only way we can
	 * reach another asi_enter() is in the return from an interrupt - in
	 * that case the reentrant asi_enter() call is entering the same domain
	 * that we're entering at the moment, it doesn't need to flush those
	 * secrets.
	 */
	this_cpu_or(asi_taints, taint_policies[target->class_id]->set);
}
EXPORT_SYMBOL_IF_KUNIT(__asi_enter);

noinstr void asi_enter(struct asi *asi)
{
	if (!static_asi_enabled())
		return;

	VM_WARN_ON_ONCE(asi_intr_nest_depth());
	VM_WARN_ON_ONCE(!asi);

	/* Should not have an asi_enter() without a prior asi_relax(). */
	VM_WARN_ON_ONCE(asi_get_target(current));

	asi_set_target(current, asi);
	barrier();

	__asi_enter();
}
EXPORT_SYMBOL_GPL(asi_enter);

noinstr void asi_enter_userspace(void)
{
	if (!static_branch_likely(&asi_sandbox_userspace))
		return;

	asi_enter(&current->mm->asi[ASI_CLASS_USERSPACE]);
}
EXPORT_SYMBOL_IF_KUNIT(asi_enter_userspace);

noinstr void asi_relax(void)
{
	if (static_asi_enabled()) {
		VM_WARN_ON_ONCE(asi_intr_nest_depth());
		barrier();
		asi_set_target(current, NULL);
	}
}
EXPORT_SYMBOL_GPL(asi_relax);

noinstr bool asi_exit(enum asi_exit_reason reason)
{
	u64 unrestricted_cr3;
	struct asi *asi;

	if (!static_asi_enabled())
		return false;

	preempt_disable_notrace();

	VM_BUG_ON(this_cpu_read(cpu_tlbstate.loaded_mm) ==
		  LOADED_MM_SWITCHING);

	asi = this_cpu_read(curr_asi);
	if (asi) {
		WARN_ON_ONCE(asi_in_critical_section());
		asi_stat_inc((enum asi_stat_item)reason);

		maybe_flush_control(NULL);

		unrestricted_cr3 =
			build_cr3_noinstr(this_cpu_read(cpu_tlbstate.loaded_mm)->pgd,
					 this_cpu_read(cpu_tlbstate.loaded_mm_asid),
					 tlbstate_lam_cr3_mask());

		/* Tainting first makes reentrancy easier to reason about.  */
		this_cpu_or(asi_taints, ASI_TAINT_KERNEL_DATA);
		write_cr3_raw(unrestricted_cr3);
		/*
		 * Must not update curr_asi until after CR3 write, otherwise a
		 * re-entrant call might not enter this branch. (This means we
		 * might do unnecessary CR3 writes).
		 */
		this_cpu_write(curr_asi, NULL);
	}

	preempt_enable_notrace();
	return !!asi;
}
EXPORT_SYMBOL_GPL(asi_exit);

int asi_init_mm_state(struct mm_struct *mm)
{
	if (!boot_cpu_has(X86_FEATURE_ASI))
		return 0;

	memset(mm->asi, 0, sizeof(mm->asi));
	mutex_init(&mm->asi_init_lock);

	return asi_init(mm, ASI_CLASS_USERSPACE, NULL);
}

void asi_handle_switch_mm(void)
{
	/*
	 * We can't handle context switching in the restricted address space yet
	 * so this is pointless in practice (we asi_exit() in this path, which
	 * doesn't care about the fine details of who exactly got at the branch
	 * predictor), but just to illustrate how the tainting model is supposed
	 * to work, here we squash the per-domain (guest/userspace) taints into
	 * a general "other MM" taint. Other processes don't care if their peers
	 * are attacking them from a guest or from bare metal.
	 */
	asi_taints_t taints = this_cpu_read(asi_taints);
	asi_taints_t new_taints = 0;

	if (taints & ASI_TAINTS_CONTROL_MASK)
		new_taints |= ASI_TAINT_OTHER_MM_CONTROL;
	if (taints & ASI_TAINTS_DATA_MASK)
		new_taints |= ASI_TAINT_OTHER_MM_DATA;

	/*
	 * We can't race with asi_enter() or we'd clobber the taint it sets.
	 * Would be odd given this function says context_switch in the name but
	 * just be to sure...
	 */
	lockdep_assert_preemption_disabled();

	/*
	 * Can'tt just this_cpu_write here as we could be racing with asi_exit()
	 * (at least, in the future where this function is actually necessary),
	 * we mustn't clobber ASI_TAINT_KERNEL_DATA.
	 */
	this_cpu_or(asi_taints, new_taints);
	this_cpu_and(asi_taints, ~(ASI_TAINTS_GUEST_MASK | ASI_TAINTS_USER_MASK));
}

static bool is_page_within_range(unsigned long addr, unsigned long page_size,
				 unsigned long range_start, unsigned long range_end)
{
	unsigned long page_start = ALIGN_DOWN(addr, page_size);
	unsigned long page_end = page_start + page_size;

	return page_start >= range_start && page_end <= range_end;
}

VISIBLE_IF_KUNIT bool follow_physaddr(
	pgd_t *pgd_table, unsigned long virt,
	phys_addr_t *phys, unsigned long *page_size, ulong *flags)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	/* RFC: This should be rewritten with lookup_address_in_*. */

	*page_size = PGDIR_SIZE;
	pgd = pgd_offset_pgd(pgd_table, virt);
	if (!pgd_present(*pgd))
		return false;
	if (pgd_leaf(*pgd)) {
		*phys = PFN_PHYS(pgd_pfn(*pgd)) | (virt & ~PGDIR_MASK);
		*flags = pgd_flags(*pgd);
		return true;
	}

	*page_size = P4D_SIZE;
	p4d = p4d_offset(pgd, virt);
	if (!p4d_present(*p4d))
		return false;
	if (p4d_leaf(*p4d)) {
		*phys = PFN_PHYS(p4d_pfn(*p4d)) | (virt & ~P4D_MASK);
		*flags = p4d_flags(*p4d);
		return true;
	}

	*page_size = PUD_SIZE;
	pud = pud_offset(p4d, virt);
	if (!pud_present(*pud))
		return false;
	if (pud_leaf(*pud)) {
		*phys = PFN_PHYS(pud_pfn(*pud)) | (virt & ~PUD_MASK);
		*flags = pud_flags(*pud);
		return true;
	}

	*page_size = PMD_SIZE;
	pmd = pmd_offset(pud, virt);
	if (!pmd_present(*pmd))
		return false;
	if (pmd_leaf(*pmd)) {
		*phys = PFN_PHYS(pmd_pfn(*pmd)) | (virt & ~PMD_MASK);
		*flags = pmd_flags(*pmd);
		return true;
	}

	*page_size = PAGE_SIZE;
	pte = pte_offset_map(pmd, virt);
	if (!pte)
		return false;

	if (!pte_present(*pte)) {
		pte_unmap(pte);
		return false;
	}

	*phys = PFN_PHYS(pte_pfn(*pte)) | (virt & ~PAGE_MASK);
	*flags = pte_flags(*pte);

	pte_unmap(pte);
	return true;
}
EXPORT_SYMBOL_IF_KUNIT(follow_physaddr);

VISIBLE_IF_KUNIT bool addr_present(pgd_t *pgd, unsigned long addr)
{
	phys_addr_t phys;
	unsigned long page_size, flags;

	return follow_physaddr(pgd, addr, &phys, &page_size, &flags);
}
EXPORT_SYMBOL_IF_KUNIT(addr_present);

bool asi_is_mapped(struct asi *asi, void *addr)
{
	return addr_present(asi->pgd, (unsigned long)addr);
}

/*
 * Map the given range into the ASI page tables. The source of the mapping is
 * the regular unrestricted page tables. Can be used to map any kernel memory.
 *
 * In contrast to some internal ASI logic (asi_clone_pgd and asi_clone_p4d) this
 * never shares pagetables between restricted and unrestricted address spaces,
 * instead it creates wholly new equivalent mappings.
 *
 * The caller MUST ensure that the source mapping will not change during this
 * function. For dynamic kernel memory, this is generally ensured by mapping the
 * memory within the allocator.
 *
 * If this fails, it may leave partial mappings behind. You must asi_unmap them,
 * bearing in mind asi_unmap's requirements on the calling context. Part of the
 * reason for this is that we don't want to unexpectedly undo mappings that
 * weren't created by the present caller.
 *
 * This must not be called from the critical section, as ASI's pagetables are
 * not guaranteed to be mapped in the restricted address space.
 *
 * If the source mapping is a large page and the range being mapped spans the
 * entire large page, then it will be mapped as a large page in the ASI page
 * tables too. If the range does not span the entire huge page, then it will be
 * mapped as smaller pages. In that case, the implementation is slightly
 * inefficient, as it will walk the source page tables again for each small
 * destination page, but that should be ok for now, as usually in such cases,
 * the range would consist of a small-ish number of pages.
 *
 * RFC: * vmap_p4d_range supports huge mappings, we can probably use that now.
 */
int __must_check asi_map_gfp(struct asi *asi, void *addr, unsigned long len, gfp_t gfp_flags)
{
	unsigned long virt;
	unsigned long start = (size_t)addr;
	unsigned long end = start + len;
	unsigned long page_size;

	if (!static_asi_enabled())
		return 0;

	/* ASI pagetables might be sensitive. */
	WARN_ON_ONCE(asi_in_critical_section());

	VM_BUG_ON(!IS_ALIGNED(start, PAGE_SIZE));
	VM_BUG_ON(!IS_ALIGNED(len, PAGE_SIZE));
	/* RFC: fault_in_kernel_space should be renamed. */
	VM_BUG_ON(!fault_in_kernel_space(start));

	gfp_flags &= GFP_RECLAIM_MASK;

	if (asi->mm != &init_mm)
		gfp_flags |= __GFP_ACCOUNT;

	for (virt = start; virt < end; virt = ALIGN(virt + 1, page_size)) {
		pgd_t *pgd;
		p4d_t *p4d;
		pud_t *pud;
		pmd_t *pmd;
		pte_t *pte;
		phys_addr_t phys;
		ulong flags;

		if (!follow_physaddr(asi->mm->pgd, virt, &phys, &page_size, &flags))
			continue;

#define MAP_AT_LEVEL(base, BASE, level, LEVEL) {				\
			if (base##_leaf(*base)) {				\
				if (WARN_ON_ONCE(PHYS_PFN(phys & BASE##_MASK) !=\
						 base##_pfn(*base)))		\
					return -EBUSY;				\
				continue;					\
			}							\
										\
			level = asi_##level##_alloc(asi, base, virt, gfp_flags);\
			if (!level)						\
				return -ENOMEM;					\
										\
			if (page_size >= LEVEL##_SIZE &&			\
			    (level##_none(*level) || level##_leaf(*level)) &&	\
			    is_page_within_range(virt, LEVEL##_SIZE,		\
						 start, end)) {			\
				page_size = LEVEL##_SIZE;			\
				phys &= LEVEL##_MASK;				\
										\
				if (!level##_none(*level)) {			\
					if (WARN_ON_ONCE(level##_pfn(*level) != \
							 PHYS_PFN(phys))) {	\
						return -EBUSY;			\
					}					\
				} else {					\
					set_##level(level,			\
						    __##level(phys | flags));	\
				}						\
				continue;					\
			}							\
		}

		pgd = pgd_offset_pgd(asi->pgd, virt);

		MAP_AT_LEVEL(pgd, PGDIR, p4d, P4D);
		MAP_AT_LEVEL(p4d, P4D, pud, PUD);
		MAP_AT_LEVEL(pud, PUD, pmd, PMD);
		/*
		 * If a large page is going to be partially mapped
		 * in 4k pages, convert the PSE/PAT bits.
		 */
		if (page_size >= PMD_SIZE)
			flags = protval_large_2_4k(flags);
		MAP_AT_LEVEL(pmd, PMD, pte, PAGE);

		VM_BUG_ON(true); /* Should never reach here. */
	}

	return 0;
#undef MAP_AT_LEVEL
}

int __must_check asi_map(struct asi *asi, void *addr, unsigned long len)
{
	return asi_map_gfp(asi, addr, len, GFP_KERNEL);
}
EXPORT_SYMBOL_IF_KUNIT(asi_map);

/*
 * Unmap a kernel address range previously mapped into the ASI page tables.
 *
 * The area being unmapped must be a whole previously mapped region (or regions)
 * Unmapping a partial subset of a previously mapped region is not supported.
 * That will work, but may end up unmapping more than what was asked for, if
 * the mapping contained huge pages. A later patch will remove this limitation
 * by splitting the huge mapping in the ASI page table in such a case. For now,
 * vunmap_pgd_range() will just emit a warning if this situation is detected.
 *
 * This might sleep, and cannot be called with interrupts disabled.
 */
void asi_unmap(struct asi *asi, void *addr, size_t len)
{
	size_t start = (size_t)addr;
	size_t end = start + len;
	pgtbl_mod_mask mask = 0;

	if (!static_asi_enabled() || !len)
		return;

	/* ASI pagetables might be sensitive. */
	WARN_ON_ONCE(asi_in_critical_section());

	VM_BUG_ON(start & ~PAGE_MASK);
	VM_BUG_ON(len & ~PAGE_MASK);
	VM_BUG_ON(!fault_in_kernel_space(start)); /* Misnamed, ignore "fault_" */

	vunmap_pgd_range(asi->pgd, start, end, &mask);

	/* We don't support partial unmappings. */
	if (mask & PGTBL_P4D_MODIFIED) {
		VM_WARN_ON(!IS_ALIGNED((ulong)addr, P4D_SIZE));
		VM_WARN_ON(!IS_ALIGNED((ulong)len, P4D_SIZE));
	} else if (mask & PGTBL_PUD_MODIFIED) {
		VM_WARN_ON(!IS_ALIGNED((ulong)addr, PUD_SIZE));
		VM_WARN_ON(!IS_ALIGNED((ulong)len, PUD_SIZE));
	} else if (mask & PGTBL_PMD_MODIFIED) {
		VM_WARN_ON(!IS_ALIGNED((ulong)addr, PMD_SIZE));
		VM_WARN_ON(!IS_ALIGNED((ulong)len, PMD_SIZE));
	}

	asi_flush_tlb_range(asi, addr, len);
}
EXPORT_SYMBOL_IF_KUNIT(asi_unmap);

/*
 * This function is to copy the given unrestricted pgd entry for
 * userspace addresses to the corresponding restricted pgd entries.
 * It means that the unrestricted pgd entry must be updated before
 * this function is called.
 * We map entire userspace addresses to the restricted address spaces
 * by copying unrestricted pgd entries to the restricted page tables
 * so that we don't need to maintain consistency of lower level PTEs
 * between the unrestricted page table and the restricted page tables.
 */
void asi_clone_user_pgtbl(struct mm_struct *mm, pgd_t *pgdp)
{
	unsigned long pgd_idx;
	struct asi *asi;
	int i;

	if (!static_asi_enabled())
		return;

	/* We shouldn't need to take care non-userspace mapping. */
	if (!pgdp_maps_userspace(pgdp))
		return;

	/*
	 * The mm will be NULL for p{4,g}d_clear(). We need to get
	 * the owner mm for this pgd in this case. The pgd page has
	 * a valid pt_mm only when SHARED_KERNEL_PMD == 0.
	 */
	BUILD_BUG_ON(SHARED_KERNEL_PMD);
	if (!mm) {
		mm = pgd_page_get_mm(virt_to_page(pgdp));
		if (WARN_ON_ONCE(!mm))
			return;
	}

	/*
	 * Compute a PGD index of the given pgd entry. This will be the
	 * index of the ASI PGD entry to be updated.
	 */
	pgd_idx = pgdp - PTR_ALIGN_DOWN(pgdp, PAGE_SIZE);

	for (i = 0; i < ARRAY_SIZE(mm->asi); i++) {
		asi = mm->asi + i;

		if (!asi_pgd(asi) || !asi_maps_user_addr(asi->class_id))
			continue;

		/*
		 * We need to synchronize concurrent callers of
		 * __asi_clone_user_pgd() among themselves, as well as
		 * __asi_init_user_pgds(). The lock makes sure that reading
		 * the unrestricted pgd and updating the corresponding
		 * ASI pgd are not interleaved by concurrent calls.
		 * We cannot rely on mm->page_table_lock here because it
		 * is not always held when pgd/p4d_clear_bad() is called.
		 */
		spin_lock(&asi->pgd_lock);
		set_pgd(asi_pgd(asi) + pgd_idx, READ_ONCE(*pgdp));
		spin_unlock(&asi->pgd_lock);
	}
}
