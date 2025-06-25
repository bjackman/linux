// SPDX-License-Identifier: GPL-2.0
#include <linux/asi.h>
#include <linux/init.h>
#include <linux/memblock.h>
#include <linux/string.h>

#include <asm/cmdline.h>
#include <asm/cpufeature.h>
#include <asm/pgalloc.h>

#include "mm_internal.h"

static struct asi_taint_policy *taint_policies[ASI_MAX_NUM_CLASSES];

const char *asi_class_names[] = {
#if IS_ENABLED(CONFIG_KVM)
	[ASI_CLASS_KVM] = "KVM",
#endif
};

DEFINE_PER_CPU_ALIGNED(struct asi *, curr_asi);
EXPORT_SYMBOL(curr_asi);

static inline bool asi_class_id_valid(enum asi_class_id class_id)
{
	return class_id >= 0 && class_id < ASI_MAX_NUM_CLASSES;
}

static inline bool asi_class_initialized(enum asi_class_id class_id)
{
	if (WARN_ON(!asi_class_id_valid(class_id)))
		return false;

	return !!(taint_policies[class_id]);
}

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

void asi_uninit_class(enum asi_class_id class_id)
{
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

static void __asi_destroy(struct asi *asi)
{
	lockdep_assert_held(&asi->mm->asi_init_lock);

}

int asi_init_domain(struct mm_struct *mm, enum asi_class_id class_id, struct asi **out_asi)
{
	struct asi *asi;
	int err = 0;

	*out_asi = NULL;

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
		GFP_KERNEL_ACCOUNT | __GFP_ZERO, pgd_allocation_order());
	if (!asi->pgd) {
		err = -ENOMEM;
		goto exit_unlock;
	}

	asi->mm = mm;
	asi->class_id = class_id;

exit_unlock:
	if (err)
		__asi_destroy(asi);
	else
		*out_asi = asi;

	for (int i = KERNEL_PGD_BOUNDARY; i < PTRS_PER_PGD; i++)
		set_pgd(asi->pgd + i, asi_nonsensitive_pgd[i]);

	mutex_unlock(&mm->asi_init_lock);

	return err;
}
EXPORT_SYMBOL_GPL(asi_init);

void asi_destroy(struct asi *asi)
{
	struct mm_struct *mm;

	if (!asi)
		return;

	if (WARN_ON(!asi_class_initialized(asi->class_id)))
		return;

	mm = asi->mm;
	/*
	 * We would need this mutex even if the refcount was atomic as we need
	 * to block concurrent asi_init calls.
	 */
	mutex_lock(&mm->asi_init_lock);
	WARN_ON_ONCE(asi->ref_count <= 0);
	if (--(asi->ref_count) == 0) {
		free_pages((ulong)asi->pgd, pgd_allocation_order());
		memset(asi, 0, sizeof(struct asi));
	}
	mutex_unlock(&mm->asi_init_lock);
}
EXPORT_SYMBOL_GPL(asi_destroy);

DEFINE_PER_CPU_ALIGNED(asi_taints_t, asi_taints);

/*
 * Flush out any potentially malicious speculative control flow (e.g. branch
 * predictor) state if necessary when we are entering a new domain (which may be
 * NULL when we are exiting to the nonsensitive address space).
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
		 * Going to the sensitive address space, this has an implicit
		 * policy of flushing all taints.
		 */
		taints &= ASI_TAINTS_CONTROL_MASK;
	}

	if (!taints)
		return;

	/*
	 * This is where we'll do the actual dirty work of clearing uarch state.
	 * For now we just pretend, clear the taints.
	 */
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

	/*
	 * This is where we'll do the actual dirty work of clearing uarch state.
	 * For now we just pretend, clear the taints.
	 */
	this_cpu_and(asi_taints, ~ASI_TAINTS_DATA_MASK);
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
	write_cr3(asi_cr3);

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

noinstr void asi_enter(struct asi *asi)
{
	if (!cpu_feature_enabled(X86_FEATURE_ASI))
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

noinstr void asi_relax(void)
{
	if (cpu_feature_enabled(X86_FEATURE_ASI)) {
		VM_WARN_ON_ONCE(asi_intr_nest_depth());
		barrier();
		asi_set_target(current, NULL);
	}
}
EXPORT_SYMBOL_GPL(asi_relax);

noinstr void asi_exit(void)
{
	u64 sensitive_cr3;
	struct asi *asi;

	preempt_disable_notrace();

	VM_BUG_ON(this_cpu_read(cpu_tlbstate.loaded_mm) ==
		  LOADED_MM_SWITCHING);

	asi = this_cpu_read(curr_asi);
	if (asi) {
		WARN_ON_ONCE(asi_in_critical_section());

		maybe_flush_control(NULL);

		sensitive_cr3 =
			build_cr3_noinstr(this_cpu_read(cpu_tlbstate.loaded_mm)->pgd,
					 this_cpu_read(cpu_tlbstate.loaded_mm_asid),
					 tlbstate_lam_cr3_mask());

		/* Tainting first makes reentrancy easier to reason about.  */
		this_cpu_or(asi_taints, ASI_TAINT_KERNEL_DATA);
		write_cr3(sensitive_cr3);
		/*
		 * Must not update curr_asi until after CR3 write, otherwise a
		 * re-entrant call might not enter this branch. (This means we
		 * might do unnecessary CR3 writes).
		 */
		this_cpu_write(curr_asi, NULL);
	}

	preempt_enable_notrace();
}
EXPORT_SYMBOL_GPL(asi_exit);

void asi_init_mm_state(struct mm_struct *mm)
{
	memset(mm->asi, 0, sizeof(mm->asi));
	mutex_init(&mm->asi_init_lock);
}

void asi_handle_switch_mm(void)
{
	/*
	 * We can't handle context switching in the nonsensitive address space yet
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

/*
 * This is a bit like init_mm.pgd, it holds mappings shared among all ASI
 * domains.
 */
pgd_t *asi_nonsensitive_pgd;

void __init asi_check_boottime_disable(void)
{
	bool enabled = false;
	char arg[4];
	int ret;

	ret = cmdline_find_option(boot_command_line, "asi", arg, sizeof(arg));
	if (ret == 3 && !strncmp(arg, "off", 3)) {
		enabled = false;
		pr_info("ASI explicitly disabled by kernel cmdline.\n");
	} else if (ret == 2 && !strncmp(arg, "on", 2)) {
		enabled = true;
		pr_info("ASI enabled.\n");
	} else if (ret) {
		pr_err("Unknown asi= flag '%s', try 'off' or 'on'\n", arg);
	}

	if (enabled)
		setup_force_cpu_cap(X86_FEATURE_ASI);
}

void __init asi_init(void)
{
	if (!cpu_feature_enabled(X86_FEATURE_ASI))
		return;

	asi_nonsensitive_pgd = alloc_low_page();
	if (WARN_ON(!asi_nonsensitive_pgd))
		setup_clear_cpu_cap(X86_FEATURE_ASI);
}

/* Helper for asi_clone_range() */
static int asi_clone_pud(p4d_t *dst_p4d, p4d_t *src_p4d,
			 unsigned long addr, unsigned long end)
{
	pud_t *dst = pud_alloc(&init_mm, dst_p4d, addr);
	pud_t *src = pud_offset(src_p4d, addr);
	unsigned long next;

	if (WARN_ON_ONCE(!dst))
		return -EINVAL;

	do {
		next = pud_addr_end(addr, end);
		if (IS_ALIGNED(addr, PUD_SIZE) && (next - addr == PUD_SIZE)) {
			if (pud_val(*dst)) {
				WARN_ONCE(1, "addr: %lx, PUD: %lx, ASI PUD: %lx",
					  addr, pud_val(*dst), pud_val(*src));
				if (pud_val(*dst) != pud_val(*src))
					return -EEXIST;
			} else {
				set_pud(dst, *src);
			}
		} else {
			WARN_ONCE(1, "Cloning PMDs is not supported");
			return -EOPNOTSUPP;
		}
	} while (dst++, src++, addr = next, addr != end);

	return 0;
}

/* Helper for asi_clone_range() */
static int asi_clone_p4d(pgd_t *dst_pgd, pgd_t *src_pgd,
			 unsigned long addr, unsigned long end)
{
	p4d_t *dst = p4d_alloc(&init_mm, dst_pgd, addr);
	p4d_t *src = p4d_offset(src_pgd, addr);
	unsigned long next;
	int err;

	if (WARN_ON_ONCE(!dst))
		return -EINVAL;

	BUILD_BUG_ON(p4d_leaf(*dst));
	do {
		next = p4d_addr_end(addr, end);
		if ((p4d_none(*src) || !p4d_present(*src)))
			continue;

		if (IS_ALIGNED(addr, P4D_SIZE) && (next - addr == P4D_SIZE)) {
			if (p4d_val(*dst)) {
				WARN_ONCE(1, "addr: %lx, P4D: %lx, ASI P4D: %lx",
					  addr, p4d_val(*dst), p4d_val(*src));
				if (p4d_val(*dst) != p4d_val(*src))
					return -EEXIST;
			} else {
				set_p4d(dst, *src);
			}
		} else {
			err = asi_clone_pud(dst, src, addr, next);
			if (err)
				return err;
		}
	} while (dst++, src++, addr = next, addr != end);

	return 0;
}

/*
 * Share the mappings of a range of addresses with the sensitive page tables
 * by cloning the page table entries at the appropriate level (PGD/P4D/PUD)
 * based on the address alignment. This shares the page tables at the lower
 * levels (i.e. P4D/PUD/PMD). Cloning mappings at a lower level than PUD is not
 * supported (hence @addr and @len must both be aligned to PUD_SIZE).
 *
 * Assumes that the cloned mappings (down to the PUD entries) will not change.
 * Any non-present or none page table entries will be ignored.
 *
 * asi_clone_range() and its helpers are not expected to fail, so always WARN
 * before returning an error.
 */
static int __maybe_unused asi_clone_range(unsigned long addr, unsigned long len)
{
	pgd_t *dst = pgd_offset_pgd(asi_nonsensitive_pgd, addr);
	pgd_t *src = pgd_offset_k(addr);
	unsigned long end = addr + len;
	unsigned long next;
	int err;

	if (WARN_ONCE(addr >= end, "addr: %lx, len: %lx, end: %lx\n",
		      addr, len, end))
		return -EINVAL;

	BUILD_BUG_ON(pgd_leaf(*dst));
	do {
		next = pgd_addr_end(addr, end);
		if ((pgd_none(*src) || !pgd_present(*src)))
			continue;

		if (IS_ALIGNED(addr, PGDIR_SIZE) && (next - addr == PGDIR_SIZE)) {
			if (pgd_val(*dst)) {
				WARN_ONCE(1, "addr: %lx, PGD: %lx, ASI PGD: %lx",
					  addr, pgd_val(*dst), pgd_val(*src));
				if (pgd_val(*dst) != pgd_val(*src))
					return -EEXIST;
			} else {
				set_pgd(dst, *src);
			}
		} else {
			err = asi_clone_p4d(dst, src, addr, next);
			if (err)
				return err;
		}
	} while (dst++, src++, addr = next, addr != end);

	return 0;
}