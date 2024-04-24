/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/asi.h>
#include <linux/compiler_types.h>
#include <linux/export.h>
#include <linux/percpu.h>
#include <linux/spinlock.h>
#include <linux/vmalloc.h>
#include <linux/syscore_ops.h>

#include <asm/pgtable.h>
#include <asm/traps.h>
#include <asm/cmdline.h>
#include <asm/cpufeature.h>
#include <asm/page.h>
#include <asm/pgalloc.h>
#include <asm/mmu_context.h>

#include "mm_internal.h"

static struct asi_taint_policy *taint_policies[ASI_MAX_NUM_CLASSES];

const char *asi_class_names[] = {
#if IS_ENABLED(CONFIG_KVM)
	[ASI_CLASS_KVM] = "KVM",
#endif
};

DEFINE_PER_CPU_ALIGNED(struct asi *, curr_asi);
EXPORT_SYMBOL(curr_asi);

__aligned(PAGE_SIZE) pgd_t asi_global_nonsensitive_pgd[PTRS_PER_PGD];

struct asi __asi_global_nonsensitive = {
	.pgd = asi_global_nonsensitive_pgd,
};

static inline bool asi_class_id_valid(enum asi_class_id class_id)
{
	return class_id >= 0 && class_id < ASI_MAX_NUM_CLASSES;
}

static inline bool asi_class_initialized(enum asi_class_id class_id)
{
	if (!boot_cpu_has(X86_FEATURE_ASI))
		return 0;

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
		pr_info("Ignoring asi=on param while ASI implementation is incomplete.\n");
	} else {
		pr_info("ASI %s by default.\n",
			enabled ? "enabled" : "disabled");
	}

	if (enabled)
		pr_info("ASI enablement ignored due to incomplete implementation.\n");
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
	asi_exit();
	return 0;
}

static struct syscore_ops asi_syscore_ops = {
	.suspend = asi_suspend,
};
#endif /* CONFIG_PM_SLEEP */

static inline void __asi_destroy(struct asi *asi)
{
	WARN_ON_ONCE(asi->ref_count <= 0);
	if (--(asi->ref_count) == 0) {
		free_pages((ulong)asi->pgd, pgd_allocation_order());
		memset(asi, 0, sizeof(struct asi));
	}
}

int asi_init(struct mm_struct *mm, enum asi_class_id class_id, struct asi **out_asi)
{
	struct asi *asi;
	int err = 0;

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
		set_pgd(asi->pgd + i, asi_global_nonsensitive_pgd[i]);

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

/* Immediately exit the restricted address space if in it. */
noinstr void asi_exit(void)
{
	u64 unrestricted_cr3;
	struct asi *asi;

	if (!cpu_feature_enabled(X86_FEATURE_ASI))
		return;

	preempt_disable_notrace();

	VM_BUG_ON(this_cpu_read(cpu_tlbstate.loaded_mm) ==
		  LOADED_MM_SWITCHING);

	asi = this_cpu_read(curr_asi);
	if (asi) {
		WARN_ON_ONCE(asi_in_critical_section());

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
}
EXPORT_SYMBOL_GPL(asi_exit);

void asi_init_mm_state(struct mm_struct *mm)
{
	if (!boot_cpu_has(X86_FEATURE_ASI))
		return;

	memset(mm->asi, 0, sizeof(mm->asi));
	mutex_init(&mm->asi_init_lock);
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

/*
 * Map the given pages into the ASI nonsensitive physmap. The source of the
 * mapping is the regular unrestricted page tables. Only supports mapping at
 * pageblock granularity. Does no synchronization.
 */
void asi_map(struct page *page, int numpages)
{
	unsigned long virt;
	unsigned long start = (size_t)(page_to_virt(page));
	unsigned long end = start + PAGE_SIZE * numpages;
	unsigned long page_size;

	VM_BUG_ON(!IS_ALIGNED(page_to_pfn(page), pageblock_nr_pages));
	VM_BUG_ON(!IS_ALIGNED(numpages, pageblock_nr_pages));

	for (virt = start; virt < end; virt = ALIGN(virt + 1, page_size)) {
		pte_t *pte, *pte_asi;
		int level, level_asi;
		pgd_t *pgd = pgd_offset_pgd(asi_global_nonsensitive_pgd, virt);

		pte_asi = lookup_pgtable_in_pgd(pgd, virt, &level_asi);
		page_size = page_level_size(level_asi);

		pte = lookup_address(virt, &level);
		if (!pte || pte_none(*pte))
			continue;

		/*
		 * Physmap should already be setup by PAT code, with no pages
		 * smaller than 2M. This function should only be called at
		 * pageblock granularity. Thus it should never be required to
		 * break up pages here.
		 */
		if (WARN_ON_ONCE(!pte_asi) ||
		    WARN_ON_ONCE(ALIGN_DOWN(virt, page_size) < virt) ||
				 ALIGN(virt, page_size) > end)
			continue;

		/*
		 * If the unrestricted physmap is finer-grained than the
		 * restricted one this is another reason why we'd need to split
		 * up pages.
		 */
		if (WARN_ONCE(level < level_asi,
		    "ASI mapping at level %d, unrestricted at %d\n",
		    level_asi, level))
			continue;

		if (level == level_asi) {
			set_pte(pte_asi, *pte);
		} else {
			pud_t *pud = (pud_t *)pte;
			pgprot_t prot = pud_pgprot(*pud);
			pmd_t pmd;

			/*
			 * TODO: This needs a more careful and flexible
			 * implementation. It would be nice to do this without
			 * needing a fully generic pagetable manipulation API,
			 * maybe if I took the time to actually understand the
			 * structure of the different pagetable levels I would
			 * be able to see an obvious way to do it.
			 * It also needs to be less duplicated wrt set_memory.c.
			 */
			WARN_ONCE(level_asi != PG_LEVEL_2M, "level %d", level_asi);
			WARN_ONCE(level != PG_LEVEL_1G, "level %d\n", level);

			/*
			 * Clear the PSE flags if the PRESENT flag is not set
			 * otherwise pmd_present() will return true even on a
			 * non present pmd.
			 */
			if (!(pgprot_val(prot) & _PAGE_PRESENT))
				pgprot_val(prot) &= ~_PAGE_PSE;

			/*
			 * TODO: Do we need to drop/move bits to change levels
			 * here? See protval_large_2_4k
			 */
			pmd = pfn_pmd(page_to_pfn(virt_to_page(virt)), prot);
			set_pmd((pmd_t *)pte_asi, pmd);
		}
	}
}

/*
 * Unmap pages previously mapped via asi_map().
 *
 * Interrupts must be enabled as this does a TLB shootdown.
 */
void asi_unmap(struct page *page, int numpages)
{
	size_t start = (size_t)page_to_virt(page);
	size_t end = start + (PAGE_SIZE * numpages);
	pgtbl_mod_mask mask = 0;

	VM_BUG_ON(!IS_ALIGNED(page_to_pfn(page), pageblock_nr_pages));
	VM_BUG_ON(!IS_ALIGNED(numpages, pageblock_nr_pages));

	vunmap_pgd_range(asi_pgd(ASI_GLOBAL_NONSENSITIVE), start, end, &mask);

	flush_tlb_kernel_range(start, end - 1);
}

/* Helper for asi_clone_range() */
static int asi_clone_pud(p4d_t *dst_p4d, p4d_t *src_p4d,
			 unsigned long addr, unsigned long end)
{
	pud_t *dst = pud_alloc(&init_mm, dst_p4d, addr);
	pud_t *src = pud_offset(src_p4d, addr);
	unsigned long last;

	if (WARN_ON_ONCE(!dst))
		return -EINVAL;

	do {
		last = pud_addr_last(addr, end);
		if (IS_ALIGNED(addr, PUD_SIZE) && (last - addr == PUD_SIZE - 1)) {
			if (pud_val(*dst)) {
				WARN_ONCE(1, "addr: %lx, PUD: %lx, ASI PUD: %lx",
					  addr, pud_val(*dst), pud_val(*src));
				if (pud_val(*dst) != pud_val(*src))
					return -EEXIST;
			} else {
				set_pud(dst, *src);
			}
		} else {
			WARN_ONCE(1, "Cloning PMDs is not supported (tried to clone %#lx)", addr);
			return -EOPNOTSUPP;
		}
	} while (dst++, src++, addr = last + 1, last != end);

	return 0;
}

/* Helper for asi_clone_range() */
static int asi_clone_p4d(pgd_t *dst_pgd, pgd_t *src_pgd,
			 unsigned long addr, unsigned long end)
{
	p4d_t *dst = p4d_alloc(&init_mm, dst_pgd, addr);
	p4d_t *src = p4d_offset(src_pgd, addr);
	unsigned long last;
	int err;

	if (WARN_ON_ONCE(!dst))
		return -EINVAL;

	BUILD_BUG_ON(p4d_leaf(*dst));
	do {
		if ((p4d_none(*src) || !p4d_present(*src)))
			continue;

		last = p4d_addr_last(addr, end);
		if (IS_ALIGNED(addr, P4D_SIZE) && (last - addr == P4D_SIZE - 1)) {
			if (p4d_val(*dst)) {
				WARN_ONCE(1, "addr: %lx, P4D: %lx, ASI P4D: %lx",
					  addr, p4d_val(*dst), p4d_val(*src));
				if (p4d_val(*dst) != p4d_val(*src))
					return -EEXIST;
			} else {
				set_p4d(dst, *src);
			}
		} else {
			err = asi_clone_pud(dst, src, addr, last);
			if (err)
				return err;
		}
	} while (dst++, src++, addr = last + 1, last != end);

	return 0;
}

/*
 * Share the mappings of a range of addresses with the unrestricted page tables
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
static int __maybe_unused asi_clone_range(unsigned long addr, unsigned long end)
{
	pgd_t *dst = pgd_offset_pgd(asi_global_nonsensitive_pgd, addr);
	pgd_t *src = pgd_offset_k(addr);
	unsigned long last;
	int err;

	if (WARN_ONCE(addr >= end, "addr: %lx, end: %lx\n", addr, end))
		return -EINVAL;

	BUILD_BUG_ON(pgd_leaf(*dst));
	do {
		if ((pgd_none(*src) || !pgd_present(*src)))
			continue;

		last = pgd_addr_last(addr, end);
		if (IS_ALIGNED(addr, PGDIR_SIZE) && (last - addr == PGDIR_SIZE - 1)) {
			if (pgd_val(*dst)) {
				WARN_ONCE(1, "addr: %lx, PGD: %lx, ASI PGD: %lx",
					  addr, pgd_val(*dst), pgd_val(*src));
				if (pgd_val(*dst) != pgd_val(*src))
					return -EEXIST;
			} else {
				set_pgd(dst, *src);
			}
		} else {
			err = asi_clone_p4d(dst, src, addr, last);
			if (err)
				return err;
		}
	} while (dst++, src++, addr = last + 1, last != end);

	return 0;
}

static int __init asi_global_init(void)
{
	if (!boot_cpu_has(X86_FEATURE_ASI))
		return 0;

	/*
	 * The direct map and vmalloc range mappings are shared by all ASI
	 * domains through ASI_GLOBAL_NONSENSITIVE, but not with the
	 * unrestricted address space. All ASI domains copy PGD entries from
	 * ASI_GLOBAL_NONSENSITIVE page tables during initialization (hence
	 * sharing lower-level page tables). To avoid needing to synchronize
	 * these PGD entries dynamically, preallocate the relevant sub-PGD page
	 * table pages so that all the needed PGD entries are created before any
	 * ASI domains copy them.
	 */
	preallocate_sub_pgd_pages(asi_global_nonsensitive_pgd,
				  PAGE_OFFSET,
				  PAGE_OFFSET + PFN_PHYS(max_pfn) - 1,
				  "ASI Global Non-sensitive direct map");
	preallocate_sub_pgd_pages(asi_global_nonsensitive_pgd,
				  VMALLOC_START, VMALLOC_END,
				  "ASI Global Non-sensitive vmalloc");

	/*
	 * Share the whole kernel address space, except the direct map, directly
	 * with the restricted address space. This is obviously incomplete; the
	 * direct map is not the only place where user data ends up. This "share
	 * the page tables" approach will always make sense for certain regions
	 * such as the kernel text and vmemmap, but e.g. the vmalloc area should
	 * certainly be managed as separate pagetables. However right now there
	 * is no infrastructure for actually taking advantage of those tables
	 * (they would need to be an exact copy of the unrestricted ones) so we
	 * just clone the whole thing.
	 *
	 * Note this is making assumptions about the address space layout :/
	 */
	asi_clone_range(LDT_BASE_ADDR, LDT_END_ADDR - 1);
	asi_clone_range(VMALLOC_START, ULONG_MAX);

#ifdef CONFIG_PM_SLEEP
	register_syscore_ops(&asi_syscore_ops);
#endif

	return 0;
}
subsys_initcall(asi_global_init)