// SPDX-License-Identifier: GPL-2.0
#include <linux/compiler_types.h>
#include <linux/export.h>
#include <linux/percpu.h>
#include <linux/spinlock.h>

#include <asm/asi.h>
#include <asm/cmdline.h>
#include <asm/cpufeature.h>
#include <asm/page.h>
#include <asm/pgalloc.h>
#include <asm/mmu_context.h>
#include <asm/traps.h>

#include "mm_internal.h"
#include "../../../mm/internal.h"

static struct asi_taint_policy *taint_policies[ASI_MAX_NUM_CLASSES];

const char *asi_class_names[] = {
#if IS_ENABLED(CONFIG_KVM)
	[ASI_CLASS_KVM] = "KVM",
#endif
};

DEFINE_PER_CPU_ALIGNED(struct asi *, curr_asi);
EXPORT_SYMBOL(curr_asi);

static __aligned(PAGE_SIZE) pgd_t asi_global_nonsensitive_pgd[PTRS_PER_PGD];

struct asi __asi_global_nonsensitive = {
	.pgd = asi_global_nonsensitive_pgd,
	.mm = &init_mm,
};

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
 *
 * On the other hand, they do not use the normal page allocation infrastructure,
 * that means that PTE pages do not have the PageTable type nor the PagePgtable
 * flag and we don't increment the meminfo stat (NR_PAGETABLE) as they do.
 */
static_assert(!IS_ENABLED(CONFIG_PARAVIRT));
#define DEFINE_ASI_PGTBL_ALLOC(base, level)				\
static level##_t * asi_##level##_alloc(struct asi *asi,			\
				       base##_t *base, ulong addr)	\
{									\
	if (unlikely(base##_none(*base))) {				\
		void *pgtbl = alloc_low_page();				\
		phys_addr_t pgtbl_pa;					\
									\
		if (!pgtbl)						\
			return NULL;					\
									\
		pgtbl_pa = __pa(pgtbl);					\
									\
		if (cmpxchg((ulong *)base, 0,				\
			    pgtbl_pa | _PAGE_TABLE) != 0) {		\
			if (!WARN_ON(!after_bootmem))			\
				__free_page(pgtbl);			\
			goto out;					\
		}							\
									\
		mm_inc_nr_##level##s(asi->mm);				\
	}								\
out:									\
	VM_BUG_ON(base##_leaf(*base));					\
	return level##_offset(base, addr);				\
}

DEFINE_ASI_PGTBL_ALLOC(pgd, p4d)
DEFINE_ASI_PGTBL_ALLOC(p4d, pud)
DEFINE_ASI_PGTBL_ALLOC(pud, pmd)
DEFINE_ASI_PGTBL_ALLOC(pmd, pte)

static int __init asi_global_init(void)
{
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

	return 0;
}
subsys_initcall(asi_global_init)

/*
 * Make sure all the pagetables in the global-nonsensitive pagetable
 * are allocated and equivalent to the unrestricted physmap. The difference is
 * they will be non-present.
 *
 * TODO: We also need to handle __set_pages_p and stuff like that.
 */
void asi_sync_physmap(unsigned long start, unsigned long size)
{
	/*
	 * TODO: this is a stupid way to implement this and is also probably
	 * insecure due to the transient mappings. Here we just use the plaid
	 * old asi_map logic to copy the mappings from the physmap then unmap
	 * them again.
	 *
	 * TODO: if the physmap isn't set up yet (which is probably the reason
	 * we're calling this function) we can't allocate ASI pagetables yet so
	 * we have to make the pagetables we're allocating here sensitive. This
	 * is also dumb. Wherever the pagetables come from that set up the
	 * nremal physmap during boot (i.e. memblock - see alloc_low_pages()) -
	 * we should get them from there, then retroactively mark them as
	 * nonsensitive if possible.
	 */
	int err = asi_map(ASI_GLOBAL_NONSENSITIVE, (void *)start, size);
	WARN_ON(err);
	asi_unmap(ASI_GLOBAL_NONSENSITIVE, (void *)start, size);
}

static void __asi_destroy(struct asi *asi)
{
	lockdep_assert_held(&asi->mm->asi_init_lock);

}

int asi_init(struct mm_struct *mm, enum asi_class_id class_id, struct asi **out_asi)
{
	struct asi *asi;
	int err = 0;
	uint i;

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
		GFP_KERNEL_ACCOUNT | __GFP_ZERO, PGD_ALLOCATION_ORDER);
	if (!asi->pgd) {
		err = -ENOMEM;
		goto exit_unlock;
	}

	asi->mm = mm;
	asi->class_id = class_id;

	for (i = KERNEL_PGD_BOUNDARY; i < PTRS_PER_PGD; i++)
		set_pgd(asi->pgd + i, asi_global_nonsensitive_pgd[i]);

exit_unlock:
	if (err)
		__asi_destroy(asi);
	else
		*out_asi = asi;

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
		free_pages((ulong)asi->pgd, PGD_ALLOCATION_ORDER);
		memset(asi, 0, sizeof(struct asi));
	}
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

static noinstr void __asi_enter(void)
{
	u64 asi_cr3;
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

	asi_cr3 = build_cr3_noinstr(target->pgd,
				    this_cpu_read(cpu_tlbstate.loaded_mm_asid),
				    tlbstate_lam_cr3_mask());
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
	barrier();
	asi_set_target(current, NULL);
}
EXPORT_SYMBOL_GPL(asi_relax);

noinstr void asi_exit(void)
{
	u64 unrestricted_cr3;
	struct asi *asi;

	preempt_disable_notrace();

	VM_BUG_ON(this_cpu_read(cpu_tlbstate.loaded_mm) ==
		  LOADED_MM_SWITCHING);

	asi = this_cpu_read(curr_asi);
	if (asi) {
		maybe_flush_control(NULL);

		unrestricted_cr3 =
			build_cr3_noinstr(this_cpu_read(cpu_tlbstate.loaded_mm)->pgd,
					  this_cpu_read(cpu_tlbstate.loaded_mm_asid),
					  tlbstate_lam_cr3_mask());

		/* Tainting first makes reentrancy easier to reason about.  */
		this_cpu_or(asi_taints, ASI_TAINT_KERNEL_DATA);
		write_cr3(unrestricted_cr3);
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

static bool follow_physaddr(
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

/*
 * Map the given range into the ASI page tables. The source of the mapping is
 * the regular unrestricted page tables. Can be used to map any kernel memory.
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
int __must_check asi_map(struct asi *asi, void *addr, unsigned long len)
{
	unsigned long virt;
	unsigned long start = (size_t)addr;
	unsigned long end = start + len;
	unsigned long page_size;

	VM_BUG_ON(!IS_ALIGNED(start, PAGE_SIZE));
	VM_BUG_ON(!IS_ALIGNED(len, PAGE_SIZE));
	/* RFC: fault_in_kernel_space should be renamed. */
	VM_BUG_ON(!fault_in_kernel_space(start));

	/* TODO: This is currently hard-coded to allocate via alloc_low_page. */

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
			level = asi_##level##_alloc(asi, base, virt);		\
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
					printk("mapped 0x%lx "__stringify(level)" at %p\n", virt, level); \
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
 * This cannot be called with interrupts disabled.
 */
void asi_unmap(struct asi *asi, void *addr, size_t len)
{
	size_t start = (size_t)addr;
	size_t end = start + len;
	pgtbl_mod_mask mask = 0;

	/*
	 * Not entirely true, e.g. strictly speaking calling this after
	 * spin_lock() would not exactly be incorrect. But, it feels like
	 * that would be a bad idea.
	 */
	might_sleep();

	if (!len)
		return;

	printk("asi_unmap %p + 0x%zx\n", addr, len);

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

	flush_tlb_kernel_range((ulong)addr, (ulong)addr + len);
}
