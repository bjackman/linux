/* SPDX-License-Identifier: GPL-2.0 */
#include "asm/pgtable_64_types.h"
#include <linux/ephmap.h>
#include <linux/mm.h>
#include <linux/pagemap.h>

#include <asm/io.h>
#include <asm/pgtable.h>
#include <asm/tlb.h>

/*
 * TODO: This is x86-specific. At least because we use get_locked_pte() for
 * kernel addresses, maybe for other reasons too.
 */

/*
 * Each CPU gets a chunk of the ephemeral mapping the size of the maximum folio
 * size.
 */
#define EPHMAP_CPU_REGION_SIZE (PAGE_SIZE << MAX_PAGECACHE_ORDER)
#define EPHMAP_SIZE (EPHMAP_CPU_REGION_SIZE * NR_CPUS)
#define EPHMAP_END_ADDR (EPHEMERAL_FILEMAP_BASE_ADDR + (NR_CPUS * EPHMAP_CPU_REGION_SIZE))

static inline void unmap_page_range_noflush(struct mm_struct *mm,
					    unsigned long addr,
					    unsigned long end)
{
	for (; addr < end; addr += PAGE_SIZE) {
		spinlock_t *ptl;
		pte_t *ptep;

		ptep = get_locked_pte(mm, addr, &ptl);
		if (!WARN_ON_ONCE(!ptep)) {
			pte_clear(mm, addr, ptep);
			pte_unmap_unlock(ptep, ptl);
		}
	};
}

/* Return a region allocated by ephmap_get(). */
void ephmap_put(void *vaddr, unsigned long size)
{
	unsigned long addr = (unsigned long)vaddr;
	unsigned long start = addr;
	unsigned long end = addr + size;

	size = PAGE_ALIGN(size);

	unmap_page_range_noflush(current->mm, addr, end);

	/*
	 * TODO: Could reuse the mapping if it's the same folio as last time. We
	 * could also allocate from a larger buffer and only TLB flush when it's
	 * full (or pages get evited etc), batching them up.
	 * Actually, some sort of complexity like this is required for security,
	 * because we need to ensure other CPUs in the mm flush their TLBs
	 * before they lose logical access to the page.
	 */
	/* TODO: create a proper API for this type of flush. */
	/*
	 * Need to flush restricted and unrestricted address space. Do not need
	 * to flush user address space if that exists, and do not need to
	 * invalidate any others.
	 *
	 * In this simplistic code, ASI address transitions never set
	 * CR3.noflush so we don't need to account for the "other" address
	 * space, just ensure we flush whatever we're currently in.
	 */
	if (size >> PAGE_SHIFT < 33) {
		for (unsigned long offset = 0; offset < size; offset += PAGE_SIZE)
			asm volatile("invlpg (%0)" ::"r" (start + offset) : "memory");
	} else {
		/*
		 * TODO: Um, I think there has to be a way to avoid flushing
		 * other PCIDs here. Just need to flush "both" PCIDs for the
		 * current ASI domain (bearing in mind the current lack of
		 * CR3.noflush). But anyway this is throwaway code.
		 */
		invpcid_flush_all();
	}

	this_cpu_write(current->mm->mml_cpu->in_use, false);
}

static inline int map_page_range(struct mm_struct *mm,
		    unsigned long addr, unsigned long end,
		    phys_addr_t phys_addr, pgprot_t prot)
{
	for (; addr < end; addr += PAGE_SIZE) {
		pgprot_t pte_prot;
		pte_t pte, *ptep;
		spinlock_t *ptl;

		/*
		 * Cribbed map_ldt_struct(). Treat the pagetables like userspace
		 * ones.
		 *
		 * There is lock contention here when first populating the
		 * pagetable tree but the leaf pagetables have a split lock. I
		 * guess that means there is no contention for the PTEs but we
		 * are still taking a spinlock. If that's an issue we might need
		 * to be more aggressive and take advantage of the fact we know
		 * nobody is racing on overlapping ranges (I think
		 * vmap_page_range() etc does this but need to read more
		 * carefully to be sure).
		 *
		 * TODO: Would be nice to use huge pages for this where
		 * possible.
		 *
		 * TODO: This is not the right way to do this, we need to do it
		 * in a way that is safe from the page allocator. This kinda
		 * works because of the pgtbl prealloc so it's good enough for
		 * experimentation.
		 */
		ptep = get_locked_pte(mm, addr, &ptl);
		if (!ptep)
			return -ENOMEM;
		pte_prot = __pgprot(__PAGE_KERNEL_RO & ~_PAGE_GLOBAL);
		pgprot_val(pte_prot) &= __supported_pte_mask;
		pte = pfn_pte(phys_addr >> PAGE_SHIFT, pte_prot);
		set_pte_at(mm, addr, ptep, pte);
		pte_unmap_unlock(ptep, ptl);

		phys_addr += PAGE_SIZE;
	}

	return 0;
}

/*
 * Allocate a region of virtual memory, and map the page into it. This tries
 * very hard to be fast and doesn't try very hard at all to actually succeed,
 * expect failures.
 *
 * The returned region is physically local to the current mm. It is _logically_
 * local to the current CPU (so you must disable migration) but this is not
 * enforced by hardware so it can't be exploited to mitigate CPU vulns.
 */
void *ephmap_get(struct page *page, unsigned long size)
{
	unsigned long addr;
	void *ptr;

	lockdep_assert(is_migration_disabled(current));

	if (this_cpu_xchg(current->mm->mml_cpu->in_use, true)) {
		/* Another thread in this mm is using it */
		return NULL;
	}

	/* TODO: Make it a BUILD_BUG_ON (annoying because PGD size is variable). */
	BUG_ON(EPHMAP_END_ADDR > MM_LOCAL_END);

	addr = EPHEMERAL_FILEMAP_BASE_ADDR + (smp_processor_id() * EPHMAP_CPU_REGION_SIZE);
	size = PAGE_ALIGN(size);
	ptr = (void *)addr;

	/*
	 * This contends for mm->page_table_lock during allocation but
	 * after that it just relies on the caller not to race with overlapping
	 * ranges.
	 *
	 * We don't need to asi_map() this region as it's already cloned into
	 * the restricted address space.
	 */
	if (map_page_range(current->mm, addr, addr + size,
			   page_to_phys(page), PAGE_KERNEL)) {
		ephmap_put(ptr, size);
		return NULL;
	}

	return ptr;

}

/* Set up ephmap for a new mm. */
void ephmap_setup(struct mm_struct *mm)
{
	/*
	 * So we can use this from the page allocator, preallocate pagetables.
	 * Easiest way to do this is just map some random address (NC to prevent
	 * CPU vuln leaks) and then unmap it again, leaving the tables behind.
	 */
	map_page_range(mm, EPHEMERAL_FILEMAP_BASE_ADDR,
		       EPHMAP_END_ADDR, __START_KERNEL_map, PAGE_KERNEL_NOCACHE);
	unmap_page_range_noflush(mm, EPHEMERAL_FILEMAP_BASE_ADDR,
				 EPHMAP_END_ADDR);
}

/* Clean up ephmap stuff on mm teardown. */
void ephmap_cleanup(struct mm_struct *mm)
{
	struct mmu_gather tlb;
	unsigned long start = EPHEMERAL_FILEMAP_BASE_ADDR;
	/*
	 * TODO: Aligning the region boundaries is a hack to make
	 * free_pgd_range() free the pagetables. Actually this pagetable
	 * management just needs to be designed properly! Yikes.
	 */
	unsigned long end = ALIGN(EPHMAP_END_ADDR, PUD_SIZE);

	/* Cribbed from free_ldt_pagetables() */
	tlb_gather_mmu_fullmm(&tlb, mm);
	free_pgd_range(&tlb, start, end, start, end);
	tlb_finish_mmu(&tlb);
}