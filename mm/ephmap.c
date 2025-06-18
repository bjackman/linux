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

/*
 * Page table functions that are a weird bastardization of the ones from
 * vmalloc.c with modification tracking, max_page_shift, and hugepage support
 * ripped out, and some amount of accounting squashed back in, in order to help
 * me debug a memory leak I had. This does some synchronization when allocating
 * but not while mapping. This means it allocates locks and stuff that I don't
 * actually take.
 */

static int map_pte_range(struct mm_struct *mm, pmd_t *pmd, unsigned long addr, unsigned long end,
			 phys_addr_t phys_addr, pgprot_t prot)
{
	pte_t *pte, *pte_table;
	u64 pfn;
	struct page *page;
	unsigned long size = PAGE_SIZE;

	pfn = phys_addr >> PAGE_SHIFT;
	pte = pte_alloc_map(mm, pmd, addr);
	pte_table = pte;
	if (WARN_ON_ONCE(!pte))
		return -ENOMEM;
	/*
	 * Hack: Only reason we set prot=0 is when preallocating. Assume we
	 * just allocate the table in which case it's already zero hence we have
	 * nothing to do.
	 */
	if (pgprot_val(prot)) {
		do {
			if (unlikely(!pte_none(ptep_get(pte)))) {
				if (pfn_valid(pfn)) {
					page = pfn_to_page(pfn);
					dump_page(page, "remapping already mapped page");
				}
				BUG();
			}

			set_pte_at(mm, addr, pte, pfn_pte(pfn, prot));
			pfn++;
		} while (pte += PFN_DOWN(size), addr += size, addr != end);
	}
	pte_unmap(pte_table);
	return 0;
}

static int map_pmd_range(struct mm_struct *mm, pud_t *pud, unsigned long addr, unsigned long end,
			  phys_addr_t phys_addr, pgprot_t prot)
{
	pmd_t *pmd;
	unsigned long next;

	pmd = pmd_alloc(mm, pud, addr);
	if (WARN_ON_ONCE(!pmd))
		return -ENOMEM;
	do {
		next = pmd_addr_end(addr, end);

		if (map_pte_range(mm, pmd, addr, next, phys_addr, prot))
			return -ENOMEM;
	} while (pmd++, phys_addr += (next - addr), addr = next, addr != end);
	return 0;
}

static int map_pud_range(struct mm_struct *mm, p4d_t *p4d, unsigned long addr, unsigned long end,
			  phys_addr_t phys_addr, pgprot_t prot)
{
	pud_t *pud;
	unsigned long next;

	pud = pud_alloc(mm, p4d, addr);
	if (WARN_ON_ONCE(!pud))
		return -ENOMEM;
	do {
		next = pud_addr_end(addr, end);

		if (map_pmd_range(mm, pud, addr, next, phys_addr, prot))
			return -ENOMEM;
	} while (pud++, phys_addr += (next - addr), addr = next, addr != end);
	return 0;
}

static int map_p4d_range(struct mm_struct *mm, unsigned long addr, unsigned long end,
			phys_addr_t phys_addr, pgprot_t prot)
{
	p4d_t *p4d;
	unsigned long next;

	p4d = p4d_alloc(mm, pgd_offset(mm, addr), addr);
	if (WARN_ON_ONCE(!p4d))
		return -ENOMEM;
	do {
		next = p4d_addr_end(addr, end);

		if (map_pud_range(mm, p4d, addr, next, phys_addr, prot))
			return -ENOMEM;
	} while (p4d++, phys_addr += (next - addr), addr = next, addr != end);
	return 0;
}

static noinline void unmap_pte_range(pmd_t *pmd, unsigned long addr, unsigned long end)
{
	pte_t *pte, *pte_base;

	pte = pte_offset_map(pmd, addr);
	pte_base = pte;
	WARN_ON(!folio_test_pgtable(virt_to_folio(pte)));
	do {
		pte_t ptent = native_ptep_get_and_clear(pte);
		WARN_ON(!pte_none(ptent) && !pte_present(ptent));
	} while (pte++, addr += PAGE_SIZE, addr != end);
	pte_unmap(pte_base);
}

static noinline void unmap_pmd_range(pud_t *pud, unsigned long addr, unsigned long end)
{
	pmd_t *pmd;
	unsigned long next;
	int cleared;

	pmd = pmd_offset(pud, addr);
	do {
		next = pmd_addr_end(addr, end);

		cleared = pmd_clear_huge(pmd);

		if (cleared)
			continue;
		if (pmd_none_or_clear_bad(pmd))
			continue;
		unmap_pte_range(pmd, addr, next);
	} while (pmd++, addr = next, addr != end);
}

static noinline void unmap_pud_range(p4d_t *p4d, unsigned long addr, unsigned long end)
{
	pud_t *pud;
	unsigned long next;
	int cleared;

	pud = pud_offset(p4d, addr);
	do {
		next = pud_addr_end(addr, end);

		cleared = pud_clear_huge(pud);

		if (cleared)
			continue;
		if (pud_none_or_clear_bad(pud))
			continue;
		unmap_pmd_range(pud, addr, next);
	} while (pud++, addr = next, addr != end);
}

static noinline void unmap_p4d_range(pgd_t *pgd, unsigned long addr, unsigned long end)
{
	p4d_t *p4d;
	unsigned long next;

	p4d = p4d_offset(pgd, addr);
	do {
		next = p4d_addr_end(addr, end);

		p4d_clear_huge(p4d);
		if (p4d_none_or_clear_bad(p4d))
			continue;
		unmap_pud_range(p4d, addr, next);
	} while (p4d++, addr = next, addr != end);
}

static noinline void unmap_page_range_noflush(struct mm_struct *mm,
					    unsigned long addr,
					    unsigned long end)
{
	unsigned long next;
	pgd_t *pgd = pgd_offset(mm, addr);

	BUG_ON(addr >= end);

	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(pgd))
			continue;
		unmap_p4d_range(pgd, addr, next);
	} while (pgd++, addr = next, addr != end);
}

/* Return a region allocated by ephmap_get(). */
void ephmap_put(const void *vaddr, unsigned long size)
{
	unsigned long addr = (unsigned long)vaddr;
	unsigned long end = addr + PAGE_ALIGN(size);

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
			asm volatile("invlpg (%0)" ::"r" (addr + offset) : "memory");
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

/* Call ephmap_put(), if the address is in the ephmap range. */
void ephmap_cond_put(const void *p, unsigned long size)
{
	unsigned long addr = (unsigned long)p;

	if (addr >= EPHEMERAL_FILEMAP_BASE_ADDR && addr < EPHMAP_END_ADDR)
		ephmap_put(p, size);
}

static int map_page_range(struct mm_struct *mm, unsigned long addr,
			  unsigned long end, phys_addr_t phys_addr, pgprot_t prot)
{
	unsigned long start;
	unsigned long next;
	int err;

	BUG_ON(addr >= end);

	start = addr;
	do {
		next = pgd_addr_end(addr, end);
		err = map_p4d_range(mm, addr, next, phys_addr, prot);
		if (err)
			break;
	} while (phys_addr += (next - addr), addr = next, addr != end);

	return err;
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
void *ephmap_get(struct page *page, unsigned long size, pgprot_t prot)
{
	unsigned long addr;
	void *ptr;

	lockdep_assert(is_migration_disabled(current));

	if (!current->mm || this_cpu_xchg(current->mm->mml_cpu->in_use, true)) {
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
			   page_to_phys(page), prot)) {
		ephmap_put(ptr, size);
		return NULL;
	}

	return ptr;

}

/* Set up ephmap for a new mm. */
void ephmap_setup(struct mm_struct *mm)
{
	int cpu;
	/*
	 * So we can use this from the page allocator, preallocate pagetables.
	 * Easiest way to do this is just map some random address (NC to prevent
	 * CPU vuln leaks) and then unmap it again, leaving the tables behind.
	 */
	for_each_possible_cpu(cpu) {
		unsigned long addr = EPHEMERAL_FILEMAP_BASE_ADDR + (smp_processor_id() * EPHMAP_CPU_REGION_SIZE);
		unsigned long end = addr + EPHMAP_CPU_REGION_SIZE;

		map_page_range(mm, addr, end, __START_KERNEL_map, __pgprot(0));
		/*
		 * Because we set __pgprot(0) everything should be pte_none() so
		 * no need to unmap.
		 */
	}
}

/*
 * Page table freeing functions, copied from memory.c but adapted not to free
 * locks or update accounting. Also dropps paravirt support.
 */

/*
 * Note: this doesn't free the actual pages themselves. That
 * has been handled earlier when unmapping all the memory regions.
 */
static noinline void free_pte_range(struct mmu_gather *tlb, pmd_t *pmd,
			   unsigned long addr)
{
	pgtable_t token = pmd_pgtable(*pmd);
	pmd_clear(pmd);
	tlb_flush_pmd_range(tlb, addr, PAGE_SIZE);
	tlb->freed_tables = 1;
	__folio_clear_pgtable(ptdesc_folio(page_ptdesc(token)));
	// lruvec_stat_sub_folio(folio, NR_PAGETABLE);
}

static inline void free_pmd_range(struct mmu_gather *tlb, pud_t *pud,
				unsigned long addr, unsigned long end,
				unsigned long floor, unsigned long ceiling)
{
	pmd_t *pmd;
	unsigned long next;
	unsigned long start;
	struct ptdesc *ptdesc;
	struct folio *folio;

	start = addr;
	pmd = pmd_offset(pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		if (pmd_none_or_clear_bad(pmd))
			continue;
		free_pte_range(tlb, pmd, addr);
	} while (pmd++, addr = next, addr != end);

	start &= PUD_MASK;
	if (start < floor)
		return;
	if (ceiling) {
		ceiling &= PUD_MASK;
		if (!ceiling)
			return;
	}
	if (end - 1 > ceiling - 1)
		return;

	pmd = pmd_offset(pud, start);
  	ptdesc = virt_to_ptdesc(pmd);
	folio = ptdesc_folio(ptdesc);
	pud_clear(pud);
	tlb_flush_pud_range(tlb, addr, PAGE_SIZE);
	tlb->freed_tables = 1;
	__folio_clear_pgtable(folio);
	lruvec_stat_sub_folio(folio, NR_PAGETABLE);
	// mm_dec_nr_pmds(tlb->mm);
	// lruvec_stat_sub_folio(folio, NR_PAGETABLE);
}

static inline void free_pud_range(struct mmu_gather *tlb, p4d_t *p4d,
				unsigned long addr, unsigned long end,
				unsigned long floor, unsigned long ceiling)
{
	pud_t *pud;
	unsigned long next;
	unsigned long start;
	struct ptdesc *ptdesc;
	struct folio *folio;

	start = addr;
	pud = pud_offset(p4d, addr);
	do {
		next = pud_addr_end(addr, end);
		if (pud_none_or_clear_bad(pud))
			continue;
		free_pmd_range(tlb, pud, addr, next, floor, ceiling);
	} while (pud++, addr = next, addr != end);

	start &= P4D_MASK;
	if (start < floor)
		return;
	if (ceiling) {
		ceiling &= P4D_MASK;
		if (!ceiling)
			return;
	}
	if (end - 1 > ceiling - 1)
		return;

	pud = pud_offset(p4d, start);
  	ptdesc = virt_to_ptdesc(pud);
	folio = ptdesc_folio(ptdesc);
	p4d_clear(p4d);
	tlb_flush_p4d_range(tlb, addr, PAGE_SIZE);
	tlb->freed_tables = 1;
	__folio_clear_pgtable(folio);
	// mm_dec_nr_puds(tlb->mm);
	// lruvec_stat_sub_folio(folio, NR_PAGETABLE);
}

static inline void free_p4d_range(struct mmu_gather *tlb, pgd_t *pgd,
				unsigned long addr, unsigned long end,
				unsigned long floor, unsigned long ceiling)
{
	p4d_t *p4d;
	unsigned long next;
	unsigned long start;
	struct ptdesc *ptdesc;
	struct folio *folio;

	start = addr;
	p4d = p4d_offset(pgd, addr);
	do {
		next = p4d_addr_end(addr, end);
		if (p4d_none_or_clear_bad(p4d))
			continue;
		free_pud_range(tlb, p4d, addr, next, floor, ceiling);
	} while (p4d++, addr = next, addr != end);

	start &= PGDIR_MASK;
	if (start < floor)
		return;
	if (ceiling) {
		ceiling &= PGDIR_MASK;
		if (!ceiling)
			return;
	}
	if (end - 1 > ceiling - 1)
		return;

	p4d = p4d_offset(pgd, start);
  	ptdesc = virt_to_ptdesc(p4d);
	folio = ptdesc_folio(ptdesc);
	pgd_clear(pgd);
	__tlb_adjust_range(tlb, addr, PAGE_SIZE);
	tlb->freed_tables = 1;
	// mm_dec_nr_p4ds(tlb->mm);
	// lruvec_stat_sub_folio(folio, NR_PAGETABLE);
}

/*
 * This function frees user-level page tables of a process.
 */
static noinline __maybe_unused void ephmap_free_pgd_range(struct mmu_gather *tlb,
			unsigned long addr, unsigned long end,
			unsigned long floor, unsigned long ceiling)
{
	pgd_t *pgd;
	unsigned long next;

	/*
	 * The next few lines have given us lots of grief...
	 *
	 * Why are we testing PMD* at this top level?  Because often
	 * there will be no work to do at all, and we'd prefer not to
	 * go all the way down to the bottom just to discover that.
	 *
	 * Why all these "- 1"s?  Because 0 represents both the bottom
	 * of the address space and the top of it (using -1 for the
	 * top wouldn't help much: the masks would do the wrong thing).
	 * The rule is that addr 0 and floor 0 refer to the bottom of
	 * the address space, but end 0 and ceiling 0 refer to the top
	 * Comparisons need to use "end - 1" and "ceiling - 1" (though
	 * that end 0 case should be mythical).
	 *
	 * Wherever addr is brought up or ceiling brought down, we must
	 * be careful to reject "the opposite 0" before it confuses the
	 * subsequent tests.  But what about where end is brought down
	 * by PMD_SIZE below? no, end can't go down to 0 there.
	 *
	 * Whereas we round start (addr) and ceiling down, by different
	 * masks at different levels, in order to test whether a table
	 * now has no other vmas using it, so can be freed, we don't
	 * bother to round floor or end up - the tests don't need that.
	 */

	addr &= PMD_MASK;
	if (addr < floor) {
		addr += PMD_SIZE;
		if (!addr)
			return;
	}
	if (ceiling) {
		ceiling &= PMD_MASK;
		if (!ceiling)
			return;
	}
	if (end - 1 > ceiling - 1)
		end -= PMD_SIZE;
	if (addr > end - 1)
		return;
	/*
	 * We add page table cache pages with PAGE_SIZE,
	 * (see pte_free_tlb()), flush the tlb if we need
	 */
	tlb_change_page_size(tlb, PAGE_SIZE);
	pgd = pgd_offset(tlb->mm, addr);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(pgd))
			continue;
		free_p4d_range(tlb, pgd, addr, next, floor, ceiling);
	} while (pgd++, addr = next, addr != end);
}

/* Clean up ephmap stuff on mm teardown. */
void ephmap_cleanup(struct mmu_gather *tlb)
{
	unsigned long start = EPHEMERAL_FILEMAP_BASE_ADDR;
	/*
	 * TODO: Aligning the region boundaries is a hack to make
	 * free_pgd_range() free the pagetables. Actually this pagetable
	 * management just needs to be designed properly! Yikes.
	 */
	unsigned long end = ALIGN(EPHMAP_END_ADDR, PUD_SIZE);
	int cpu;

	/* Stop anyone from using it now that we are freeing the pagetables. */
	for_each_possible_cpu(cpu) {
		per_cpu(tlb->mm->mml_cpu->in_use, cpu) = false;
	}

	/* Cribbed from free_ldt_pagetables() */
	free_pgd_range(tlb, start, end, start, end);
}