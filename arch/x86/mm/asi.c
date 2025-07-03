// SPDX-License-Identifier: GPL-2.0
#include <linux/bug.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/pgtable.h>
#include <linux/set_memory.h>
#include <linux/vmalloc.h>

#include <asm/asi.h>
#include <asm/pgtable.h>
#include <asm/traps.h>

__aligned(PAGE_SIZE) pgd_t asi_global_nonsensitive_pgd[PTRS_PER_PGD];

struct asi __asi_global_nonsensitive = {
	.pgd = asi_global_nonsensitive_pgd,
};

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
