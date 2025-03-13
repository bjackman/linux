// SPDX-License-Identifier: GPL-2.0
#include <linux/bug.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/pgtable.h>
#include <linux/set_memory.h>
#include <linux/vmalloc.h>

#include <asm/asi.h>
#include <asm/traps.h>

static __aligned(PAGE_SIZE) pgd_t asi_global_nonsensitive_pgd[PTRS_PER_PGD];

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
		 * Existing mappings should already match the structure of the
		 * unrestricted physmap.
		 */
		if (WARN_ON_ONCE(level != level_asi))
			continue;

		set_pte(pte_asi, *pte);
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
