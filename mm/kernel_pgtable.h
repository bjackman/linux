/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_KERNEL_PGTABLE_H
#define _LINUX_KERNEL_PGTABLE_H

#include <linux/hugetlb.h>
#include <linux/mm.h>
#include <linux/pgtable.h>
#include <linux/vmalloc.h>

#include "pgalloc-track.h"

/*
 * Helpers for manipulating kernel pagetables.
 */

static inline int kernel_map_pte_range(pmd_t *pmd,
			unsigned long addr, unsigned long end,
			phys_addr_t phys_addr, pgprot_t prot,
			unsigned int max_page_shift, pgtbl_mod_mask *mask)
{
	pte_t *pte;
	u64 pfn;
	struct page *page;
	unsigned long size = PAGE_SIZE;

	if (WARN_ON_ONCE(!PAGE_ALIGNED(end - addr)))
		return -EINVAL;

	pfn = phys_addr >> PAGE_SHIFT;
	pte = pte_alloc_kernel_track(pmd, addr, mask);
	if (!pte)
		return -ENOMEM;

	arch_enter_lazy_mmu_mode();

	do {
		if (unlikely(!pte_none(ptep_get(pte)))) {
			if (pfn_valid(pfn)) {
				page = pfn_to_page(pfn);
				dump_page(page, "remapping already mapped page");
			}
			BUG();
		}

#ifdef CONFIG_HUGETLB_PAGE
		size = arch_vmap_pte_range_map_size(addr, end, pfn, max_page_shift);
		if (size != PAGE_SIZE) {
			pte_t entry = pfn_pte(pfn, prot);

			entry = arch_make_huge_pte(entry, ilog2(size), 0);
			set_huge_pte_at(&init_mm, addr, pte, entry, size);
			pfn += PFN_DOWN(size);
			continue;
		}
#endif
		set_pte_at(&init_mm, addr, pte, pfn_pte(pfn, prot));
		pfn++;
	} while (pte += PFN_DOWN(size), addr += size, addr != end);

	arch_leave_lazy_mmu_mode();
	*mask |= PGTBL_PTE_MODIFIED;
	return 0;
}

static inline int kernel_try_huge_pmd(pmd_t *pmd,
			unsigned long addr, unsigned long end,
			phys_addr_t phys_addr, pgprot_t prot,
			unsigned int max_page_shift)
{
	if (max_page_shift < PMD_SHIFT)
		return 0;

	if (!arch_vmap_pmd_supported(prot))
		return 0;

	if ((end - addr) != PMD_SIZE)
		return 0;

	if (!IS_ALIGNED(addr, PMD_SIZE))
		return 0;

	if (!IS_ALIGNED(phys_addr, PMD_SIZE))
		return 0;

	if (pmd_present(*pmd) && !pmd_free_pte_page(pmd, addr))
		return 0;

	return pmd_set_huge(pmd, phys_addr, prot);
}

static inline int kernel_map_pmd_range(pud_t *pud,
			unsigned long addr, unsigned long end,
			phys_addr_t phys_addr, pgprot_t prot,
			unsigned int max_page_shift, pgtbl_mod_mask *mask)
{
	pmd_t *pmd;
	unsigned long next;
	int err = 0;

	pmd = pmd_alloc_track(&init_mm, pud, addr, mask);
	if (!pmd)
		return -ENOMEM;
	do {
		next = pmd_addr_end(addr, end);

		if (kernel_try_huge_pmd(pmd, addr, next, phys_addr, prot,
					max_page_shift)) {
			*mask |= PGTBL_PMD_MODIFIED;
			continue;
		}

		err = kernel_map_pte_range(pmd, addr, next, phys_addr, prot, max_page_shift, mask);
		if (err)
			break;
	} while (pmd++, phys_addr += (next - addr), addr = next, addr != end);
	return err;
}

static inline int kernel_map_try_huge_pud(pud_t *pud,
			unsigned long addr, unsigned long end,
			phys_addr_t phys_addr, pgprot_t prot,
			unsigned int max_page_shift)
{
	if (max_page_shift < PUD_SHIFT)
		return 0;

	if (!arch_vmap_pud_supported(prot))
		return 0;

	if ((end - addr) != PUD_SIZE)
		return 0;

	if (!IS_ALIGNED(addr, PUD_SIZE))
		return 0;

	if (!IS_ALIGNED(phys_addr, PUD_SIZE))
		return 0;

	if (pud_present(*pud) && !pud_free_pmd_page(pud, addr))
		return 0;

	return pud_set_huge(pud, phys_addr, prot);
}

static inline int kernel_map_pud_range(p4d_t *p4d,
			unsigned long addr, unsigned long end,
			phys_addr_t phys_addr, pgprot_t prot,
			unsigned int max_page_shift, pgtbl_mod_mask *mask)
{
	pud_t *pud;
	unsigned long next;
	int err = 0;

	pud = pud_alloc_track(&init_mm, p4d, addr, mask);
	if (!pud)
		return -ENOMEM;
	do {
		next = pud_addr_end(addr, end);

		if (kernel_map_try_huge_pud(pud, addr, next, phys_addr, prot,
					max_page_shift)) {
			*mask |= PGTBL_PUD_MODIFIED;
			continue;
		}

		err = kernel_map_pmd_range(pud, addr, next, phys_addr, prot, max_page_shift, mask);
		if (err)
			break;
	} while (pud++, phys_addr += (next - addr), addr = next, addr != end);
	return err;
}

static inline int kernel_try_huge_p4d(p4d_t *p4d,
			unsigned long addr, unsigned long end,
			phys_addr_t phys_addr, pgprot_t prot,
			unsigned int max_page_shift)
{
	if (max_page_shift < P4D_SHIFT)
		return 0;

	if (!arch_vmap_p4d_supported(prot))
		return 0;

	if ((end - addr) != P4D_SIZE)
		return 0;

	if (!IS_ALIGNED(addr, P4D_SIZE))
		return 0;

	if (!IS_ALIGNED(phys_addr, P4D_SIZE))
		return 0;

	if (p4d_present(*p4d) && !p4d_free_pud_page(p4d, addr))
		return 0;

	return p4d_set_huge(p4d, phys_addr, prot);
}

static inline int kernel_map_p4d_range(pgd_t *pgd,
			unsigned long addr, unsigned long end,
			phys_addr_t phys_addr, pgprot_t prot,
			unsigned int max_page_shift, pgtbl_mod_mask *mask)
{
	p4d_t *p4d;
	unsigned long next;
	int err = 0;

	p4d = p4d_alloc_track(&init_mm, pgd, addr, mask);
	if (!p4d)
		return -ENOMEM;
	do {
		next = p4d_addr_end(addr, end);

		if (kernel_try_huge_p4d(p4d, addr, next, phys_addr, prot,
					max_page_shift)) {
			*mask |= PGTBL_P4D_MODIFIED;
			continue;
		}

		err = kernel_map_pud_range(p4d, addr, next, phys_addr, prot, max_page_shift, mask);
		if (err)
			break;
	} while (p4d++, phys_addr += (next - addr), addr = next, addr != end);
	return err;
}

static inline int kernel_map_range_noflush(unsigned long addr, unsigned long end,
			phys_addr_t phys_addr, pgprot_t prot,
			unsigned int max_page_shift)
{
	pgd_t *pgd;
	unsigned long start;
	unsigned long next;
	int err;
	pgtbl_mod_mask mask = 0;

	might_sleep();
	BUG_ON(addr >= end);

	start = addr;
	pgd = pgd_offset_k(addr);
	do {
		next = pgd_addr_end(addr, end);
		err = kernel_map_p4d_range(pgd, addr, next, phys_addr, prot,
					max_page_shift, &mask);
		if (err)
			break;
	} while (pgd++, phys_addr += (next - addr), addr = next, addr != end);

	if (mask & ARCH_PAGE_TABLE_SYNC_MASK)
		arch_sync_kernel_mappings(start, end);

	return err;
}

static inline void kernel_unmap_pte_range(pmd_t *pmd,
			unsigned long addr, unsigned long end,
			pgtbl_mod_mask *mask)
{
	pte_t *pte;
	pte_t ptent;
	unsigned long size = PAGE_SIZE;

	pte = pte_offset_kernel(pmd, addr);
	arch_enter_lazy_mmu_mode();

	do {
#ifdef CONFIG_HUGETLB_PAGE
		size = arch_vmap_pte_range_unmap_size(addr, pte);
		if (size != PAGE_SIZE) {
			if (WARN_ON(!IS_ALIGNED(addr, size))) {
				addr = ALIGN_DOWN(addr, size);
				pte = PTR_ALIGN_DOWN(pte, sizeof(*pte) * (size >> PAGE_SHIFT));
			}
			ptent = huge_ptep_get_and_clear(&init_mm, addr, pte, size);
			if (WARN_ON(end - addr < size))
				size = end - addr;
		} else
#endif
			ptent = ptep_get_and_clear(&init_mm, addr, pte);
		WARN_ON(!pte_none(ptent) && !pte_present(ptent));
	} while (pte += (size >> PAGE_SHIFT), addr += size, addr != end);

	arch_leave_lazy_mmu_mode();
	*mask |= PGTBL_PTE_MODIFIED;
}

static inline void kernel_unmap_pmd_range(pud_t *pud,
			unsigned long addr, unsigned long end,
			pgtbl_mod_mask *mask)
{
	pmd_t *pmd;
	unsigned long next;
	int cleared;

	pmd = pmd_offset(pud, addr);
	do {
		next = pmd_addr_end(addr, end);

		cleared = pmd_clear_huge(pmd);
		if (cleared || pmd_bad(*pmd))
			*mask |= PGTBL_PMD_MODIFIED;

		if (cleared) {
			WARN_ON(next - addr < PMD_SIZE);
			continue;
		}
		if (pmd_none_or_clear_bad(pmd))
			continue;
		kernel_unmap_pte_range(pmd, addr, next, mask);

		cond_resched();
	} while (pmd++, addr = next, addr != end);
}

static inline void kernel_unmap_pud_range(p4d_t *p4d,
			unsigned long addr, unsigned long end,
			pgtbl_mod_mask *mask)
{
	pud_t *pud;
	unsigned long next;
	int cleared;

	pud = pud_offset(p4d, addr);
	do {
		next = pud_addr_end(addr, end);

		cleared = pud_clear_huge(pud);
		if (cleared || pud_bad(*pud))
			*mask |= PGTBL_PUD_MODIFIED;

		if (cleared) {
			WARN_ON(next - addr < PUD_SIZE);
			continue;
		}
		if (pud_none_or_clear_bad(pud))
			continue;
		kernel_unmap_pmd_range(pud, addr, next, mask);
	} while (pud++, addr = next, addr != end);
}

static inline void kernel_unmap_p4d_range(pgd_t *pgd,
			unsigned long addr, unsigned long end,
			pgtbl_mod_mask *mask)
{
	p4d_t *p4d;
	unsigned long next;

	p4d = p4d_offset(pgd, addr);
	do {
		next = p4d_addr_end(addr, end);

		p4d_clear_huge(p4d);
		if (p4d_bad(*p4d))
			*mask |= PGTBL_P4D_MODIFIED;

		if (p4d_none_or_clear_bad(p4d))
			continue;
		kernel_unmap_pud_range(p4d, addr, next, mask);
	} while (p4d++, addr = next, addr != end);
}

static inline void kernel_unmap_range_noflush(unsigned long start,
					      unsigned long end)
{
	unsigned long next;
	pgd_t *pgd;
	unsigned long addr = start;
	pgtbl_mod_mask mask = 0;

	BUG_ON(addr >= end);
	pgd = pgd_offset_k(addr);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_bad(*pgd))
			mask |= PGTBL_PGD_MODIFIED;
		if (pgd_none_or_clear_bad(pgd))
			continue;
		kernel_unmap_p4d_range(pgd, addr, next, &mask);
	} while (pgd++, addr = next, addr != end);

	if (mask & ARCH_PAGE_TABLE_SYNC_MASK)
		arch_sync_kernel_mappings(start, end);
}

#endif /* _LINUX_KERNEL_PGTABLE_H */
