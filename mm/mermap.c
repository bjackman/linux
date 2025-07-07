/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/mermap.h>
#include <linux/mm.h>
#include <linux/pagemap.h>

#include <asm/io.h>
#include <asm/pgtable.h>
#include <asm/tlb.h>

#include "kernel_pgtable.h"
#include "internal.h"

/*
 * Each CPU gets a chunk of the ephemeral mapping the size of the maximum folio
 * size.
 */
#define MERMAP_CPU_REGION_SIZE (PAGE_SIZE << MAX_PAGECACHE_ORDER)
#define MERMAP_SIZE (MERMAP_CPU_REGION_SIZE * NR_CPUS)
#define MERMAP_END_ADDR (MERMAP_BASE_ADDR + (NR_CPUS * MERMAP_CPU_REGION_SIZE))

/* Return a region allocated by mermap_get(). */
void mermap_put(const void *vaddr, unsigned long size)
{
	unsigned long addr = (unsigned long)vaddr;
	unsigned long end = addr + PAGE_ALIGN(size);

	kernel_unmap_range_noflush(addr, end);

	// TODO: CONFIG_ARCH_HAS_ for this.
	flush_tlb_kernel_range_local(addr, end);

	this_cpu_write(current->mm->mermap->in_use, false);
}
EXPORT_SYMBOL(mermap_put);

static inline unsigned long mermap_cpu_base(int cpu)
{
	return MERMAP_BASE_ADDR + (cpu * MERMAP_CPU_REGION_SIZE);
}

/* Non-inclusive :/ */
static inline unsigned long mermap_cpu_end(int cpu)
{
	return MERMAP_BASE_ADDR + ((cpu + 1) * MERMAP_CPU_REGION_SIZE);
}

static inline bool is_mermap(unsigned long addr, int cpu)
{
	return addr >= mermap_cpu_base(cpu) && addr < mermap_cpu_end(cpu);
}

/* Call mermap_put(), if the address is in the mermap range. */
void mermap_cond_put(const void *p, unsigned long size)
{
	if (is_mermap((unsigned long)p, smp_processor_id()))
		mermap_put(p, size);
}
EXPORT_SYMBOL(mermap_cond_put);

/*
 * Allocate a region of virtual memory, and map the page into it. This tries
 * very hard to be fast and doesn't try very hard at all to actually succeed,
 * expect failures.
 *
 * The returned region is physically local to the current mm. It is _logically_
 * local to the current CPU (so you must disable migration) but this is not
 * enforced by hardware so it can't be exploited to mitigate CPU vulns.
 *
 * This should only be called from process context.
 */
void *mermap_get(struct page *page, unsigned long size, pgprot_t prot)
{
	struct kp_opts opts = {
		.may_alloc = false,
		/* Prevent lower pagetables from getting freed. */
		.max_page_shift = 0,
	};
	unsigned long addr;
	void *ptr;

	// TODO: Disable migration, update commit message and comments to describe
	// new API.

	if (size > MERMAP_CPU_REGION_SIZE)
		return NULL;

	if (!current->mm || this_cpu_xchg(current->mm->mermap->in_use, true)) {
		/* Another thread in this mm is using it */
		return NULL;
	}

	addr = mermap_cpu_base(smp_processor_id());
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

	if (WARN_ON_ONCE(kernel_map_range_noflush(
			addr, addr + size, page_to_phys(page), prot, &opts))) {
		mermap_put(ptr, size);
		return NULL;
	}

	return ptr;

}
EXPORT_SYMBOL(mermap_get);

int mermap_mm_init(struct mm_struct *mm)
{
	struct kp_opts opts = {
		.may_alloc = 1,
		.max_page_shift = 0,
	};
	int cpu;

	mm->mermap = alloc_percpu_gfp(struct mermap, GFP_KERNEL_ACCOUNT);
	if (!mm->mermap)
		return -ENOMEM;


	/* Runtime assert because MM_LOCAL_END_ADDR is variable on x86. */
	BUG_ON(MERMAP_END_ADDR > MM_LOCAL_END_ADDR);

	/*
	 * So we can use this from the page allocator, preallocate pagetables.
	 * Easiest way to do this is just map some random address (NC to prevent
	 * CPU vuln leaks) and then unmap it again, leaving the tables behind.
	 */
	for_each_possible_cpu(cpu) {
		unsigned long addr = MERMAP_BASE_ADDR + (cpu * MERMAP_CPU_REGION_SIZE);
		unsigned long end = addr + MERMAP_CPU_REGION_SIZE;

		kernel_map_range_noflush(addr, end, __START_KERNEL_map,
					 PAGE_KERNEL_NOCACHE, &opts);
		kernel_unmap_range_noflush(addr, end);
	}

	return 0;
}

/* Clean up mermap stuff on mm teardown. */
void mermap_mm_teardown(struct mm_struct *mm)
{
	/*
	 * TODO: Aligning the region boundaries is a hack to make
	 * free_pgd_range() free the pagetables. Actually this pagetable
	 * management just needs to be designed properly! Yikes.
	 */
	unsigned long end = ALIGN(MERMAP_END_ADDR, PUD_SIZE);
	unsigned long start = MERMAP_BASE_ADDR;
	struct mmu_gather tlb;
	int cpu;

	for_each_possible_cpu(cpu)
		VM_WARN_ON_ONCE(mm->mermap->in_use);

	tlb_gather_mmu_fullmm(&tlb, mm);
	free_pgd_range(&tlb, start, end, start, end);
	tlb_finish_mmu(&tlb);

	free_percpu(mm->mermap);
}
