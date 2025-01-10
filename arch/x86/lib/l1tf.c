// SPDX-License-Identifier: GPL-2.0
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/string.h>

#include <asm/cpufeature.h>
#include <asm/l1tf.h>
#include <asm/msr.h>

#define L1D_CACHE_ORDER 4
static void *l1tf_flush_pages;

int l1tf_flush_setup(void)
{
	struct page *page;
	unsigned int i;

	if (l1tf_flush_pages || boot_cpu_has(X86_FEATURE_FLUSH_L1D))
		return 0;

	page = alloc_pages(GFP_KERNEL, L1D_CACHE_ORDER);
	if (!page)
		return -ENOMEM;
	l1tf_flush_pages = page_address(page);

	/*
	 * Initialize each page with a different pattern in
	 * order to protect against KSM in the nested
	 * virtualization case.
	 */
	for (i = 0; i < 1u << L1D_CACHE_ORDER; ++i) {
		memset(l1tf_flush_pages + i * PAGE_SIZE, i + 1,
			 PAGE_SIZE);
	}

	return 0;
}
EXPORT_SYMBOL(l1tf_flush_setup);

/*
 * Flush L1D in a way that:
 *
 *  - definitely works on CPUs X86_FEATURE_FLUSH_L1D (because the SDM says so).
 *  - almost definitely works on other CPUs with L1TF (because someone on LKML
 *    said someone from Intel said so).
 *  - may or may not work on other CPUs.
 *
 * Don't call unless l1tf_flush_setup() has returned successfully.
 *
 * Must be reentrant, for use by ASI.
 */
noinstr void l1tf_flush(void)
{
	int size = PAGE_SIZE << L1D_CACHE_ORDER;

	if (static_cpu_has(X86_FEATURE_FLUSH_L1D)) {
		native_wrmsrl(MSR_IA32_FLUSH_CMD, L1D_FLUSH);
		return;
	}

	if (WARN_ON(!l1tf_flush_pages))
		return;

	/*
	 * This sequence was provided by Intel for the purpose of mitigating
	 * L1TF on VMX.
	 *
	 * The L1D cache is 32 KiB on Nehalem and some later microarchitectures,
	 * but to flush it is required to read in 64 KiB because the replacement
	 * algorithm is not exactly LRU. This could be sized at runtime via
	 * topology information but as all relevant affected CPUs have 32KiB L1D
	 * cache size there is no point in doing so.
	 */
	asm volatile(
		/* First ensure the pages are in the TLB */
		"xorl	%%eax, %%eax\n"
		".Lpopulate_tlb:\n\t"
		"movzbl	(%[flush_pages], %%" _ASM_AX "), %%ecx\n\t"
		"addl	$4096, %%eax\n\t"
		"cmpl	%%eax, %[size]\n\t"
		"jne	.Lpopulate_tlb\n\t"
		"xorl	%%eax, %%eax\n\t"
		"cpuid\n\t"
		/* Now fill the cache */
		"xorl	%%eax, %%eax\n"
		".Lfill_cache:\n"
		"movzbl	(%[flush_pages], %%" _ASM_AX "), %%ecx\n\t"
		"addl	$64, %%eax\n\t"
		"cmpl	%%eax, %[size]\n\t"
		"jne	.Lfill_cache\n\t"
		"lfence\n"
		:: [flush_pages] "r" (l1tf_flush_pages),
		    [size] "r" (size)
		: "eax", "ebx", "ecx", "edx");
}
EXPORT_SYMBOL(l1tf_flush);
