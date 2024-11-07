// SPDX-License-Identifier: GPL-2.0-only
#include <linux/gfp.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/mm_types.h>
#include <linux/mm.h>
#include <linux/pgtable.h>
#include <linux/sched/mm.h>
#include <linux/types.h>
#include <linux/vmalloc.h>

#include <kunit/resource.h>
#include <kunit/test.h>

#include <asm/apic.h>
#include <asm/asi.h>
#include <asm/kvm_host.h>
#include <asm/nmi.h>
#include <asm/set_memory.h>

#include "asi_internal.h"

/*
 * Thank you for visiting asi_test.c. We have some local naming conventions:
 *
 *  - do_ is the prefix for general wrappers around kernel APIs. do_foo should
 *    call foo, and nothing more except dealing with error handling (via
 *    KUNIT_ASSERT_*) and cleanup (via KUnit's resource/action API).
 *  - action_ is the prefix for cleanup-specific wrappers. action_foo should do
 *    nothing but call foo in a way that's suitable for use with KUnit's action
 *    API.
 *  - If action_ helpers need state beyond what can be squashed into void *,
 *    we'll use a struct with _ctx at the end of the name. action_foo should use
 *    struct foo_ctx.
 *  - Test functions start with test_. Note they don't need "asi" in the name
 *    because they are already namespaced within the "asi" test suite.
 *
 * A few things to be careful about when writing tests:
 * - Do not use KUNIT_ASSERT_* in ASI critical sections, only KUNIT_EXPECT_*. If
 *   the former fails, it stops running the test thread and runs cleanup actions
 *   in a different thread, which tries to context switch in the critical
 *   section.
 */

struct asi_test_info {
	struct asi              *asi;
	struct mm_struct	*mm;
};

static void action_mmdrop(void *ctx)
{
	mmdrop((struct mm_struct *)ctx);
}

static struct mm_struct *do_mm_alloc(struct kunit *test)
{
	struct mm_struct *mm = mm_alloc();

	KUNIT_ASSERT_NOT_NULL(test, mm);
	kunit_add_action_or_reset(test, action_mmdrop, mm);
	return mm;
}

static void action_kthread_unuse_mm(void *ctx)
{
	struct mm_struct *mm = ctx;

	if (current->mm == mm)
		kthread_unuse_mm(mm);
}

static void action_asi_uninit_class(void *ctx)
{
	asi_uninit_class((enum asi_class_id)ctx);
}

static void action_asi_destroy(void *ctx)
{
	asi_destroy((struct asi *)ctx);
}

static void do_asi_init(struct kunit *test, struct mm_struct *mm,
			enum asi_class_id class_id, struct asi **out_asi)
{
	KUNIT_ASSERT_GE(test, 0, asi_init(mm, class_id, out_asi));
	kunit_add_action(test, action_asi_destroy, *out_asi);
}
static struct asi_test_info *setup_test_asi(struct kunit *test)
{
	struct asi_test_info *info;
	static struct asi_taint_policy taint_policy = {
		/* Arbitrary policy */
		.prevent_control = ASI_TAINTS_CONTROL_MASK,
		.protect_data = ASI_TAINTS_DATA_MASK,
		.set = ASI_TAINTS_CONTROL_MASK | ASI_TAINTS_DATA_MASK,
	};

	if (!static_asi_enabled())
		kunit_skip(test, "ASI disabled. Set asi=on in kmdline to run test");

	info = kunit_kzalloc(
			test, sizeof(struct asi_test_info), GFP_KERNEL);
	KUNIT_ASSERT_GE(test, asi_init_class(ASI_CLASS_TEST, &taint_policy), 0);
	kunit_add_action(test, action_asi_uninit_class, (void *)ASI_CLASS_TEST);

	info->mm = do_mm_alloc(test);
	kthread_use_mm(info->mm);
	kunit_add_action(test, action_kthread_unuse_mm, info->mm);

	do_asi_init(test, info->mm, ASI_CLASS_TEST, &info->asi);
	return info;
}

static void test_asi_state(struct kunit *test)
{
	struct asi_test_info *info = setup_test_asi(test);
	struct asi *asi = info->asi;

	preempt_disable();

	asi_enter(asi);
	KUNIT_EXPECT_TRUE(test, asi_is_restricted());
	KUNIT_EXPECT_FALSE(test, asi_is_relaxed());

	asi_relax();
	KUNIT_EXPECT_TRUE(test, asi_is_restricted());
	KUNIT_EXPECT_TRUE(test, asi_is_relaxed());

	asi_exit(ASI_EXIT_MISC);
	KUNIT_EXPECT_FALSE(test, asi_is_restricted());
	KUNIT_EXPECT_TRUE(test, asi_is_relaxed());

	preempt_enable();
}

enum asi_transition {
	ASI_TRANS_ENTER_USERSPACE,
	ASI_TRANS_ENTER_KVM,
	ASI_TRANS_EXIT,
	ASI_TRANS_SWITCH_MM,
	ASI_NUM_TRANSITIONS,
};

const char *asi_transition_names[] = {
	[ASI_TRANS_ENTER_USERSPACE] = "enter(user)",
	[ASI_TRANS_ENTER_KVM] = "enter(kvm)",
	[ASI_TRANS_EXIT] = "exit",
	[ASI_TRANS_SWITCH_MM] = "switch-mm",
};

#define ASI_MAX_NUM_TRANSITIONS 4 /* Ought to be enough for anyone. */

/*
 * We want to test the tainting logic with reference to the real world, so we
 * use the real ASI KVM logic to set up the taint flags. In other words this
 * tests not only the core tainting logic but also the parameters of the
 * userspace and KVM classes.
 */
#if IS_REACHABLE(CONFIG_KVM_X86)

/*
 * Generates a param for test_asi_tainting which takes the form of an array of
 * asi_transitions, terminated by an invalid value.
 */
static const void *asi_tainting_gen_params(const void *prev, char *desc)
{
	/* Start with an invalid value. */
	static enum asi_transition transitions[ASI_MAX_NUM_TRANSITIONS] = {
		[0 ... ASI_MAX_NUM_TRANSITIONS - 1] = 0,
	};
	size_t desc_len = 0;
	int i = 0;

	/*
	 * Just do an exhaustive search of all the transition sequences up to
	 * the max length. This algorithm is just "counting" in base
	 * ASI_NUM_TRANSITION where @transitions contains digits and [0] is the
	 * least significant.
	 */
	transitions[0]++;
	for (i = 0;
	     i < ARRAY_SIZE(transitions) - 1 && transitions[i] >= ASI_NUM_TRANSITIONS;
	     i++) {
		transitions[i] = (enum asi_transition)0;
		transitions[i + 1]++;
	}
	if (i == ARRAY_SIZE(transitions) - 1) {
		/* Done. */
		return NULL;
	}

	/* Generate description as comma-separated list .*/
	for (i = 0;
	     i < ARRAY_SIZE(transitions) && transitions[i] < ASI_NUM_TRANSITIONS;
	     i++) {
		desc_len += sized_strscpy(&desc[desc_len],
					  asi_transition_names[transitions[i]],
					  KUNIT_PARAM_DESC_SIZE - desc_len);
		if (i + 1 < ARRAY_SIZE(transitions) &&
		    transitions[i + 1] != ASI_NUM_TRANSITIONS &&
		    desc_len < KUNIT_PARAM_DESC_SIZE) {
			desc[desc_len++] = ',';
		}
	}

	return (void *)transitions;
}

/*
 * Macros are here to:
 * - Avoid urneadable error messages due to expansion of this_cpu_read calls.
 * - Avoid super verbose repetitive assertions.
 * - Preserve information about the location of the assert.
 */

#define EXPECT_NO_TAINTS(test, mask, i) ({					\
	asi_taints_t taints = this_cpu_read(asi_taints);			\
	KUNIT_EXPECT_EQ_MSG(test, taints & mask, 0, "at iteration %d", i);	\
})

#define EXPECT_TAINTS(test, mask, i) ({						\
	asi_taints_t taints = this_cpu_read(asi_taints);			\
	KUNIT_EXPECT_EQ_MSG(test, taints & mask, mask, "at iteration %d", i);	\
})

static void test_asi_tainting(struct kunit *test)
{
	enum asi_transition *transitions = (enum asi_transition *)test->param_value;
	struct mm_struct *mms[2];
	struct asi *fake_kvm_asis[ARRAY_SIZE(mms)];
	int cur_mm_idx = 0;
	int i;

	if (!asi_class_initialized(ASI_CLASS_KVM)) {
		KUNIT_ASSERT_EQ(test, kvm_x86_init_asi_class(), 0);
		kunit_add_action(test, action_asi_uninit_class, (void *)ASI_CLASS_KVM);
	}
	KUNIT_ASSERT_TRUE(test, asi_class_initialized(ASI_CLASS_USERSPACE));

	/*
	 * Switching mms needs to be fairly realistic, if you try to cheat by
	 * just directly calling asi_handle_switch_mm(), test cases that do
	 * asi_enter(userspace)->switch_mm->asi_enter(userspce) will get
	 * confused, since the two userspace classes will be the same object so
	 * the ASI code doesn't really act like it entered a new userspace
	 * domain. So we really allocate 2 mms.
	 */
	for (i = 0; i < ARRAY_SIZE(mms); i++) {
		mms[i] = do_mm_alloc(test);
		do_asi_init(test, mms[i], ASI_CLASS_KVM, &fake_kvm_asis[i]);
	}
	kthread_use_mm(mms[cur_mm_idx]);

	preempt_disable();

	for (i = 0;
	     i < ASI_MAX_NUM_TRANSITIONS - 1 && transitions[i] < ASI_NUM_TRANSITIONS;
	     i++) {
		enum asi_transition transition = transitions[i];
		asi_taints_t taints;

		/*
		 * Enact the transition and check we applied the appropriate
		 * taint for the incoming domain.
		 */
		switch (transition) {
		case ASI_TRANS_ENTER_USERSPACE:
			asi_enter_userspace();
			EXPECT_TAINTS(test, ASI_TAINT_USER_DATA | ASI_TAINT_USER_CONTROL, i);
			asi_relax();
			break;
		case ASI_TRANS_ENTER_KVM:
			asi_enter(fake_kvm_asis[cur_mm_idx]);
			EXPECT_TAINTS(test, ASI_TAINT_GUEST_CONTROL, i);
			asi_relax();
			break;
		case ASI_TRANS_EXIT:
			asi_exit(ASI_EXIT_MISC);
			EXPECT_TAINTS(test, ASI_TAINT_KERNEL_DATA, i);
			break;
		case ASI_TRANS_SWITCH_MM:
			kthread_unuse_mm(mms[cur_mm_idx]);
			cur_mm_idx = (cur_mm_idx + 1) & ARRAY_SIZE(mms);
			kthread_use_mm(mms[cur_mm_idx]);
			break;
		default:
			KUNIT_FAIL(test, "test bug - invalid transition");
			/* Can't use KUNIT_FAIL_AND_ABORT with preemption off. */
			goto bail;
		}

		/*
		 * Now check that, at least according to the taints, we
		 * performed necessary flushes. This wouldn't catch bugs where
		 * we clear taints without actually scrubbing uarch state.
		 */
		taints = this_cpu_read(asi_taints);

		/* Don't let anyone leak sensitive kernel data or other MMs' data. */
		if (taints & (ASI_TAINT_KERNEL_DATA | ASI_TAINT_OTHER_MM_DATA)) {
			EXPECT_NO_TAINTS(test, ASI_TAINT_USER_CONTROL, i);
			EXPECT_NO_TAINTS(test, ASI_TAINT_GUEST_CONTROL, i);
		}
		if (taints & ASI_TAINT_KERNEL_DATA)
			EXPECT_NO_TAINTS(test, ASI_TAINT_OTHER_MM_CONTROL, i);

		/* Don't let guests or other MMs leak data from userspace */
		if (taints & ASI_TAINT_USER_DATA) {
			EXPECT_NO_TAINTS(test, ASI_TAINT_OTHER_MM_CONTROL, i);
			/*
			 * ..unless we map userspace memory in the restricted address space of
			 *  ASI KVM anyway.
			 */
			if (!asi_maps_user_addr(ASI_CLASS_KVM))
				EXPECT_NO_TAINTS(test, ASI_TAINT_GUEST_CONTROL, i);
		}
	}

bail:
	kthread_unuse_mm(mms[cur_mm_idx]);
	asi_exit(ASI_EXIT_MISC);
	preempt_enable();
}

#else

/* Make the test visible in the list, but skip it. */
static int asi_taint_dummy_cases[] = { 0 };
KUNIT_ARRAY_PARAM(asi_tainting, asi_taint_dummy_cases, NULL);
static void test_asi_tainting(struct kunit *test)
{
	kunit_skip(test, "KVM disabled");
}

#endif /* CONFIG_KVM */

struct free_pages_ctx {
	unsigned int order;
	struct page *pages;
};

static void action___free_pages(void *ctx)
{
	struct free_pages_ctx *context = ctx;

	__free_pages(context->pages, context->order);
}

static struct page *do_alloc_pages(struct kunit *test, gfp_t gfp, unsigned int order)
{
	struct free_pages_ctx *ctx = kunit_kzalloc(
		test, sizeof(struct free_pages_ctx), GFP_KERNEL);

	KUNIT_ASSERT_NOT_NULL(test, ctx);
	ctx->pages = alloc_pages(gfp, order);
	KUNIT_ASSERT_NOT_NULL(test, ctx->pages);
	ctx->order = order;
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(test, action___free_pages, ctx), 0);
	return ctx->pages;
}

struct vm_unmap_ram_ctx {
	void *vaddr;
	unsigned int num_pages;
};

static void action_vm_unmap_ram(void *ctx)
{
	struct vm_unmap_ram_ctx *context = ctx;

	vm_unmap_ram(context->vaddr, context->num_pages);
}

static void *do_vm_map_ram(struct kunit *test, struct page **pages, unsigned int count)
{
	struct vm_unmap_ram_ctx *ctx = kunit_kzalloc(
		test, sizeof(struct vm_unmap_ram_ctx), GFP_KERNEL);

	KUNIT_ASSERT_NOT_NULL(test, ctx);
	ctx->vaddr = vm_map_ram(pages, count, /*node=*/-1);
	KUNIT_ASSERT_NOT_NULL(test, ctx->vaddr);
	ctx->num_pages = count;
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(test, action_vm_unmap_ram, ctx), 0);
	return ctx->vaddr;
}

/*
 * Takes an array of contiguous struct pages and returns an array of pointers to
 * those struct pages. Handy when you get some contiguous pages and want to pass
 * them to an API that supports non-contiguous pages.
 */
static struct page **pages_to_ptr_array(struct kunit *test, struct page *pages, int num_pages)
{
	struct page **pg_array = kunit_kzalloc(test, num_pages * sizeof(struct page *), GFP_KERNEL);
	int i;

	KUNIT_ASSERT_NOT_NULL(test, pages);
	for (i = 0; i < num_pages; i++)
		pg_array[i] = nth_page(pages, i);

	return pg_array;
}

/* This is a very minimal smoke test. */
static void test_asi_map_global_nonsensitive(struct kunit *test)
{
	int order = 1; /* Test with 2 pages */
	int num_pages = 1 << order;
	int size = num_pages * PAGE_SIZE;
	struct page *pages = do_alloc_pages(test, GFP_KERNEL, order);
	struct page **pg_array = pages_to_ptr_array(test, pages, num_pages);
	/* Map the va in the unrestricted address space */
	void *vaddr = do_vm_map_ram(test, pg_array, num_pages);
	unsigned long va_0 = (unsigned long)vaddr;
	unsigned long va_1 = va_0 + size - sizeof(void *);
	struct asi *asi = ASI_GLOBAL_NONSENSITIVE;
	pgd_t *restricted_pgd = asi->pgd;
	pgd_t *unrestricted_pgd = init_mm.pgd;

	/*
	 * va_0/va_1 should be accessible in the unrestricted address space, but
	 * not in the restricted.
	 */
	KUNIT_EXPECT_TRUE(test, addr_present(unrestricted_pgd, va_0));
	KUNIT_EXPECT_TRUE(test, addr_present(unrestricted_pgd, va_1));
	KUNIT_EXPECT_FALSE(test, addr_present(restricted_pgd, va_0));
	KUNIT_EXPECT_FALSE(test, addr_present(restricted_pgd, va_1));

	/*
	 * After mapping the first half of the region, the first half should be
	 * accessible in the restricted address space, but the second half
	 * should not.
	 */
	KUNIT_ASSERT_EQ(test, asi_map(ASI_GLOBAL_NONSENSITIVE, (void *)va_0, PAGE_SIZE), 0);
	KUNIT_EXPECT_TRUE(test, addr_present(restricted_pgd, va_0));
	KUNIT_EXPECT_FALSE(test, addr_present(restricted_pgd, va_1));

	/* Map the entire allocated region. */
	KUNIT_ASSERT_EQ(test, asi_map(ASI_GLOBAL_NONSENSITIVE, (void *)va_0, size), 0);
	KUNIT_EXPECT_TRUE(test, addr_present(restricted_pgd, va_0));
	KUNIT_EXPECT_TRUE(test, addr_present(restricted_pgd, va_1));

	/* Unmap the first half of the region */
	asi_unmap(ASI_GLOBAL_NONSENSITIVE, (void *)va_0, PAGE_SIZE);
	KUNIT_EXPECT_FALSE(test, addr_present(restricted_pgd, va_0));
	KUNIT_EXPECT_TRUE(test, addr_present(restricted_pgd, va_1));

	/* Unmap the entire region */
	asi_unmap(ASI_GLOBAL_NONSENSITIVE, (void *)va_0, size);
	KUNIT_EXPECT_FALSE(test, addr_present(restricted_pgd, va_0));
	KUNIT_EXPECT_FALSE(test, addr_present(restricted_pgd, va_1));
}

static pte_t *lookup_address_asi_global(unsigned long addr, int *level)
{
	pgd_t *restricted_pgd = asi_pgd(ASI_GLOBAL_NONSENSITIVE);

	return lookup_address_in_pgd(pgd_offset_pgd(restricted_pgd, addr),
				     addr, level);
}

static void action_vunmap(void *ctx)
{
	vunmap(ctx);
}

static void *do_vmap(struct kunit *test, struct page **pages,
		     unsigned int count, unsigned long flags, pgprot_t prot)
{
	void *addr = vmap(pages, count, flags, prot);

	KUNIT_ASSERT_NOT_NULL(test, addr);
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(test, action_vunmap, addr), 0);
	return addr;
}

static void test_change_page_attr(struct kunit *test)
{
	pte_t *ptep, *restricted_ptep;
	unsigned long laddr, vaddr;
	struct page *page;
	int level;

	kunit_skip(test, "Not yet supported in this branch");

	/*
	 * Allocate a page and make sure it's mapped by a 4K mapping in the
	 * unrestricted page tables so that the mapping is equivalent to that in
	 * the restricted page tables.
	 */
	page = do_alloc_pages(test, GFP_KERNEL, 0);
	laddr = (unsigned long)page_to_virt(page);
	set_memory_4k(laddr, 1);

	/*
	 * Check that the allocated page has equal a writeable mapping in
	 * both the restricted and unrestricted page tables.
	 */
	ptep = lookup_address(laddr, &level);
	KUNIT_ASSERT_NOT_NULL(test, ptep);

	restricted_ptep = lookup_address_asi_global(laddr, &level);
	KUNIT_ASSERT_NOT_NULL(test, restricted_ptep);

	KUNIT_EXPECT_EQ(test, pte_val(*restricted_ptep), pte_val(*ptep));
	KUNIT_EXPECT_TRUE(test, pte_write(*restricted_ptep));

	/* Now make the page read-only in the direct map */
	set_memory_ro(laddr, 1);

	/* Check that the direct map mappings are still equal, but are now RO */
	ptep = lookup_address(laddr, &level);
	KUNIT_ASSERT_NOT_NULL(test, ptep);

	restricted_ptep = lookup_address_asi_global(laddr, &level);
	KUNIT_ASSERT_NOT_NULL(test, restricted_ptep);

	KUNIT_EXPECT_EQ(test, pte_val(*restricted_ptep), pte_val(*ptep));
	KUNIT_EXPECT_FALSE(test, pte_write(*restricted_ptep));

	/* Restore the mappings to RW and check again */
	set_memory_rw(laddr, 1);

	ptep = lookup_address(laddr, &level);
	KUNIT_ASSERT_NOT_NULL(test, ptep);

	restricted_ptep = lookup_address_asi_global(laddr, &level);
	KUNIT_ASSERT_NOT_NULL(test, restricted_ptep);

	KUNIT_EXPECT_EQ(test, pte_val(*restricted_ptep), pte_val(*ptep));
	KUNIT_EXPECT_TRUE(test, pte_write(*restricted_ptep));

	/*
	 * Check that vmap creates an equal writeable mapping in the vmalloc
	 * address space in both the restricted and unrestricted page tables.
	 */
	vaddr = (unsigned long)do_vmap(test, &page, 1, VM_MAP, PAGE_KERNEL);
	ptep = lookup_address(vaddr, &level);
	KUNIT_ASSERT_NOT_NULL(test, ptep);

	restricted_ptep = lookup_address_asi_global(vaddr, &level);
	KUNIT_ASSERT_NOT_NULL(test, restricted_ptep);

	KUNIT_EXPECT_EQ(test, pte_val(*restricted_ptep), pte_val(*ptep));
	KUNIT_EXPECT_TRUE(test, pte_write(*restricted_ptep));

	/*
	 * Set the memory to RO again using the vmap address. The same
	 * operations should apply to the direct map aliases as well.
	 */
	set_memory_ro(vaddr, 1);

	/* Check that the vmap mappings are still equal, but are now RO */
	ptep = lookup_address(vaddr, &level);
	KUNIT_ASSERT_NOT_NULL(test, ptep);

	restricted_ptep = lookup_address_asi_global(vaddr, &level);
	KUNIT_ASSERT_NOT_NULL(test, restricted_ptep);

	KUNIT_EXPECT_EQ(test, pte_val(*restricted_ptep), pte_val(*ptep));
	KUNIT_EXPECT_FALSE(test, pte_write(*restricted_ptep));

	/* Check that direct map mappings are still equal, but are now RO */
	ptep = lookup_address(laddr, &level);
	KUNIT_ASSERT_NOT_NULL(test, ptep);

	restricted_ptep = lookup_address_asi_global(laddr, &level);
	KUNIT_ASSERT_NOT_NULL(test, restricted_ptep);

	KUNIT_EXPECT_EQ(test, pte_val(*restricted_ptep), pte_val(*ptep));
	KUNIT_EXPECT_FALSE(test, pte_write(*restricted_ptep));

	/*
	 * Reset the mappings to RW as some debug code on the page free path
	 * writes to freed pages to poison them.
	 */
	set_memory_rw(vaddr, 1);
}

/*
 * In more recent kernels with large mappings support in vmalloc (v5.13+), this
 * test can be simplified by using a large vmalloc mapping instead of trying to
 * find an existing large mapping in the direct map.
 */
static void test_change_page_attr_split_mapping(struct kunit *test)
{
	int pmd_order = PMD_SHIFT - PAGE_SHIFT;
	pte_t *ptep, *restricted_ptep;
	unsigned long addr, laddr;
	struct page *page;
	int retries = 100;
	int level;

	kunit_skip(test, "Not yet supported in this branch");

	if (!boot_cpu_has(X86_FEATURE_PSE))
		kunit_skip(test, "Large mappings are not supported by the CPU");

	/*
	 * In probe_page_size_mask(), only small mappings are used in the direct
	 * map if debug_pagealloc_enabled() is true.
	 */
	if (debug_pagealloc_enabled())
		kunit_skip(test, "No large mappings in the direct map");

	/* Try to allocate pages with a large mapping in the direct map */
	do {
		page = do_alloc_pages(test, GFP_KERNEL, pmd_order);
		laddr = (unsigned long)page_to_virt(page);
		ptep = lookup_address(laddr, &level);
		KUNIT_ASSERT_NOT_NULL(test, ptep);

		if (level < PG_LEVEL_2M)
			continue;

		/*
		 * Check that the allocated pages have a large mapping in the
		 * ASI page tables as well.  ASI may use 4K mappings even if the
		 * direct map has a 2M mapping if the PMD was already pointing
		 * at a PTEs page as we never free page table pages in ASI.
		 */
		restricted_ptep = lookup_address_asi_global(laddr, &level);
		KUNIT_ASSERT_NOT_NULL(test, restricted_ptep);
		if (level >= PG_LEVEL_2M)
			break;
	} while (--retries);

	if (level < PG_LEVEL_2M)
		kunit_skip(test, "Could not find pages with a large mapping");

	/*
	 * Split the mappings into 4K mappings, and check that they are
	 * equivalent in both the restricted and unrestricted page tables.
	 */
	set_memory_4k(laddr, 1 << pmd_order);
	for (addr = laddr; addr < laddr + PMD_SIZE; addr += PAGE_SIZE) {
		ptep = lookup_address(addr, &level);
		KUNIT_ASSERT_NOT_NULL(test, ptep);
		KUNIT_EXPECT_EQ(test, level, PG_LEVEL_4K);

		restricted_ptep = lookup_address_asi_global(addr, &level);
		KUNIT_ASSERT_NOT_NULL(test, restricted_ptep);
		KUNIT_EXPECT_EQ(test, level, PG_LEVEL_4K);

		KUNIT_EXPECT_EQ(test, pte_val(*restricted_ptep), pte_val(*ptep));
	}
}

static void test_page_alloc_restricted(struct kunit *test)
{
	struct asi_test_info *info = setup_test_asi(test);
	struct asi *asi = info->asi;
	struct page *page;

	preempt_disable();

	asi_enter(asi);
	asi_relax();

	page = alloc_page(GFP_ATOMIC);
	KUNIT_ASSERT_NOT_NULL(test, page);

	KUNIT_EXPECT_TRUE(test, asi_is_restricted());

	asi_exit(ASI_EXIT_MISC);
	preempt_enable();

	__free_page(page);
}

static void action_free_percpu(void __percpu *ptr)
{
	free_percpu(ptr);
}

static void __percpu *do___alloc_percpu(struct kunit *test, size_t sz, size_t align)
{
	void __percpu *pcpu;
	int r;

	pcpu = __alloc_percpu(sz, align);
	KUNIT_ASSERT_NOT_NULL(test, pcpu);

	r = kunit_add_action_or_reset(test, action_free_percpu, pcpu);
	KUNIT_ASSERT_EQ(test, r, 0);

	return pcpu;
}

static DEFINE_PER_CPU(uint64_t, static_percpu_data);
#define DYNAMIC_PCPU_BUF_SZ	(PAGE_SIZE * 2)

/*
 * Verify that statically allocated percpu memory and dynamically
 * allocated percpu memory are mapped in the restricted address space.
 */
static void test_percpu_alloc(struct kunit *test)
{
	struct asi *asi = ASI_GLOBAL_NONSENSITIVE;
	pgd_t *unrestricted_pgd = init_mm.pgd;
	pgd_t *restricted_pgd = asi->pgd;
	uint64_t __percpu *dynamic_pcpu;
	uint64_t test_end_offset = 8;
	uint64_t base, end;
	int cpu;

	BUILD_BUG_ON(test_end_offset > DYNAMIC_PCPU_BUF_SZ);

	dynamic_pcpu = do___alloc_percpu(test, DYNAMIC_PCPU_BUF_SZ, PAGE_SIZE);
	for_each_possible_cpu(cpu) {
		/* Test statically allocated per-cpu data */
		base = (uint64_t)per_cpu_ptr(&static_percpu_data, cpu);

		KUNIT_EXPECT_TRUE(test, addr_present(unrestricted_pgd, base));
		KUNIT_EXPECT_TRUE(test, addr_present(restricted_pgd, base));

		/* Test dynamically allocated per-cpu data */
		base = (uint64_t)per_cpu_ptr(dynamic_pcpu, cpu);
		end = base + DYNAMIC_PCPU_BUF_SZ - test_end_offset;

		KUNIT_EXPECT_TRUE(test, addr_present(unrestricted_pgd, base));
		KUNIT_EXPECT_TRUE(test, addr_present(unrestricted_pgd, end));
		KUNIT_EXPECT_TRUE(test, addr_present(restricted_pgd, base));
		KUNIT_EXPECT_TRUE(test, addr_present(restricted_pgd, end));
	}
}

/*******************************************************************************
 * ASI Interrupts
 *
 * Test ASI interaction with interrupts received while in different states.
 ******************************************************************************/
static bool *sensitive_data;
static bool intr_handled;

static int asi_nmi_handler(unsigned int val, struct pt_regs *regs)
{
	/*
	 * Store an "expected value" (sensitive) into an "expected
	 * variable" (non sensitive) as a way to detect the interrupt
	 * has been served.
	 */
	WRITE_ONCE(intr_handled, *sensitive_data);

	return NMI_HANDLED;
}

static void test_asi_intr(struct kunit *test)
{
	struct asi_test_info *info = setup_test_asi(test);
	struct page *sensitive_page;
	struct asi *asi = info->asi;
	int64_t init_pf_exits;
	int test_cpu;

	/* Setup: data for the intr handler to be read from sensitive memory. */
	sensitive_page = do_alloc_pages(test, GFP_KERNEL | __GFP_SENSITIVE, 0);
	sensitive_data = (bool *)page_address(sensitive_page);
	WRITE_ONCE(*sensitive_data, true);

	/* Setup: interrupt handler to read from sensitive memory. */
	register_nmi_handler(NMI_UNKNOWN, asi_nmi_handler, 0, "asi-test-intr");
	test_cpu = get_cpu();
	init_pf_exits = asi_cpu_stat(test_cpu, (int)ASI_EXIT_PAGE_FAULT);
	/* Case 1: Interrupt while in critical section... */
	asi_enter(asi);
	KUNIT_EXPECT_TRUE(test, asi_is_restricted());
	test_cpu = smp_processor_id();

	WRITE_ONCE(intr_handled, false);
	barrier();
	apic->send_IPI_mask(cpumask_of(test_cpu), NMI_VECTOR);
	while (!READ_ONCE(intr_handled))
		cpu_relax();

	/* ... on return must remain in the critical section. */
	KUNIT_EXPECT_TRUE(test, asi_is_restricted());
	KUNIT_EXPECT_TRUE(test, asi_in_critical_section());
	KUNIT_EXPECT_GE(test, asi_cpu_stat(test_cpu, (int)ASI_EXIT_PAGE_FAULT) - init_pf_exits, 1);

	/* Case 2: Interrupt outside the critical section... */
	asi_relax();

	WRITE_ONCE(intr_handled, false);
	barrier();
	apic->send_IPI_mask(cpumask_of(test_cpu), NMI_VECTOR);
	while (!READ_ONCE(intr_handled))
		cpu_relax();

	/* ... on return do not re-enter the critical section. */
	KUNIT_EXPECT_FALSE(test, asi_is_restricted());
	KUNIT_EXPECT_FALSE(test, asi_in_critical_section());
	KUNIT_EXPECT_GE(test, asi_cpu_stat(test_cpu, (int)ASI_EXIT_PAGE_FAULT) - init_pf_exits, 2);

	put_cpu();
	unregister_nmi_handler(NMI_UNKNOWN, "asi-test-intr");
}

#define NMI_ACTIVE -2
static int nmi_cpu;
static int nmi_level;
static bool nmi_handled;
static bool nmi_exit_is_restricted;

static int asi_nested_nmi_handler(unsigned int val, struct pt_regs *regs)
{
	/*
	 * This NMI handler can be called by any random NMI.
	 * Do nothing when not scheduled by the asi IRQ work.
	 * This still leaves a tiny race condition, in case another NMI should
	 * come in before we latch the NMI level in the next instruction.
	 * In any case, we still expect the first NMI to pass this check to
	 * latch a nesting level greater than the IRQ work one.
	 */
	if (READ_ONCE(nmi_level) != NMI_ACTIVE)
		return NMI_DONE;
	WRITE_ONCE(nmi_level, asi_intr_nest_depth());
	WRITE_ONCE(nmi_cpu, smp_processor_id());

	/*
	 * Store an "expected value" (sensitive) into an "expected
	 * variable" (non sensitive) as a way to detect the interrupt
	 * has been served.
	 * This is also expected to generate an ASI exit which will have to be
	 * persistent until we re-enter the critical section.
	 */
	WRITE_ONCE(nmi_handled, *sensitive_data);
	WRITE_ONCE(nmi_exit_is_restricted, asi_is_restricted());

	return NMI_HANDLED;
}

static struct irq_work asi_iw;
static int iw_cpu;
static int iw_level;
static bool iw_exit_is_restricted;
static bool iw_entry_is_restricted;

static void asi_iw_handler(struct irq_work *iw)
{
	int test_cpu = smp_processor_id();

	/*
	 * Keep track of system and ASI status. Note, these are global variables
	 * thus we expect them mapped in the restricted domain, i.e. no ASI
	 * exit is expected to be triggered by these memory accesses.
	 */
	WRITE_ONCE(iw_level, asi_intr_nest_depth());
	WRITE_ONCE(iw_cpu, smp_processor_id());
	WRITE_ONCE(iw_entry_is_restricted, asi_is_restricted());

	/*
	 * Set the tokens expected by the NMI handler. Do that to ensure
	 * the NMI handler will capture the metrics only when scheduled by asi.
	 */
	WRITE_ONCE(nmi_level, NMI_ACTIVE);
	barrier();

	/* Generate an NMI on same CPU to nest the source interrupt. */
	apic->send_IPI_mask(cpumask_of(test_cpu), NMI_VECTOR);

	/*
	 * An IRQ work is expected to be fast. However, for the scope of this
	 * test, busy loop waiting for a (nested) NMI to come in and unlock us.
	 */
	while (READ_ONCE(nmi_level) <= iw_level)
		cpu_relax();

	/*
	 * Keep track of ASI status before returning. We expect the (nested)
	 * NMI triggered an ASI exit and we do not return the restricted address
	 * space before continuing the critical section.
	 */
	WRITE_ONCE(iw_exit_is_restricted, asi_is_restricted());
}

static void test_asi_intr_nesting(struct kunit *test)
{
	struct asi_test_info *info = setup_test_asi(test);
	struct page *sensitive_page;
	struct asi *asi = info->asi;

	/* Setup: data for the intr handler to be read from sensitive memory. */
	sensitive_page = do_alloc_pages(test, GFP_KERNEL | __GFP_SENSITIVE, 0);
	sensitive_data = (bool *)page_address(sensitive_page);
	*sensitive_data = true;

	/* Setup: Level2: NMI handler to read from sensitive memory. */
	register_nmi_handler(NMI_UNKNOWN, asi_nested_nmi_handler, 0,
			     "asi-test-nmi");

	/* Setup: Level1: IRQ handler to generate a nested interrupt. */
	asi_iw = IRQ_WORK_INIT_HARD(asi_iw_handler);
	WRITE_ONCE(iw_level, -1);
	WRITE_ONCE(iw_cpu, -1);

	/* Critical section start: switch to restricted domain. */
	preempt_disable();
	asi_enter(asi);
	KUNIT_EXPECT_TRUE(test, asi_is_restricted());

	/* Level1: schedule IRQ work (on this CPU) and wait for NMI. */
	WRITE_ONCE(nmi_handled, false);
	barrier();
	irq_work_queue(&asi_iw);
	while (!READ_ONCE(nmi_handled))
		cpu_relax();

	/* Test: NMI interrupt nested into IRQ Work interrupt. */
	KUNIT_EXPECT_EQ(test, READ_ONCE(iw_cpu), READ_ONCE(nmi_cpu));
	KUNIT_EXPECT_GE(test, READ_ONCE(iw_level), 1);
	KUNIT_EXPECT_LT(test, READ_ONCE(iw_level), READ_ONCE(nmi_level));

	/* Test: Can handle page faults from arbitrary IRQs nesting depth. */
	KUNIT_EXPECT_TRUE(test, READ_ONCE(iw_entry_is_restricted));
	KUNIT_EXPECT_FALSE(test, READ_ONCE(nmi_exit_is_restricted));

	/* Test: Return to restricted domain only on critical section return. */
	KUNIT_EXPECT_FALSE(test, READ_ONCE(iw_exit_is_restricted));
	KUNIT_EXPECT_TRUE(test, asi_is_restricted());
	KUNIT_EXPECT_TRUE(test, asi_in_critical_section());

	/* Critical section end: switch back to unrestricted domain. */
	asi_relax();
	asi_exit(ASI_EXIT_MISC);
	preempt_enable();
	unregister_nmi_handler(NMI_UNKNOWN, "asi-test-nmi");
}

static void test_alloc_pages_sensitivity(struct kunit *test)
{
	pgd_t *restricted_pgd = asi_pgd(ASI_GLOBAL_NONSENSITIVE);
	struct page *page_s = do_alloc_pages(test, GFP_KERNEL | __GFP_SENSITIVE, 0);
	struct page *page_ns = do_alloc_pages(test, GFP_KERNEL, 0);

	KUNIT_EXPECT_FALSE(test, addr_present(restricted_pgd,
			  (unsigned long)page_to_virt(page_s)));
	KUNIT_EXPECT_TRUE(test, addr_present(restricted_pgd,
			  (unsigned long)page_to_virt(page_ns)));
}

static struct kunit_case asi_test_cases[] = {
	KUNIT_CASE(test_asi_state),
	KUNIT_CASE_PARAM(test_asi_tainting, asi_tainting_gen_params),
	KUNIT_CASE(test_asi_map_global_nonsensitive),
	KUNIT_CASE(test_alloc_pages_sensitivity),
	KUNIT_CASE(test_percpu_alloc),
	KUNIT_CASE(test_change_page_attr),
	KUNIT_CASE(test_change_page_attr_split_mapping),
	KUNIT_CASE(test_asi_intr),
	KUNIT_CASE(test_asi_intr_nesting),
	KUNIT_CASE(test_page_alloc_restricted),
	{}
};

static unsigned long taint_pre;

static int store_taint_pre(struct kunit *test)
{
	taint_pre = get_taint();
	return 0;
}

static void check_taint_post(struct kunit *test)
{
	unsigned long new_taint = get_taint() & ~taint_pre;

	KUNIT_EXPECT_EQ_MSG(test, new_taint, 0,
		"Kernel newly tainted after test. Maybe a WARN?");
}

static struct kunit_suite asi_test_suite = {
	.name = "asi",
	.init = store_taint_pre,
	.exit = check_taint_post,
	.test_cases = asi_test_cases,
};

kunit_test_suite(asi_test_suite);

MODULE_LICENSE("GPL");
MODULE_IMPORT_NS(EXPORTED_FOR_KUNIT_TESTING);
