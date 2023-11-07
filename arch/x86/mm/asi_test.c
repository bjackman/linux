/* SPDX-License-Identifier: GPL-2.0-only */
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

#include <asm/asi.h>

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

	info->mm = mm_alloc();
	KUNIT_ASSERT_NOT_NULL(test, info->mm);
	kunit_add_action(test, action_mmdrop, info->mm);
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

	asi_exit();
	KUNIT_EXPECT_FALSE(test, asi_is_restricted());
	KUNIT_EXPECT_TRUE(test, asi_is_relaxed());

	preempt_enable();
}

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

/* Is this page present in the physmap? */
static bool page_present_phys(struct kunit *test, pgd_t *pgd, struct page *page)
{
	unsigned int level;
	unsigned long addr = (unsigned long)page_address(page);
	pte_t *pte = lookup_address_in_pgd(pgd_offset_pgd(pgd, addr), addr, &level);

	if (!pte)
		return false;

	switch (level) {
	case PG_LEVEL_4K:
		return pte_flags(*pte) & _PAGE_PRESENT;
	case PG_LEVEL_2M:
		return pmd_flags(*(pmd_t *)pte) & _PAGE_PRESENT;
	case PG_LEVEL_1G:
		return pud_flags(*(pud_t *)pte) & _PAGE_PRESENT;
	case PG_LEVEL_512G:
		/* Assuming this is the same regardless of la57... */
		return p4d_flags(*(p4d_t *)pte) & _PAGE_PRESENT;
	case PG_LEVEL_256T:
		return pgd_flags(*(pgd_t *)pte) & _PAGE_PRESENT;
	default:
		KUNIT_FAIL_AND_ABORT(test, "Unknown pagetable level %d\n", level);
	}
}

/* This is a very minimal smoke test. */
static void test_alloc_sensitive_nonsensitive(struct kunit *test)
{
	struct page *page_sensitive, *page_nonsensitive;
	pgd_t *restricted_pgd, *unrestricted_pgd;

	if (!static_cpu_has(X86_FEATURE_ASI))
		kunit_skip(test, "ASI disabled. Set asi=on to test\n");

	page_sensitive = do_alloc_pages(test, GFP_KERNEL | __GFP_SENSITIVE, 0);
	page_nonsensitive = do_alloc_pages(test, GFP_KERNEL, 0);
	restricted_pgd = asi_pgd(ASI_GLOBAL_NONSENSITIVE);
	unrestricted_pgd = init_mm.pgd;

	KUNIT_EXPECT_TRUE(test, page_present_phys(test, unrestricted_pgd, page_sensitive));
	KUNIT_EXPECT_TRUE(test, page_present_phys(test, unrestricted_pgd, page_nonsensitive));
	KUNIT_EXPECT_FALSE(test, page_present_phys(test, restricted_pgd, page_sensitive));
	KUNIT_EXPECT_TRUE(test, page_present_phys(test, restricted_pgd, page_nonsensitive));
}

static struct kunit_case asi_test_cases[] = {
	KUNIT_CASE(test_asi_state),
	KUNIT_CASE(test_alloc_sensitive_nonsensitive),
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
MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");
