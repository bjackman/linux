// SPDX-License-Identifier: GPL-2.0-only
#include <linux/asi.h>
#include <linux/errname.h>
#include <linux/list.h>
#include <linux/gfp.h>
#include <linux/memory.h>
#include <linux/memory_hotplug.h>
#include <linux/nodemask.h>
#include <linux/percpu.h>
#include <linux/smp.h>

#include <kunit/test.h>

#include "internal.h"

#define EXPECT_PCPLIST_EMPTY(test, zone, cpu, pindex) ({			\
	struct per_cpu_pages *pcp = per_cpu_ptr(zone->per_cpu_pageset, cpu);	\
	struct page *page;							\
										\
	lockdep_assert_held(&pcp->lock);					\
	page = list_first_entry_or_null(					\
		&pcp->lists[pindex], struct page, pcp_list);			\
										\
	if (page) {								\
		KUNIT_FAIL(test, "PCPlist %d on CPU %d wasn't empty", i, cpu);	\
		dump_page(page, "unexpectedly on pcplist");			\
	}									\
})

#define EXPECT_WITHIN_ZONE(test, page, zone) ({					\
	unsigned long pfn = page_to_pfn(page);					\
	unsigned long start_pfn = zone->zone_start_pfn;				\
	unsigned long end_pfn = start_pfn + zone->spanned_pages;		\
										\
	KUNIT_EXPECT_TRUE_MSG(test,						\
		pfn >= start_pfn && pfn < end_pfn,				\
		"Wanted PFN 0x%lx - 0x%lx, got 0x%lx",				\
		start_pfn, end_pfn, pfn);					\
	KUNIT_EXPECT_PTR_EQ_MSG(test, page_zone(page), zone,			\
		"Wanted %px (%s), got %px (%s)",				\
		zone, zone->name, page_zone(page), page_zone(page)->name);	\
})

static void action_nodemask_free(void *ctx)
{
	NODEMASK_FREE(ctx);
}

/*
 * Call __alloc_pages_noprof with a nodemask containing only the nid.
 *
 * Never returns NULL.
 */
static inline struct page *alloc_pages_force_nid(struct kunit *test,
						 gfp_t gfp, int order, int nid)
{
	NODEMASK_ALLOC(nodemask_t, nodemask, GFP_KERNEL);
	struct page *page;

	KUNIT_ASSERT_NOT_NULL(test, nodemask);
	kunit_add_action(test, action_nodemask_free, &nodemask);
	nodes_clear(*nodemask);
	node_set(nid, *nodemask);

	page = __alloc_pages_noprof(gfp, order, nid, nodemask);
	KUNIT_ASSERT_NOT_NULL(test, page);
	return page;
}

static inline bool page_on_buddy_list(struct page *want_page, struct list_head *head)
{
	struct page *found_page;

	list_for_each_entry(found_page, head, buddy_list) {
		if (found_page == want_page)
			return true;
	}

	return false;
}

/* Test case parameters that are independent of alloc order.  */
static const struct {
	gfp_t gfp_flags;
	enum zone_type want_zone;
	int want_migratetype;
} alloc_fresh_gfps[] = {
	/*
	 * The way we currently set up the isolated node, everything ends up in
	 * ZONE_NORMAL.
	 */
	{
		.gfp_flags = GFP_KERNEL,
		.want_zone = ZONE_NORMAL,
		.want_migratetype = MIGRATE_UNMOVABLE_NONSENSITIVE
	},
	{
		.gfp_flags = GFP_ATOMIC,
		.want_zone = ZONE_NORMAL,
		.want_migratetype =  MIGRATE_UNMOVABLE_NONSENSITIVE
	},
	{
		.gfp_flags = GFP_USER,
		.want_zone = ZONE_NORMAL,
		.want_migratetype =  MIGRATE_UNMOVABLE_SENSITIVE
	},
};

struct alloc_fresh_test_case {
	int order;
	int gfp_idx;
};

/* Generate test cases as the cross product of orders and alloc_fresh_gfps.  */
static const void *alloc_fresh_gen_params(const void *prev, char *desc)
{
	/* Buffer to avoid allocations. */
	static struct alloc_fresh_test_case tc;

	if (!prev) {
		/* First call */
		tc.order = 0;
		tc.gfp_idx = 0;
		goto out;
	}

	tc.gfp_idx++;
	if (tc.gfp_idx >= ARRAY_SIZE(alloc_fresh_gfps)) {
		tc.gfp_idx = 0;
		tc.order++;
	}
	if (tc.order > MAX_PAGE_ORDER)
		/* Finished. */
		return NULL;

out:
	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "order %d %pGg\n",
		tc.order, &alloc_fresh_gfps[tc.gfp_idx].gfp_flags);
	return &tc;
}

/* Smoke test: allocate from a node where everything is in a pristine state. */
static void test_alloc_fresh(struct kunit *test)
{
	const struct alloc_fresh_test_case *tc = test->param_value;
	gfp_t gfp_flags = alloc_fresh_gfps[tc->gfp_idx].gfp_flags;
	enum zone_type want_zone_type = alloc_fresh_gfps[tc->gfp_idx].want_zone;
	enum zone_type want_migratetype = alloc_fresh_gfps[tc->gfp_idx].want_migratetype;
	struct zone *want_zone = &NODE_DATA(isolated_node)->node_zones[want_zone_type];
	struct free_area *free_area = &want_zone->free_area[MAX_PAGE_ORDER];
	struct list_head *buddy_list;
	struct per_cpu_pages *pcp;
	struct page *page, *merged_page;
	int cpu, i;

	page = alloc_pages_force_nid(test, gfp_flags, tc->order, isolated_node);

	KUNIT_EXPECT_FALSE(test, PageBuddy(page));

	EXPECT_WITHIN_ZONE(test, page, want_zone);

	cpu = get_cpu();
	__free_pages(page, tc->order);
	pcp = per_cpu_ptr(want_zone->per_cpu_pageset, cpu);
	put_cpu();

	/*
	 * Should end up back in the free area when drained. Because everything
	 * is free, it should get buddy-merged up to the maximum order.
	 */
	drain_pages_zone(cpu, want_zone);
	KUNIT_EXPECT_TRUE(test, PageBuddy(page));
	KUNIT_EXPECT_EQ(test, buddy_order(page), MAX_PAGE_ORDER);
	for (i = 0; i < ARRAY_SIZE(pcp->lists); i++)
		KUNIT_EXPECT_TRUE_MSG(test, list_empty(&pcp->lists[i]),
			"pcplist %d not empty", i);
	merged_page = pfn_to_page(round_down(page_to_pfn(page), 1 << MAX_PAGE_ORDER));
	buddy_list = &free_area->free_list[want_migratetype];
	KUNIT_EXPECT_TRUE(test, page_on_buddy_list(merged_page, buddy_list));
}

#ifdef CONFIG_MITIGATION_ADDRESS_SPACE_ISOLATION

enum asi_mapped_state {
	/* Concrete values used for convenient cast from bool. */
	ASI_UNMAPPED = 0,
	ASI_MAPPED = 1,
	ASI_MIXED,
};

static enum asi_mapped_state pte_asi_state(struct kunit *test, pte_t *pte, int level)

{
	if (!pte)
		return ASI_UNMAPPED;

	switch (level) {
	case PG_LEVEL_4K:
		fallthrough;
	case PG_LEVEL_2M:
		/*
		 * Check _PAGE_PRESENT specifically as {pte,pmd}_present also
		 * consider _PAGE_PROTNONE to be "present".
		 */
		return !!(pte_flags(*pte) & _PAGE_PRESENT);
	/* Not necessarily wrong, but unexpected, better investigate. */
	default:
		KUNIT_FAIL_AND_ABORT(test, "page level not implemented in test harness");
	}
}

static enum asi_mapped_state region_asi_state(struct kunit *test, unsigned long addr, size_t size)
{
	pgd_t *pgd = pgd_offset_pgd(asi_pgd(ASI_GLOBAL_NONSENSITIVE), addr);
	int level;
	pte_t *pte = lookup_pgtable_in_pgd(pgd, addr, &level);
	enum asi_mapped_state base_mapped = pte_asi_state(test, pte, level);
	unsigned long base_addr = addr;

	addr += page_level_size(level);
	while (addr < (base_addr + size)) {
		enum asi_mapped_state mapped;

		pte = lookup_pgtable_in_pgd(pgd, addr, &level);
		mapped = pte_asi_state(test, pte, level);

		if (mapped != base_mapped)
			return ASI_MIXED;

		addr += page_level_size(level);
	}

	return base_mapped;
}

struct sensitivity_test_case {
	int order;
	const char *desc;
	gfp_t gfp;
	enum asi_mapped_state want_mapped;
};

const struct sensitivity_test_case sensitivity_test_cases[] = {
	{
		.order = 0,
		.desc = "default (nonsensitive), order=0",
		.gfp = GFP_KERNEL,
		.want_mapped = ASI_MAPPED,
	},
	{
		.order = 0,
		.desc = "sensitive, order=0",
		.gfp = GFP_KERNEL | __GFP_SENSITIVE,
		.want_mapped = ASI_UNMAPPED,
	},
	{
		.order = 1,
		.desc = "default (nonsensitive), order=1",
		.gfp = GFP_KERNEL,
		.want_mapped = ASI_MAPPED,
	},
	{
		.order = pageblock_order,
		.desc = "default (nonsensitive), order=pageblock_order",
		.gfp = GFP_KERNEL,
		.want_mapped = ASI_MAPPED,
	},
	{
		.order = pageblock_order,
		.desc = "sensitive, order=pageblock_order",
		.gfp = GFP_KERNEL | __GFP_SENSITIVE,
		.want_mapped = ASI_UNMAPPED,
	},
	{
		.order = MAX_PAGE_ORDER,
		.desc = "default (nonsensitive), order=MAX_PAGE_ORDER",
		.gfp = GFP_KERNEL,
		.want_mapped = ASI_MAPPED,
	},
	{
		.order = MAX_PAGE_ORDER,
		.desc = "sensitive, order=MAX_PAGE_ORDER",
		.gfp = GFP_KERNEL | __GFP_SENSITIVE,
		.want_mapped = ASI_UNMAPPED,
	}
};
KUNIT_ARRAY_PARAM_DESC(sensitivity, sensitivity_test_cases, desc);

/* Allocate a page, the sensitivity flag should be respected. */
static void test_alloc_sensitivity(struct kunit *test)
{
	struct sensitivity_test_case *tc = (struct sensitivity_test_case *)test->param_value;
	struct page *page = alloc_pages_force_nid(test, tc->gfp, tc->order, isolated_node);

	KUNIT_ASSERT_NOT_NULL(test, page);

	KUNIT_EXPECT_EQ(test,
			region_asi_state(test, (unsigned long)page_to_virt(page),
					 PAGE_SIZE  << tc->order),
			tc->want_mapped);
	if (test->status == KUNIT_FAILURE)
		dump_page(page, "test failed");

	__free_pages(page, tc->order);
}

static void action_free_contig_range(void *ctx)
{
	pg_data_t *node = (pg_data_t *)ctx;
	unsigned long start_pfn = node->node_start_pfn;

	free_contig_range(start_pfn, node->node_spanned_pages);
}

/*
 * Allocate the whole node. Return an already-registered KUnit action to free
 * everything again. The action's context is the node.
 */
static noinline kunit_action_t *alloc_all_pages(struct kunit *test, gfp_t gfp_flags,
						pg_data_t *node)
{
	unsigned long start_pfn = node->node_start_pfn;
	/* There should be no holes in this node. */
	unsigned long end_pfn = start_pfn + node->node_spanned_pages;
	unsigned long pfn;
	int migratetype;
	int err;

	if (gfp_flags & __GFP_SENSITIVE)
		migratetype = MIGRATE_MOVABLE;
	else
		migratetype = MIGRATE_UNMOVABLE_NONSENSITIVE;

	err = alloc_contig_range(start_pfn, end_pfn, migratetype, gfp_flags);
	KUNIT_ASSERT_EQ(test, err, 0);
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(test, action_free_contig_range, node), 0);
	/* Cautious sanity-check */
	for (pfn = start_pfn; pfn < end_pfn; pfn += pageblock_nr_pages)
		KUNIT_ASSERT_EQ(test, get_pageblock_migratetype(pfn_to_page(pfn)), migratetype);

	return action_free_contig_range;
}

/*
 * First, allocate every page in the zone with the inverse of the requested
 * sensitivity. Then, allocate the page itself and check the sensitivity is
 * respected. This should force pages to be flipped between sensitivities.
 */
static void test_alloc_sensitivity_drain(struct kunit *test)
{
	struct sensitivity_test_case *tc = (struct sensitivity_test_case *)test->param_value;
	struct page *page;
	enum asi_mapped_state state;
	pg_data_t *node = NODE_DATA(isolated_node);
	unsigned long node_start_addr = (unsigned long)pfn_to_kaddr(node->node_start_pfn);
	size_t node_span = node->node_spanned_pages << PAGE_SHIFT;
	enum asi_mapped_state want_mapped_opposite;
	kunit_action_t *free_pages_action;

	if (tc->want_mapped == ASI_MAPPED)
		want_mapped_opposite = ASI_UNMAPPED;
	else
		want_mapped_opposite = ASI_MAPPED;

	/* Allocate everything with the inverse sensitivity. */
	free_pages_action = alloc_all_pages(test, tc->gfp ^ __GFP_SENSITIVE, node);

	/*
	 * Check everything reached the excepted sensitivity. There are no holes
	 * in the fake node.
	 */
	state = region_asi_state(test, node_start_addr, node_span);
	KUNIT_EXPECT_EQ(test, state, want_mapped_opposite);

	/* Free everything again. */
	kunit_release_action(test, free_pages_action, node);

	/*
	 * At present we don't expect freeing the pages to change any mapping.
	 * In the future, it totally could, but for now just assert to avoid
	 * confusion.
	 */
	state = region_asi_state(test, node_start_addr, node_span);
	KUNIT_EXPECT_EQ(test, state, want_mapped_opposite);

	page = alloc_pages_force_nid(test, tc->gfp, tc->order, isolated_node);
	KUNIT_ASSERT_NOT_NULL(test, page);
	KUNIT_EXPECT_EQ(test,
			region_asi_state(test, (unsigned long)page_to_virt(page),
					 tc->order << PAGE_SHIFT),
			tc->want_mapped);
	__free_pages(page, tc->order);
}

#endif /* CONFIG_MITIGATION_ADDRESS_SPACE_ISOLATION */

static void action_drain_pages_all(void *unused)
{
	int cpu;

	for_each_online_cpu(cpu)
		drain_pages(cpu);
}

/* Runs before each test. */
static int test_init(struct kunit *test)
{
	struct zone *zone_normal;
	int cpu;

	if (isolated_node == NUMA_NO_NODE)
		kunit_skip(test, "No fake NUMA node ID allocated");

	zone_normal = &NODE_DATA(isolated_node)->node_zones[ZONE_NORMAL];

	/*
	 * Nothing except these tests should be allocating from the fake node so
	 * the pcplists should be empty. Obviously this is racy but at least it
	 * can probabilistically detect issues that would otherwise make for
	 * really confusing test results.
	 */
	for_each_possible_cpu(cpu) {
		struct per_cpu_pages *pcp = per_cpu_ptr(zone_normal->per_cpu_pageset, cpu);
		unsigned long flags;
		int i;

		spin_lock_irqsave(&pcp->lock, flags);
		for (i = 0; i < ARRAY_SIZE(pcp->lists); i++)
			EXPECT_PCPLIST_EMPTY(test, zone_normal, cpu, i);
		spin_unlock_irqrestore(&pcp->lock, flags);
	}

	/* Also ensure we don't leave a mess for the next test. */
	kunit_add_action(test, action_drain_pages_all, NULL);

	return 0;
}

static int memory_block_online_cb(struct memory_block *mem, void *unused)
{
	return memory_block_online(mem);
}

struct region {
	int node;
	unsigned long start;
	unsigned long size;
};

/*
 * Unplug some memory from a "real" node and plug it into the isolated node, for
 * use during the tests.
 */
static int populate_isolated_node(struct kunit_suite *suite)
{
	struct zone *zone_movable = &NODE_DATA(0)->node_zones[ZONE_MOVABLE];
	phys_addr_t zone_start = zone_movable->zone_start_pfn << PAGE_SHIFT;
	phys_addr_t zone_size = zone_movable->spanned_pages << PAGE_SHIFT;
	unsigned long bs = memory_block_size_bytes();
	u64 start = round_up(zone_start, bs);
	/* Plug a memory block if we can find it. */
	unsigned long size = round_down(min(zone_size, bs), bs);
	int err;

	if (!size) {
		pr_err("Couldn't find ZONE_MOVABLE block to offline\n");
		pr_err("Try setting/expanding movablecore=\n");
		return -1;
	}

	err = offline_and_remove_memory(start, size);
	if (err) {
		pr_notice("Couldn't offline PFNs 0x%llx - 0x%llx\n",
			start >> PAGE_SHIFT, (start + size) >> PAGE_SHIFT);
		return err;
	}
	err = add_memory(isolated_node, start, size, MMOP_ONLINE);
	if (err) {
		pr_notice("Couldn't add PFNs 0x%llx - 0x%llx\n",
			start >> PAGE_SHIFT, (start + size) >> PAGE_SHIFT);
		goto add_and_online_memory;
	}
	err = walk_memory_blocks(start, size, NULL, memory_block_online_cb);
	if (err) {
		pr_notice("Couldn't online PFNs 0x%llx - 0x%llx\n",
			start >> PAGE_SHIFT, (start + size) >> PAGE_SHIFT);
		goto remove_memory;
	}

	return 0;

remove_memory:
	if (WARN_ON(remove_memory(start, size)))
		return err;
add_and_online_memory:
	if (WARN_ON(add_memory(0, start, size, MMOP_ONLINE)))
		return err;
	WARN_ON(walk_memory_blocks(start, size, NULL, memory_block_online_cb));
	return err;
}

static void depopulate_isolated_node(struct kunit_suite *suite)
{
	unsigned long start, size = memory_block_size_bytes();

	if (suite->suite_init_err)
		return;

	start = NODE_DATA(isolated_node)->node_start_pfn << PAGE_SHIFT;

	WARN_ON(remove_memory(start, size));
	WARN_ON(add_memory(0, start, size, MMOP_ONLINE));
	WARN_ON(walk_memory_blocks(start, size, NULL, memory_block_online_cb));
}

static struct kunit_case test_cases[] = {
	KUNIT_CASE_PARAM(test_alloc_fresh, alloc_fresh_gen_params),
#ifdef CONFIG_MITIGATION_ADDRESS_SPACE_ISOLATION
	KUNIT_CASE_PARAM(test_alloc_sensitivity, sensitivity_gen_params),
	KUNIT_CASE_PARAM(test_alloc_sensitivity_drain, sensitivity_gen_params),
#endif /* CONFIG_MITIGATION_ADDRESS_SPACE_ISOLATION */
	{}
};

struct kunit_suite page_alloc_test_suite = {
	.name = "page_alloc",
	.test_cases = test_cases,
	.suite_init = populate_isolated_node,
	.suite_exit = depopulate_isolated_node,
	.init = test_init,
};
kunit_test_suite(page_alloc_test_suite);

MODULE_LICENSE("GPL");
MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");
