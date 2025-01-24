// SPDX-License-Identifier: GPL-2.0-only
#include <linux/errname.h>
#include <linux/gfp.h>
#include <linux/list.h>
#include <linux/memory_hotplug.h>
#include <linux/memory.h>
#include <linux/mm.h>
#include <linux/mmdebug.h>
#include <linux/mmzone.h>
#include <linux/nodemask.h>
#include <linux/percpu.h>
#include <linux/smp.h>
#include <linux/spinlock.h>

#include <asm/asi.h>

#include <kunit/test.h>

#include "internal.h"

static int memory_block_online_cb(struct memory_block *mem, void *unused)
{
	return memory_block_online(mem);
}

static void action_nodemask_free(void *ctx)
{
	NODEMASK_FREE(ctx);
}

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


#define EXPECT_PCPLIST_EMPTY(test, zone, cpu, pindex) ({			\
	struct per_cpu_pages *pcp = per_cpu_ptr(zone_normal->per_cpu_pageset, cpu); \
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

static inline bool page_on_pcplist(struct page *want_page, struct list_head *head)
{
	struct page *found_page;

	list_for_each_entry(found_page, head, pcp_list) {
		if (found_page == want_page)
			return true;
	}

	return false;
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

static inline const char *debug_list_state(struct list_head *entry)
{
	if (list_empty(entry))
		return "empty";
	else if (entry->next == LIST_POISON1 && entry->prev == LIST_POISON2)
		return "deleted";
	else
		return "on list?";
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

	page = __alloc_pages_noprof(GFP_KERNEL, 0, nid, nodemask);
	KUNIT_ASSERT_NOT_NULL(test, page);
	return page;
}

static void test_alloc(struct kunit *test)
{
	int fake_nid = get_kunit_isolated_nid();
	struct list_head *buddy_list;
	struct per_cpu_pages *pcp;
	struct page *page, *merged_page;
	struct zone *zone_normal = &NODE_DATA(fake_nid)->node_zones[ZONE_NORMAL];
	int cpu;

	page = alloc_pages_force_nid(test, GFP_KERNEL, 0, fake_nid);

	/*
	 * For a plain allocation with no memory pressure, it should come from
	 * ZONE_NORMAL.
	 */
	EXPECT_WITHIN_ZONE(test, page, zone_normal);

	/*
	 * Free the page. For a boring alloc like this, while the rest of the
	 * zone is free and the pcplists are empty, it should go onto the
	 * pcplist. This is not exactly a functional requirement itself, but if
	 * it doesn't happen something is messed up.
	 *
	 * TODO: There are asynchronous processes that could cause the page to
	 * get drained to the zonelists and break this assertion. Protect
	 * against that somehow.
	 */

	cpu = get_cpu();
	__free_pages(page, 0);
	pcp = per_cpu_ptr(zone_normal->per_cpu_pageset, cpu);
	KUNIT_EXPECT_TRUE(test, page_on_pcplist(page, &pcp->lists[MIGRATE_UNMOVABLE]));
	put_cpu();

	/*
	 * Should end up back in the free area when drained. Because everything
	 * is free, it should get buddy-merged up to the maximum order.
	 */
	drain_zone_pages(zone_normal, pcp);
	KUNIT_EXPECT_TRUE(test, PageBuddy(page));
	KUNIT_EXPECT_EQ(test, buddy_order(page), MAX_PAGE_ORDER);
	KUNIT_EXPECT_TRUE(test, list_empty(&pcp->lists[MIGRATE_UNMOVABLE]));
	merged_page = pfn_to_page(round_down(page_to_pfn(page), 1 << MAX_PAGE_ORDER));
	buddy_list = &zone_normal->free_area[MAX_PAGE_ORDER].free_list[MIGRATE_UNMOVABLE];
	KUNIT_EXPECT_TRUE(test, page_on_buddy_list(merged_page, buddy_list));

	/* Failures above can be a bit unhelpful so throw some more info over the fence. */
	if (test->status != KUNIT_SUCCESS) {
		printk("lru: %s\n", debug_list_state(&page->lru));
		dump_page(page, "kunit failed (allocated page)");
		printk("lru: %s\n", debug_list_state(&page->lru));
		dump_page(merged_page, "kunit failed (merged page)");
		if (PageBuddy(page)) {
			unsigned long buddy_pfn = __find_buddy_pfn(
				page_to_pfn(page), buddy_order(page));

			dump_page(pfn_to_page(buddy_pfn),
				  "buddy of allocated page");
		}
	}
}

/* Is an order-0 page mapped in the ASI restricted address space? */
static bool is_asi_mapped(struct page *page)
{
	pgd_t *pgd = asi_pgd(ASI_GLOBAL_NONSENSITIVE);
	int level;
	pte_t *pte = lookup_address_in_pgd(pgd, (unsigned long)page_to_virt(page), &level);

	if (!pte)
		return false;

	return pte_present(*pte);
}

static void test_alloc_sensitivity(struct kunit *test)
{
	int fake_nid = get_kunit_isolated_nid();
	struct page *page = alloc_pages_force_nid(test, GFP_KERNEL, 0, fake_nid);

	KUNIT_EXPECT_FALSE(test, is_asi_mapped(page));
}

/*
 * Some basic defensive checking to try and detect mistakes in the test
 * harness.
 */
static int check_preconditions(struct kunit *test)
{
	int fake_nid = get_kunit_isolated_nid();
	struct zone *zone_normal;
	int cpu;

	if (fake_nid == NUMA_NO_NODE)
		kunit_skip(test, "No fake NUMA node ID allocated");

	zone_normal = &NODE_DATA(fake_nid)->node_zones[ZONE_NORMAL];

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
		for (i = 0; i < ARRAY_SIZE(pcp->lists); i++) {
			EXPECT_PCPLIST_EMPTY(test, zone_normal, cpu, i);
		}
		spin_unlock_irqrestore(&pcp->lock, flags);
	}

	return 0;
}

static int plug_fake_node(struct kunit_suite *suite)
{
	struct zone *zone_movable = &NODE_DATA(0)->node_zones[ZONE_MOVABLE];
	phys_addr_t zone_start = zone_movable->zone_start_pfn << PAGE_SHIFT;
	phys_addr_t zone_size = zone_movable->spanned_pages << PAGE_SHIFT;
	u64 start = round_up(zone_start, memory_block_size_bytes());
	/* How big? Unlpugging whole zone seems to fail a lot. So, um, half? */
	unsigned long size = round_down((zone_size / 2) - (start - zone_start),
					memory_block_size_bytes());
	/* TODO: communicate this from numa.c or something. */
	int fake_nid = get_kunit_isolated_nid();
	int err;

	if (!size) {
		pr_err("Couldn't find ZONE_MOVABLE block to offline\n");
		pr_err("Try setting/embiggening movablecore=\n");
		return -1;
	}

	err = offline_and_remove_memory(start, size);
	if (err) {
		pr_notice("Couldn't offline PFNs 0x%llx - 0x%llx\n",
			start >> PAGE_SHIFT, (start + size) >> PAGE_SHIFT);
		return err;
	}
	err = add_memory(fake_nid, start, size, MMOP_ONLINE);
	if (err) {
		pr_notice("Couldn't add PFNs 0x%llx - 0x%llx\n",
			start >> PAGE_SHIFT, (start + size) >> PAGE_SHIFT);
		return err;
	}
	err = walk_memory_blocks(start, size, NULL, memory_block_online_cb);
	if (err) {
		pr_notice("Couldn't online PFNs 0x%llx - 0x%llx\n",
			start >> PAGE_SHIFT, (start + size) >> PAGE_SHIFT);
		return err;
	}

	/* TODO: CLEANUP LOL */
	return 0;
}

static struct kunit_case test_cases[] = {
	KUNIT_CASE(test_alloc),
	KUNIT_CASE(test_alloc_sensitivity),
	{}
};

/* TODO: This needs to be ifdef'd, or even moved to arch/ */
struct kunit_suite page_alloc_test_suite = {
	.name = "page_alloc",
	.test_cases = test_cases,
	.suite_init = plug_fake_node,
	.init = check_preconditions,
};
kunit_test_suite(page_alloc_test_suite);

MODULE_LICENSE("GPL");
MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");
