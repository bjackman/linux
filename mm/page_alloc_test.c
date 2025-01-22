// SPDX-License-Identifier: GPL-2.0-only
#include <linux/errname.h>
#include <linux/gfp.h>
#include <linux/list.h>
#include <linux/memory_hotplug.h>
#include <linux/memory.h>
#include <linux/mmdebug.h>
#include <linux/mmzone.h>
#include <linux/nodemask.h>
#include <linux/percpu.h>
#include <linux/smp.h>

#include <kunit/test.h>

static void test_alloc(struct kunit *test)
{
}

static int memory_block_online_cb(struct memory_block *mem, void *unused)
{
	return memory_block_online(mem);
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

static struct kunit_case test_cases[] = { KUNIT_CASE(test_alloc), {} };

struct kunit_suite page_alloc_test_suite = {
	.name = "page_alloc",
	.test_cases = test_cases,
	.suite_init = plug_fake_node,
};
kunit_test_suite(page_alloc_test_suite);

MODULE_LICENSE("GPL");
MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");
