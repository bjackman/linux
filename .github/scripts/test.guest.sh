#!/bin/bash
# Runs inside the QEMU guest on startup.
# The CWD is expected to contain the extract contents of the kernel build job
# (including kselftests).

set -eux

cd mm/

# Disable all the tests that I have never seen pass.
# See https://lore.kernel.org/linux-mm/20250228-mm-selftests-v3-0-958e3b6f0203@google.com/
ENABLED_VMTESTS=(
    mmap
    gup_test
    # userfaultfd: These usually pass but they're flaky.
    compaction
    mlock
    # mremap: Fails due to ENOMEM
    hugevm
    vmalloc
    hmm
    # guard-regions.c:1812:truncation:Expected ptr (18446744073709551615) != MAP_FAILED (18446744073709551615)
    # madv_guard
    # madv_populate: "range is softdirty"
    memfd_secret
    process_mrelease
    ksm
    ksm_numa
    pkey
    # soft_dirty: dirty bit was 0, but should be 1 (i=0)
    pagemap
    cow
    # thp: Reading PMD pagesize failed
    # hugetlb: Hangs
    migration
    mkdirty
    mdwe
    page_frag
    # There might be new tests that have been added, but run_vmtests.sh doesn't
    # support skipping tests, only listing the exact ones you wanna run, or
    # running everything.
)

./run_vmtests.sh -t "${ENABLED_VMTESTS[*]}"
