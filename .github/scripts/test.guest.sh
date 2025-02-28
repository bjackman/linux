#!/bin/bash
# Runs inside the QEMU guest on startup.
# The CWD is expected to contain the extract contents of the kernel build job
# (including kselftests).

set -eux

cd mm/

for type in mmap gup_test compaction migration page_frag; do
    ./run_vmtests.sh -t $type
done