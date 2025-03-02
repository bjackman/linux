#!/bin/bash
# Runs inside the QEMU guest on startup.
# The CWD is expected to contain the extract contents of the kernel build job
# (including kselftests).

set -eux

cd mm/

# These are the only tests I've managed to get working so far.
# See https://lore.kernel.org/linux-mm/20250228-mm-selftests-v3-0-958e3b6f0203@google.com/
./run_vmtests.sh -t "mmap gup_test compaction migration page_frag"