#!/bin/bash
# Runs inside the QEMU guest on startup.
# The CWD is expected to contain the extract contents of the kernel build job
# (including kselftests).

cd mm/
./run_vmtests.sh -t mmap