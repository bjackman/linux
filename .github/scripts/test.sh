#!/bin/bash

set -eux

mkdir -p image
tar -C image  --zstd -xf image.tar.zst

mkdir -p kernel-build
tar -C kernel-build  -zxf kernel.tgz

unshare -r vng --verbose \
    --root image --user root --run kernel-build/vmlinuz \
    --rwdir=/mnt=kernel-build/kselftests -- \
        "cd /mnt/mm; ./run_vmtests.sh -t mmap"
