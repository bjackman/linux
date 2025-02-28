#!/bin/bash

set -eux

mkdir -p image
tar -C image  --zstd -xf image.tar.zst

mkdir -p kernel
tar -C kernel  -zxf kernel.tgz

mkdir -p kselftests
tar -C kselftests  -zxf kselftests.tgz

unshare -r vng --verbose \
    --root image --user root --run kernel/vmlinuz \
    --rwdir=/mnt=kselftests/kselftest_install -- \
        "cd /mnt/mm; ./run_vmtests.sh -t mmap"
