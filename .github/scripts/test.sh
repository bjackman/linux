#!/bin/bash
# Starts up virtme-ng and runs test.guest.sh inside it.

set -eux

mkdir -p image
tar -C image  --zstd -xf image.tar.zst

mkdir -p kernel-build
tar -C kernel-build  -zxf kernel.tgz

# Dumb hack to get the script into the guest.
cp $(dirname "$0")/test.guest.sh kernel-build/kselftests

unshare -r vng --verbose \
    --root image --user root --run kernel-build/vmlinuz \
    --rwdir=/mnt=kernel-build/kselftests -- \
        "cd /mnt; ./test.guest.sh"
