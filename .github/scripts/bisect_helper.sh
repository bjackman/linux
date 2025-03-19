#!/bin/bash

set -eux

# Build the kernel and kselftests. Build the rootfs _only if it isn't built
# already_. Then boot up and cd into the kselftests directory, then run the
# provided command (instead of test.guest.sh).
# This is intended to be useful for bisection.

SCRIPTS_DIR="$(dirname "$0")"

"$SCRIPTS_DIR"/build_kernel.sh
if [ ! -d image ]; then
    if [ -f image ]; then
        rm image
    fi
    mkosi -C "$SCRIPTS_DIR"/rootfs --output-directory=$PWD
    mkdir -p image
    tar -C image  --zstd -xf image.tar.zst
fi

unshare -r vng --verbose --cpus 4 \
    --root image --user root --run kernel-build/vmlinuz \
    --rwdir=/mnt=kernel-build/kselftests \
    --rodir=/lib/modules=kernel-build/lib/modules -- \
    "cd /mnt; $@" | tee guest.log