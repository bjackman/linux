#!/bin/bash

# Builds the kernel and puts it in kernel.tgz.
# Needs to be run from the root of this repo.
set -eux -o pipefail

mkdir -p kernel-build

# Configure stuff to boot in virtme-ng
vng --kconfig
# Configure stuff needed by mm selftests
scripts/config -e GUP_TEST -e USERFAULTFD
make olddefconfig
# Build kernel
make -s -j $(( $(nproc) * 2 )) CC="ccache gcc"

# Just extract the important bits, Github is dumb and will copy the whole
# artifact between jobs every time which takes minutes if you include the whole
# build result.
make -j $(( $(nproc) * 2 )) INSTALL_PATH=$PWD/kernel-build install

# Shouldn't happen in GHA but when running locally the file might exist
if [ -e kernel-build/vmlinuz ]; then
    rm kernel-build/vmlinuz
fi

# Make a symlink that always has the same name
ln -s vmlinuz-$(make kernelrelease) kernel-build/vmlinuz

# -static is a simple way to workaround differences in the shared
# library environment between host & guest.
make -j $(( $(nproc) * 2 )) -C tools/testing/selftests \
    TARGETS=mm KDIR=$PWD EXTRA_CFLAGS=-static INSTALL_PATH=$PWD/kernel-build/kselftests install

# Github breaks file permissions so tar everything up
tar czf kernel.tgz -C kernel-build .
