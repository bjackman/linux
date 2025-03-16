#!/bin/bash

set -eux

# For running everything locally all at once. Ought to more or less mirror the
# test.yaml Github workflow.
# You can run this from any kernel repo and it should find its sister sripts
# based on $0.

SCRIPTS_DIR="$(dirname "$0")"

"$SCRIPTS_DIR"/build_kernel.sh
mkosi -C "$SCRIPTS_DIR"/rootfs --output-directory=$PWD
# I dunno how to stop mkosi from creating this symlink, and the other scripts
# use "image" as a working directory for the rootfs. This isn't an issue in
# Github actions because those run in separate jobs so we just don't pass the
# symlink in the artifacts between jobs.
rm -rf image
"$SCRIPTS_DIR"/test.sh