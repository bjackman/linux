#!/bin/bash
# Starts up virtme-ng and runs test.guest.sh inside it.

GITHUB_STEP_SUMMARY=${GITHUB_STEP_SUMMARY:-/dev/stdout}

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
        "cd /mnt; ./test.guest.sh" | tee guest.log

# Hack: Use kunit.py to parse the TAP output so we can generate something a bit
# more readable. I can't find any other tool that can parse KTAP.
# It produces JSON in the KernelCI format:
# https://github.com/kernelci/kernelci-doc/wiki/Test-API
# It has some hardcoded KUnit-specific bits in there but it works for these
# purposes.
# We discard the script's stdout because, even though it's quite helpful, it
# would be confusing since we've already just dumped the whole log, whic it's a
# subset of.
# The script is hard-coded to exit with an error if there's a test failure so we
# just ignore errors...
#
# Hack: There's a bug in rum_vmtests.sh where it puts the KTAP "Plan Line" (i.e.
# the "1..N") at the end instead of at the beginning. And there's a bug in
# kunit.py where that causes it to infinite loop. Work around by just removing
# the (optional) plan line.
grep -vE '^[0-9]+..[0-9]+$' guest.log | python3 tools/testing/kunit/kunit.py parse  --json=summary.json >/dev/null || true

# ChatGPT magic to convert the JSON summary into Markdown
jq -r '.test_cases | map("| \(.name) | \(.status) |") | .[]' summary.json \
    | sed '1i| Test Case | Status |' \
    | sed '2i| ----------- | --------- |' > "$GITHUB_STEP_SUMMARY"