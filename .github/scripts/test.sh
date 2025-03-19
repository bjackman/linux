#!/bin/bash
# Starts up virtme-ng and runs test.guest.sh inside it.

GITHUB_STEP_SUMMARY=${GITHUB_STEP_SUMMARY:-/dev/stdout}

set -eux

mkdir -p image
tar -C image  --zstd -xf image.tar.zst

mkdir -p kernel-build
tar -C kernel-build  -zxf kernel.tgz

# Dumb hack to get the script into the guest.
cp "$(dirname "$0")/test.guest.sh" kernel-build/kselftests

# If you change this, please also update bisect_helper.sh
unshare -r vng --verbose --cpus 4  \
    --root image --user root --run kernel-build/vmlinuz \
    --rwdir=/mnt=kernel-build/kselftests \
    --rodir=/lib/modules=kernel-build/lib/modules -- \
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

# Convert the JSON summary into a Markdown table
echo "| Test Case | Status |" >> "$GITHUB_STEP_SUMMARY"
echo "| --------- | ------ |" >> "$GITHUB_STEP_SUMMARY"
# First jq command adds style, pizazz, panache, empathy, lived experience,
# equality, aspiration, wisdom and truth. Second jq command converts the JSON
# into rows of a Markdown table.
jq '.test_cases[] |= (.status += (if .status == "PASS" then " ✅" elif .status == "SKIP" then " ⏭️" else " ❌" end))'  summary.json \
    | jq -r '.test_cases | map("| \(.name) | \(.status) |") | .[]' >> "$GITHUB_STEP_SUMMARY"