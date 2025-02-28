#!/bin/bash

set -eux

if ! git remote | grep '^akpm-mm$'; then
    git remote add akpm-mm https://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm.git
fi

if ! git remote | grep '^linus$'; then
    git remote add linus https://github.com/torvalds/linux.git
fi

git fetch --all

for upstream_branch in linus/master akpm-mm/mm-stable; do
    git checkout github/$upstream_branch
    git merge --no-edit $upstream_branch
    git merge --no-edit github-base
    git push origin github/$upstream_branch:github/$upstream_branch
done