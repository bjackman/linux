#!/bin/bash

set -eux

declare -A REMOTES
REMOTES=(
    ["akpm-mm"]="https://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm.git"
    ["linus"]="https://github.com/torvalds/linux.git"
)

for remote in "${!REMOTES[@]}"; do
    if ! git remote | grep "^${remote}$"; then
        git remote add "$remote" "${REMOTES["$remote"]}"
    fi
done

git fetch --all

for upstream_branch in linus/master akpm-mm/mm-stable; do
    git checkout github/$upstream_branch
    git merge --no-edit $upstream_branch
    git merge --no-edit github-base
    git push origin github/$upstream_branch:github/$upstream_branch
done