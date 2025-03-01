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

declare -A BRANCHES
BRANCHES=(
    ["linus/master"]=merge
    ["akpm-mm/mm-stable"]=merge
)

for upstream_branch in "${!BRANCHES[@]}"; do
    git checkout github/$upstream_branch
    if [[ "${BRANCHES["$upstream_branch"]}" = merge ]]; then
        git merge --no-edit $upstream_branch
    else
        echo "Invalid branch setting '${BRANCHES["$upstream_branch"]}' for $upstream_branch, must be 'merge'"
        exit 1
    fi
    git merge --no-edit github-base
    git push origin github/$upstream_branch:github/$upstream_branch
done