#!/bin/bash

set -eux

# Map remote names to remote URLs.
declare -A REMOTES
REMOTES=(
    ["akpm-mm"]="https://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm.git"
    ["linus"]="https://github.com/torvalds/linux.git"
)

# Create remotes if they don't exist.
# (They will never exist when running on Github, but handling pre-existing
# branches makes this script runnable locally for testing).
for remote in "${!REMOTES[@]}"; do
    if ! git remote | grep "^${remote}$"; then
        git remote add "$remote" "${REMOTES["$remote"]}"
    fi
done

git remote -v

git fetch --all

# Map remote branches to update strategies.
#
# "merge" means we just repeatedly merge the branch and github-base into the
# shadow branch. This is cleaner for branches that actually feed into Linus'
# tree.
#
# "rebase" means the shadow branch is just the upstream branch with a single
# commit on top of it that merges in github-base. This avoids merge conflicts
# when testing upstream branches that get rebased.
declare -A BRANCHES
BRANCHES=(
    ["linus/master"]=merge
    ["akpm-mm/mm-stable"]=merge
    ["akpm-mm/mm-unstable"]=rebase
)

for upstream_branch in "${!BRANCHES[@]}"; do
    # If the branch exists (in origin), check it out, otherwise create it
    if git branch -a | grep -q "\(origin/\)\?github/$upstream_branch"; then
        # This will create the local branch if it doesn't already exist
        git checkout "github/$upstream_branch"
    else
        git checkout -b "github/$upstream_branch" "$upstream_branch"
    fi

    # Update the shadow branch with the latest upstream contents, then merge in
    # github-base.
    mode=${BRANCHES["$upstream_branch"]}
    if [[ "$mode" = merge ]]; then
        git merge --no-edit "$upstream_branch"
        git merge --no-edit github-base
        git push origin "github/$upstream_branch:github/$upstream_branch"
    elif [[ "$mode" = rebase ]]; then
        # This is called "rebase" because even though we don't invoke "git
        # rebase", we're "rebasing the merge commit of github-base onto the
        # shadow branch each time. (It's not actually equivalent to doing that,
        # because we also amend the merge commit to merge in the latest version
        # of github-base, instead of just having a pointless series of repeated
        # merge commits).
        git reset --hard "$upstream_branch"
        git merge --no-edit github-base --allow-unrelated-histories
        git push --force origin "github/$upstream_branch:github/$upstream_branch"
    else
        echo "Invalid branch setting '$mode' for $upstream_branch, must be 'merge' or 'rebase'"
        exit 1
    fi
done