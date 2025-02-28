# Linux Kernel Github CI???

This repo contains my attempts to run Linux
[kselftests](https://docs.kernel.org/dev-tools/kselftest.html) via GitHub
Actions (GHA).

It is also where I dump my kernel work, GitHub wouldn't let me push a whole
fresh kernel tree and wouldn't let me create a separate fork of Linus' tree.
🤷‍♂️

Certain upstream branches are mirrored into this repository. For each upstream
branch, there is a shadow branch called `github/$remote/$branch`. And a branch
called `github-base` contains the actual GHA configuration.

The `update_branches.yaml` workflow periodically merges the upstream branches
into their shadow branches, _then also merges `github-base` into them_. Then the
`test.yaml` workflow can be run on the shadow branch to actually build the
kernel and run tests.

Note that the `github-base` branch doesn't contain any files that are likely
ever to exist in upstream kernel trees, so hopefully there will never be any
merge conflicts.

The goal is to keep minimal logic in the GHA YAML and instead put everything in
shell scripts under `.github/scripts/`, so that to the greatest extent possible
you can verify the logic locally.

TODO:

- [ ] Make sure the scripts can actually be run locally and document an example.
- [ ] Automate running tests regularly (I don't think the automated push to the
      shadow branches fires the `push` trigger in GHA, as a simple way to avoid
      recursive triggering).
- [ ] Run tests on unstable branches like -next. This will require logic to rebase.
- [ ] Figure out a way to make test results readable.
- [ ] Figure out a way to make failures easy to reproduce locally.