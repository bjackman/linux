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
- [x] Run tests on unstable branches like -next. This will require logic to rebase.
- [ ] Figure out a way to make test results readable.

      I looked into trying to parse the `mm` selftests
      [KTAP](https://docs.kernel.org/dev-tools/ktap.html#test-case-result-lines).
      I found that:

      - There is an open source Python library called
        [Tappy](https://github.com/pwcazenave/tappy), it cannot parse this data.
        It may be partly because the data is bogus but it also handles it
        poorly, e.g. it gets confused about seeing "Tap Version 13" lines even
        when they are prefixed with `#`. It also has a wack API, so I think it's
        probably just quite a bad library.

      - There is a KTAP parser provided with `kunit.py`. When given the outpout
        of my script (which, admittedly, is a bit tricky because it runs
        `run_vmtests.sh` in a loop), it gets into an infinite loop.

      - I noticed that one issue is that `run_vmtests.sh` does not produce valid
        KTAP, it puts the 1..N line at the end instead of at the beginning,
        maybe this is why `kunit.py` falls over.

      So I guess before we do anything else here we probably do need a parser
      for KTAP that isn't broken. So I guess the plan would be:

      - [ ] Fix `kunit.py` to not go into infinite loops.
      - [ ] Fix the `KTAP` outpuit from `run_vmtests.sh`.
      - [ ] Try parsing fixed KTAP and show it in some readable format.

      Note also that `run_vmtests.sh` doesn't use KTAP's nesting feature which
      is a shame.

- [ ] Figure out a way to make failures easy to reproduce locally.