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

## Reproducing locally

Assuming you have an `apt`-based system, you can run the stuff under
`.github/scripts` locally. You can either do this by checking out one of this
repo's "shadow branches" (`github/*`), or you can just checkout `github-base` in
this repo and then run the scripts from the root of a separate kernel tree.

TODO: The reason for the `apt` dependency is for building the Debian guest
rootfs. It should be possible to avoid that by running the build in a container,
but even more practical would just be to provide an easy way to download it from
the Github artifacts.

`.github/scripts/run_local.sh` is intended to reproduce the whole test workflow
end-to-end.

`.github/scripts/bisect_helper.sh` is a modified version for when you want to
run a specific test, presumably to bisect a failure. For example, to just run
`gup_test`:

```sh
.github/scripts/bisect_helper.sh "cd mm/; ./run_vmtests.sh -t gup_test"
```

## TODOs

- [x] Make sure the scripts can actually be run locally and document an example.
- [x] Automate running tests regularly (I don't think the automated push to the
      shadow branches fires the `push` trigger in GHA, as a simple way to avoid
      recursive triggering).
- [x] Run tests on unstable branches like -next. This will require logic to rebase.
- [x] Add basic logic to parse KTAP output. This now shows up in the summary of
  the Github Actions run.
- [ ] Resolve vmtests that get skipped completely
  - [x] `vmalloc` -> requires `CONFIG_TEST_VMALLOC`
  - [x] `hmm` -> requires `CONFIG_TEST_HMM`
  - [x] `ksm`, `ksm_numa` -> "Config KSM not enabled" (I guess `CONFIG_KSM`?)
  - [ ] `hugevm` -> requires 5-level paging and `PR_SET_VMA_ANON_NAME`
  - [ ] `memfd_secret` -> dunno, doesn't print anything
  - [ ] KSM, but probably various: Requires NUMA
  - [ ] (Probably others that just silently skip most of their logic. `mrelease_test`?)
- [ ] Look into obvious failures commented in `.github/scripts/test.guest.sh`
- [ ] `userfaultfd` tests are flaky. Think about how to address flaky tests.

- [x] Try
  [this](https://www.kernel.org/best-way-to-do-linux-clones-for-your-ci.html) to
  make things faster. Because we are interested in create merge commits, we need
  to clone the full history (at least, we don't know up front how much history
  we need to clone, and I don't know of a good way to figure that out
  on-the-fly). Apparently GitHub doesn't optimise this case, so it takes 10+
  minutes to start the `update_branches` job.
- [ ] Make the summary tables more readable, try to represent the nested
  structure if possible? ChatGPT says you can have arbitrary HTML in the
  `$GITHUB_STEP_SUMMARY`, maybe with a `<details>` element you can make
  something reasonably readable.
- [ ] Also include skipped tests.
- [ ] Make the skipped mm tests run
- [ ] Try to run some more tests in this setup.
- [ ] Figure out a way to make failures easy to reproduce locally by downloading
      artifacts.
- Improvements to kernel scripts:
  - [ ] Fix bug where `tools/testing/kunit.py parse` goes into an infinite loop
        on this input:

    ```
    TAP version 13
    ok 4 gup_longterm
    1..4
    ```

  - [ ] Fix bug where `run_vmtests.sh` puts the plan line in the wrong place
        (i.e. produces output like the one above).
- [ ] Clean up upstream testing scripts:
  - [ ] Fix `kunit.py` to not go into infinite loops.
  - [ ] Fix the `KTAP` outpuit from `run_vmtests.sh`.


## Some notes on KTAP parsing

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
  of my script it gets into an infinite loop, fixed by:

  https://lore.kernel.org/lkml/CABVgOS=Pfp2_ZvCtxy6X_xoM6pGVgT6bD_4VxGVZ_SNWVgesGQ@mail.gmail.com/

Note also that `run_vmtests.sh` doesn't use KTAP's nesting feature which
is a shame.

Broonie pointed me here: https://github.com/Linaro/test-definitions/tree/master/automated/linux/kselftest
