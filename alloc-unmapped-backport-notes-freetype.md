# freetype_t / FREETYPE_UNMAPPED: backport from mm-new to v7.2-rc5

`v7.2-rc5` (`11028ab62899`) plus **41 commits**:

| | count |
|---|---|
| Prerequisite patches from mm-new | 18 |
| b4 cover letter (empty, reworded) | 1 |
| ALLOC_UNMAPPED v4 patches 4–24 of 26 | 21 |
| Backport-only Kconfig scaffolding | 1 |

Scope: the **mermap** and the **freetype / FREETYPE_UNMAPPED** machinery, as a
base for a new `__GFP_SENSITIVE` for Address Space Isolation. `AS_NO_DIRECT_MAP`
and its page-cache adoption are not carried.

Sibling branches, same 26-patch series but complete:

| branch | commits | prerequisites |
|---|---|---|
| `claude/alloc-unmapped-backport-plan-psfpcn` | 53 | whole series (25 patches) |
| `claude/alloc-unmapped-backport-minimal-psfpcn` | 48 | minimal (20 patches) |
| **this branch** | **41** | minimal (18 patches) |

---

## 1. What was dropped from the series, and why it is clean

Five of the 26 patches:

```
 1/26  10e93fd30  set_memory: add folio_{zap,restore}_direct_map helpers
 2/26  c23b038bc  mm/secretmem: make use of folio_{zap,restore}_direct_map
 3/26  7575645e2  mm: introduce AS_NO_DIRECT_MAP
25/26  89d417670  mm: plumb alloc flags into some alloc funcs
26/26  1315774fc  mm: add fast path for AS_NO_DIRECT_MAP
```

Patches 4–24 are carried unchanged and in order. The cut is clean in both
directions, checked mechanically:

* **Nothing in 4–24 reaches back into 1–3.** No patch in the kept range
  references `AS_NO_DIRECT_MAP`, `folio_zap_direct_map()`,
  `folio_restore_direct_map()`, `mapping_no_direct_map()`,
  `vma_has_no_direct_map()` or `secretmem`.
* **The mermap glue in the page cache belongs entirely to patch 26.**
  `mapping_check_flush_mermap()`, `vma_check_flush_mermap()` and
  `mapping_grab_mermap_stale()` are all introduced by `1315774fc`, so dropping
  it takes `mm/filemap.c`, `include/linux/pagemap.h` and the `mm/internal.h`
  flush helpers with it. `mm/page_alloc.c` and `mm/compaction.c` never call the
  mermap at all — the v4 design has `ALLOC_UNMAPPED` incompatible with
  `__GFP_ZERO`, so the allocator does no zeroing and needs no ephemeral mapping.
* The only surviving mermap mention in the allocator is a **comment** on
  `ALLOC_UNMAPPED` in `mm/page_alloc.h` ("This uses the mermap (when
  `__GFP_ZERO`)…"), which is stale in v4 upstream too.

### 1.1 …which also drops a whole prerequisite series

`folio-alloc-cleanups` (`c34a134c1` + `9c238f9b3`) — the *declared b4
prerequisite* of the full series — is **not needed here**. It was required only
because patch 25 re-introduces `__folio_alloc_node_noprof()` with an
`alloc_flags` argument and patch 26 edits `__folio_alloc()` in
`mm/page_alloc.h`. Re-running the blame closure over patches 4–24 drops both
commits out of the set entirely.

That is the whole difference in prerequisites versus
`claude/alloc-unmapped-backport-minimal-psfpcn`: 20 → 18.

---

## 2. Prerequisites — 18 patches, and why none can go

Re-running the identifier analysis against patches 4–24 alone yields **exactly
the same six** build-breaking symbol gaps as the full series:

| symbol | from | used by |
|---|---|---|
| `ALLOC_DEFAULT` | alloc-trylock 5/18 | `introduce ALLOC_NOBLOCK`, `implement FREETYPE_UNMAPPED allocations`, the KUnit tests |
| `fastpath_alloc_flags` | alloc-trylock 2/18 + 5/18 | `introduce ALLOC_NOBLOCK` |
| `ALLOC_NOLOCK` | alloc-trylock 1/18 | `implement FREETYPE_UNMAPPED allocations` |
| `ALLOC_NO_CODETAG` | alloc-trylock 15/18 | `implement FREETYPE_UNMAPPED allocations` |
| `alloc_flags_cma()` (1-arg) | alloc-trylock 2/18 + 17/18 | `implement FREETYPE_UNMAPPED allocations` |
| `compact_order` | reclaim storms 4/4 | `always direct compact for unmapped allocs` |

They are concentrated in exactly the patch this branch exists for.

```
6176de146  gfp-pessimisation v2 (1/1)
4a28f8182  alloc-trylock v5  1/18   rename ALLOC_TRYLOCK -> ALLOC_NOLOCK
511b762e4  alloc-trylock v5  2/18   renames to clarify alloc_flags scopes    [conflict]
80bbff065  alloc-trylock v5  4/18   split out internal page_alloc.h          [conflict]
49b09a465  alloc-trylock v5  5/18   unify __alloc_frozen_pages[_nolock]      [conflict]
4eb22c260  alloc-trylock v5  7/18   move some stuff to mm/page_alloc.h
9b777c01e  alloc-trylock v5  8/18   perf/x86/intel
3417d8f34  alloc-trylock v5  9/18   KVM: VMX
b7606739d  alloc-trylock v5 10/18   x86/virt
2b5d31f57  alloc-trylock v5 11/18   sgi-xp
010455a92  alloc-trylock v5 12/18   net/funeth
d65ae4c5f  alloc-trylock v5 13/18   remove __alloc_pages_node()
82c49de33  alloc-trylock v5 14/18   move __alloc_pages() to mm/page_alloc.h
cf3b3031e  alloc-trylock v5 15/18   replace __GFP_NO_CODETAG with ALLOC_NO_CODETAG
e71e6e115  alloc-trylock v5 17/18   drop alloc_flags arg from alloc_flags_cma()
0e6379e72  reclaim storms   2/4     non-movable compaction for pageblock requests
17f165092  reclaim storms   3/4     move capture_control to the page allocator
40685a0b2  reclaim storms   4/4     fix non-movable reclaim storm in defrag_mode
```

The irreducible bits are unchanged from the other branches and are documented
in `alloc-unmapped-backport-notes-minimal.md` §2:

* `cf3b3031e` → `82c49de33` → `d65ae4c5f` → 8–12/18. 15/18 puts `alloc_flags` on
  `__alloc_pages_noprof()` *inside `mm/page_alloc.h`*, which needs the
  declaration out of the public header, which needs `__alloc_pages_node()` gone,
  which needs its five treewide users converted — and those five patches are
  exactly the five remaining users in v7.2.
* `6176de146`, without which alloc-trylock 2/18 stops being a mechanical rename.
* `0e6379e72`, a **functional** dependency: both `40685a0b2` and
  `dda9957ef` promote non-movable requests to pageblock-order compaction, which
  without it cannot scan blocks of another type.

Dropped from the prerequisite set relative to the whole-series branch:
`e11b5c372`, `e3370af71`, `3c4fb0280`, `0650b2553`, `67d0ba828` (see
`…-notes-minimal.md` §1), plus `c34a134c1` and `9c238f9b3` (§1.1 above).

---

## 3. The scaffolding commit

`mm: backport scaffolding - make MERMAP selectable` — **not an upstream
patch**, and the one thing on this branch that is invented rather than
cherry-picked.

In the full series, `CONFIG_MERMAP` and `CONFIG_PAGE_ALLOC_UNMAPPED` are turned
on by patch 26, which builds the chain

```
SECRETMEM -> PAGECACHE_NO_DIRECT_MAP -> MERMAP -> PAGE_ALLOC_UNMAPPED
```

With patch 26 dropped, `MERMAP` and `PAGE_ALLOC_UNMAPPED` are left as bare
`bool`s with no prompt and nothing selecting them — so `mm/mermap.c`,
`freetype_t`'s flag paths and the whole `FREETYPE_UNMAPPED` implementation
would never be compiled by *any* config. That is a silent hole: the branch
would build fine and contain nothing.

The commit gives `MERMAP` a prompt and restores
`PAGE_ALLOC_UNMAPPED`'s `def_bool MERMAP` verbatim from the dropped patch.
**Drop it once the `__GFP_SENSITIVE` work selects the symbols itself.**

Consequence for building: `defconfig` alone leaves `CONFIG_MERMAP=n`. Enable it
explicitly:

```sh
make defconfig && ./scripts/config --enable MERMAP && make olddefconfig
# => CONFIG_MM_LOCAL_REGION=y  CONFIG_MERMAP=y  CONFIG_PAGE_ALLOC_UNMAPPED=y
```

---

## 4. Conflict resolutions

Seven of the 41 commits conflicted (the cover letter also carries a
`[ Backport to v7.2-rc5: ... ]` block, but that records its reword). All seven
are resolutions already made and explained on the sibling branches:

| commit | file | see |
|---|---|---|
| `mm/page_alloc: some renames to clarify alloc_flags scopes` | `mm/page_alloc.c` | `…-notes-minimal.md` §3.1 |
| `mm: split out internal page_alloc.h` | `mm/internal.h` ×2 | §3.2 |
| `mm/page_alloc: unify __alloc_frozen_pages[_nolock]_noprof()` | `mm/page_alloc.c` | §3.3 |
| `mm: Create flags arg for __apply_to_page_range()` | `mm/internal.h` | §3.4 |
| `x86/mm: introduce the mermap` | `mm/Makefile` | §3.7 |
| `mm: introduce freetype_t` | `mm/internal.h` | §3.8 |
| `mm/page_alloc: rename ALLOC_NON_BLOCK back to _HARDER` | `mm/page_alloc.c` | §3.9 |

Two conflicts that the other branches hit do **not** arise here, because their
patches are dropped: `mm: introduce AS_NO_DIRECT_MAP` (`mm/mlock.c`) and
`mm, treewide: replace __folio_alloc_node()` (`include/linux/gfp.h`).

The cover letter was reworded to describe this branch's scope, and its
**`b4-submit-tracking` block was removed**: this branch carries a subset of the
series, so it is not a revision of it, and leaving b4 metadata in place would
make `b4 prep` offer to send a v5 that is missing five patches. The full series
with b4 metadata intact is on `claude/alloc-unmapped-backport-plan-psfpcn`.

---

## 5. Verification

**Patches 4–24 are byte-identical to upstream's.** `git diff <cover> <last
series commit>` against `git diff 7575645e2 dda9957ef` (the same 21 patches on
mm-new) is 48 lines, every one a context line from a skipped dependency, except
one relocated `+`/`-` pair — the `ALLOC_NON_BLOCK` → `ALLOC_HARDER` rename that
moves out of `alloc_flags_nonblocking()` and into `alloc_flags_slowpath()`
(§4). Same single divergence as the other two branches.

**Build:** `make mm/` clean, no errors or warnings, with
`CONFIG_MERMAP=y CONFIG_PAGE_ALLOC_UNMAPPED=y CONFIG_MM_LOCAL_REGION=y`, so
`mm/mermap.c` and the `FREETYPE_UNMAPPED` paths did compile.

**Not built** (this VM is too small): full `defconfig`/`allmodconfig` link,
`arch/x86/` — which matters more here than anywhere, since this branch keeps
the x86 mm-local region and the mermap but drops everything that used to
exercise them from the page cache — `kernel/`, the five treewide call sites,
i386 + `CONFIG_X86_PAE` with and without PTI, and the KUnit tests
(`CONFIG_KUNIT` is off in defconfig, so neither new test file has been
compiled).

```sh
make -j$(nproc) defconfig && ./scripts/config --enable MERMAP && \
    make -j$(nproc) olddefconfig && make -j$(nproc)
make -j$(nproc) allmodconfig && make -j$(nproc)
make -j$(nproc) ARCH=i386 defconfig && ./scripts/config --enable X86_PAE MERMAP && make -j$(nproc)

tools/testing/kunit/kunit.py run --arch=x86_64 "page_alloc.*" \
    --kconfig_add CONFIG_MERMAP=y --kconfig_add CONFIG_PAGE_ALLOC_UNMAPPED=y
tools/testing/kunit/kunit.py run --arch=x86_64 "mermap.*" --kconfig_add CONFIG_MERMAP=y
```

The two KUnit suites are the main runtime check available on this branch —
`memfd_secret()`, which exercised the feature end-to-end on the other branches,
is no longer wired to any of this code.

---

## 6. Notes for the `__GFP_SENSITIVE` work

* `mm/tests/page_alloc_kunit.c` calls `mermap_mm_prepare(current->mm)` in
  `test_alloc_unmapped()`. That is vestigial — v4 dropped allocator-side
  zeroing, and the test allocates with `GFP_KERNEL | __GFP_THISNODE`, never
  `__GFP_ZERO` — but it is kept as-is here rather than edited, since the mermap
  is present anyway.
* `FREETYPE_UNMAPPED` currently implies `MIGRATE_UNMOVABLE`
  (`mm/page_alloc: separate pcplists by freetype flags` takes advantage of this
  to keep the pcplist growth to one extra bank). A sensitivity freetype for ASI
  will most likely want the same simplification at first.
* `mm/page_alloc: always direct compact for unmapped allocs` is deliberately
  asymmetric — it never promotes `!ALLOC_UNMAPPED` allocations — for the same
  reason: unmapped blocks contain no movable pages, so compaction can never
  free one up. That reasoning carries over to sensitive blocks unchanged.
* The pageblock flip in `implement FREETYPE_UNMAPPED allocations` uses
  `set_direct_map_valid_noflush()` + `flush_tlb_kernel_range()` and is gated on
  `can_set_direct_map() && !(alloc_flags & ALLOC_NOLOCK)`. For ASI this is the
  hook to replace with the restricted-pagetable equivalent.
