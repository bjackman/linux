# freetype_t / FREETYPE_UNMAPPED for a GFP flag: backport to v7.2-rc5

`v7.2-rc5` (`11028ab62899`) plus **34 commits**:

| | count |
|---|---|
| Prerequisite patches cherry-picked from mm-new | 10 |
| Commits that are **not** upstream patches | 2 |
| b4 cover letter (empty, reworded) | 1 |
| ALLOC_UNMAPPED v4 patches 4–24 of 26 | 21 |

Scope: the **mermap** plus the **freetype / FREETYPE_UNMAPPED** machinery, as a
base for a new `__GFP_SENSITIVE` for Address Space Isolation — trimmed on the
premise that the flag will be a **GFP flag**, so the branch deliberately does
not carry the API changes whose only purpose is letting code *outside* `mm/`
pass an `ALLOC_` flag in.

| branch | commits | series patches | prereqs | alloc-trylock |
|---|---|---|---|---|
| `…-plan-psfpcn` | 53 | 26 | 25 | 18/18 |
| `…-minimal-psfpcn` | 48 | 26 | 20 | 14/18 |
| `…-freetype-psfpcn` | 42 | 21 | 18 | 14/18 |
| **this branch** | **34** | **21** | **10 + 2** | **6/18** |

---

## 1. The premise, and what it buys

`cf3b3031e` ("mm: replace `__GFP_NO_CODETAG` with `ALLOC_NO_CODETAG`") does two
separable things:

1. **Public-facing.** It converts a GFP flag into an ALLOC flag, so callers
   outside `mm/` must be able to pass an `ALLOC_` flag in. That means
   `__alloc_pages_noprof()` gains an `alloc_flags` parameter, which forces its
   declaration out of `include/linux/gfp.h` (`82c49de33`), which forces the
   removal of `__alloc_pages_node()` (`d65ae4c5f`), which forces its five
   treewide users to be converted (alloc-trylock 8–12/18). **Eight patches.**
2. **mm-internal.** It adds `alloc_flags` to `struct alloc_context` and
   propagates it through the slowpath, and gives `post_alloc_hook()` an
   `alloc_flags` parameter.

Only (2) is needed here. `__GFP_SENSITIVE` arrives in the `gfp_t` through the
existing public API and is converted inside the allocator, so no caller outside
`mm/` ever names an `ALLOC_` flag.

Dropping (1) removes **eight** prerequisite patches:

```
cf3b3031e  alloc-trylock 15/18  mm: replace __GFP_NO_CODETAG with ALLOC_NO_CODETAG
82c49de33  alloc-trylock 14/18  mm: move __alloc_pages() to mm/page_alloc.h
d65ae4c5f  alloc-trylock 13/18  mm: remove __alloc_pages_node()
9b777c01e  alloc-trylock  8/18  perf/x86/intel: use higher-level allocator API
3417d8f34  alloc-trylock  9/18  KVM: VMX: use higher-level allocator API
b7606739d  alloc-trylock 10/18  x86/virt: use higher-level allocator API
2b5d31f57  alloc-trylock 11/18  sgi-xp: use higher-level allocator API
010455a92  alloc-trylock 12/18  net/funeth: switch to higher-level allocator API
```

`include/linux/gfp.h`, `arch/x86/kvm/`, `drivers/misc/sgi-xp/`,
`drivers/net/ethernet/fungible/` and `arch/x86/events/` are now untouched by
this branch.

alloc-trylock v5 drops from 14 patches to **6**: 1, 2, 4, 5, 7 and 17 of 18.

---

## 2. What is still required

```
6176de146  gfp-pessimisation v2 (1/1)   drop flag-conversion "optimisation"
4a28f8182  alloc-trylock  1/18          rename ALLOC_TRYLOCK -> ALLOC_NOLOCK
511b762e4  alloc-trylock  2/18          renames to clarify alloc_flags scopes   [conflict]
80bbff065  alloc-trylock  4/18          split out internal page_alloc.h         [conflict]
49b09a465  alloc-trylock  5/18          unify __alloc_frozen_pages[_nolock]     [conflict]
4eb22c260  alloc-trylock  7/18          move some stuff to mm/page_alloc.h
e71e6e115  alloc-trylock 17/18          drop alloc_flags arg from alloc_flags_cma()  [conflict]
0e6379e72  reclaim storms 2/4           non-movable compaction for pageblock requests
17f165092  reclaim storms 3/4           move capture_control to the page allocator
40685a0b2  reclaim storms 4/4           fix non-movable reclaim storm in defrag_mode
```

| patch | why |
|---|---|
| `80bbff065` | creates `mm/page_alloc.h`, which v7.2 has no equivalent of |
| `49b09a465` | `ALLOC_DEFAULT`, `fastpath_alloc_flags`, and the `alloc_flags` parameter on the **mm-internal** `__alloc_frozen_pages_noprof()` |
| `4a28f8182` | `ALLOC_NOLOCK`, referenced by the FREETYPE_UNMAPPED implementation |
| `511b762e4` / `e71e6e115` | one-argument `alloc_flags_cma()`, called four times by the implementation |
| `4eb22c260` | moves `gfp_migratetype()` into `mm/page_alloc.h`; `mm: introduce freetype_t` **deletes that definition**, so without this the deletion has nothing to match |
| `6176de146` | without it alloc-trylock 2/18 stops being a mechanical rename — see `…-notes-minimal.md` §2.1 |
| reclaim storms 2–4/4 | `compact_order`, the reshaped `struct capture_control`, and the functional requirement that non-movable pageblock-order compaction can scan other block types |

---

## 3. The two commits that are not upstream patches

### 3.1 `mm/page_alloc: carry alloc_context.alloc_flags and post_alloc_hook()'s`

An extraction of half of `cf3b3031e`, taken verbatim:

* `struct alloc_context.alloc_flags` and its comment
* `ac->alloc_flags` in the two `__alloc_pages_may_oom()` fallbacks
* `ac->alloc_flags | alloc_flags_slowpath()` plus the `ALLOC_WMARK_MASK`
  warning in `__alloc_pages_slowpath()`
* `ac->alloc_flags` in the `reserve_flags` and `nofail` paths
* `.alloc_flags` initialisation in `__alloc_frozen_pages_noprof()`
* the `alloc_flags` parameter on `post_alloc_hook()`, its four call sites in
  `mm/page_alloc.c` and `mm/compaction.c`, and `ALLOC_DEFAULT` for a bare `0`
  in `alloc_contig_frozen_range_noprof()`

Left behind: `ALLOC_NO_CODETAG`, the `pgalloc_tag_add()` /
`alloc_tag_add_early_pfn()` signature changes, the `__alloc_pages_noprof()`
parameter and all of its call sites. `post_alloc_hook()` therefore still passes
`gfp_flags` to `pgalloc_tag_add()`, as v7.2 does.

**`post_alloc_hook()`'s parameter is not optional**, and I got that wrong on the
first pass — the branch failed to build with

```
mm/page_alloc.c:1948: error: 'alloc_flags' undeclared
```

because `implement FREETYPE_UNMAPPED allocations` gives `should_skip_init()` an
`alloc_flags` argument (so `ALLOC_UNMAPPED` pages skip KASAN tag init) and
`post_alloc_hook()` is what calls it. `post_alloc_hook()` is declared in
`mm/page_alloc.h`, so extending it costs nothing outside `mm/` — it belongs on
the internal side of the split, not the public one.

Replace the whole commit with the real `cf3b3031e` if the public-facing
parameter is ever wanted.

### 3.2 `mm: backport scaffolding - make MERMAP selectable`

Unchanged from `…-freetype-psfpcn`. Dropped patch 26 is what builds the chain
`SECRETMEM → PAGECACHE_NO_DIRECT_MAP → MERMAP → PAGE_ALLOC_UNMAPPED`; without
it both symbols are bare `bool`s that nothing selects and no prompt can reach,
so none of this code would ever be compiled. The commit gives `MERMAP` a prompt
and restores `PAGE_ALLOC_UNMAPPED`'s `def_bool MERMAP` verbatim from the
dropped patch. **Drop it once `__GFP_SENSITIVE` selects the symbols itself.**

```sh
make defconfig && ./scripts/config --enable MERMAP && make olddefconfig
# => CONFIG_MM_LOCAL_REGION=y  CONFIG_MERMAP=y  CONFIG_PAGE_ALLOC_UNMAPPED=y
```

---

## 4. Adjustments inside the carried series patches

Two, beyond the mechanical conflicts in §5. Both are recorded in the relevant
commit messages.

### 4.1 `ALLOC_UNMAPPED`'s bit value

`mm: add definitions for allocating unmapped pages` adds `ALLOC_UNMAPPED`
immediately after `ALLOC_NO_CODETAG` (`0x1000`), which does not exist here.
Only the `ALLOC_UNMAPPED` block was taken, and its value is **deliberately left
at upstream's `0x2000`** rather than moved down into the vacant `0x1000`, so
that `0x1000` stays free for `ALLOC_NO_CODETAG` if the rest of `cf3b3031e` is
ever picked up.

Correspondingly, `implement FREETYPE_UNMAPPED allocations` defines
`SUPPORTED_INPUT_ALLOC_FLAGS` as `ALLOC_NOLOCK | ALLOC_UNMAPPED` (and
`ALLOC_NOLOCK` in the `!CONFIG_PAGE_ALLOC_UNMAPPED` case) rather than upstream's
lists, which include `ALLOC_NO_CODETAG`.

### 4.2 The KUnit test

`mm: Minimal KUnit tests for some new page_alloc logic` was the **only** thing
on this branch that wanted the public-facing parameter — its
`do_many_alloc_pages()` helper calls the five-argument
`__alloc_pages(gfp, order, nid, NULL, alloc_flags)`.

Rather than drag `cf3b3031e` and its three-deep chain back in for one test
helper, the helper was switched to the mm-internal equivalent, which does take
`alloc_flags` and is already declared in `mm/page_alloc.h`:

```c
-		struct page *page = __alloc_pages(gfp, order, numa_node_id(),
-			NULL, alloc_flags);
+		struct page *page = __alloc_frozen_pages(gfp, order,
+			numa_node_id(), NULL, alloc_flags);
 		...
+		set_page_refcounted(page);
```

That is exactly what `__alloc_pages_noprof()` itself does, so the pages handed
back are identical and the existing `__free_pages()` teardown is unchanged. The
file already includes both `mm/page_alloc.h` and `mm/internal.h`.

> **This adaptation is compile-untested.** `CONFIG_KUNIT` is off in defconfig
> and this was prepared on a machine too small to build it. Run the suite
> before relying on it — and note that once `__GFP_SENSITIVE` exists the helper
> can go back to a plain `alloc_pages_node()` with the GFP flag, which is
> simpler than either version.

---

## 5. Conflict resolutions

Seven commits conflicted (the cover letter also carries a
`[ Backport to v7.2-rc5: ... ]` block, recording its reword rather than a
conflict).

| commit | file | resolution |
|---|---|---|
| `mm/page_alloc: some renames to clarify alloc_flags scopes` | `mm/page_alloc.c` | `…-notes-minimal.md` §3.1 — no `alloc_flags_nonblocking()` without `7a496b133` |
| `mm: split out internal page_alloc.h` | `mm/internal.h` ×2 | §3.2 — `const nodemask_t` and the `e11b5c372` named-args block |
| `mm/page_alloc: unify __alloc_frozen_pages[_nolock]_noprof()` | `mm/page_alloc.c` | §3.3 |
| `mm/page_alloc: drop alloc_flags arg from alloc_flags_cma()` | `mm/page_alloc.c` | **new here** — the hunk also carries `ac->alloc_flags |`, which does not exist until the extraction commit two patches later; applied the patch's own change without it |
| `mm: Create flags arg for __apply_to_page_range()` | `mm/internal.h` | §3.4 |
| `x86/mm: introduce the mermap` | `mm/Makefile` | §3.7 |
| `mm: introduce freetype_t` | `mm/internal.h` | §3.8 |
| `mm: add definitions for allocating unmapped pages` | `mm/page_alloc.h` | **new here** — see §4.1 |
| `mm/page_alloc: implement FREETYPE_UNMAPPED allocations` | `mm/page_alloc.c` | **new here** — see §4.1 |
| `mm/page_alloc: rename ALLOC_NON_BLOCK back to _HARDER` | `mm/page_alloc.c` | §3.9 |

---

## 6. Verification

### 6.1 Against upstream

`git diff <cover> <last series commit>` compared with
`git diff 7575645e2 dda9957ef` (the same 21 patches on mm-new) is 76 lines.
Every line is a context line from a skipped dependency **except** three
documented deltas:

| delta | §|
|---|---|
| the `ALLOC_NON_BLOCK` → `ALLOC_HARDER` rename relocating out of `alloc_flags_nonblocking()` | 5 |
| `SUPPORTED_INPUT_ALLOC_FLAGS` without `ALLOC_NO_CODETAG` (both definitions) | 4.1 |
| the KUnit helper's `__alloc_pages` → `__alloc_frozen_pages` + `set_page_refcounted` | 4.2 |

Nothing else in the 21 patches was lost, weakened or altered.

### 6.2 Build

`make mm/` completes with no errors and no warnings under x86_64 `defconfig`
plus `CONFIG_MERMAP=y` (which pulls in `CONFIG_PAGE_ALLOC_UNMAPPED=y` and
`CONFIG_MM_LOCAL_REGION=y`), so `mm/mermap.c` and the `FREETYPE_UNMAPPED` paths
did compile.

This branch is the one where that build actually caught something — see §3.1.

**Not built:** full `defconfig`/`allmodconfig` link, `arch/x86/`, `kernel/`,
i386 + `CONFIG_X86_PAE` with and without PTI, and the KUnit tests. The
treewide-call-site risk that dominated the other branches is *gone* here
(nothing outside `mm/` and `arch/x86/`'s mm-local code is touched), but §4.2 is
new untested code, so the KUnit run matters more:

```sh
make -j$(nproc) defconfig && ./scripts/config --enable MERMAP && \
    make -j$(nproc) olddefconfig && make -j$(nproc)
make -j$(nproc) allmodconfig && make -j$(nproc)

tools/testing/kunit/kunit.py run --arch=x86_64 "page_alloc.*" \
    --kconfig_add CONFIG_MERMAP=y --kconfig_add CONFIG_PAGE_ALLOC_UNMAPPED=y
tools/testing/kunit/kunit.py run --arch=x86_64 "mermap.*" --kconfig_add CONFIG_MERMAP=y
```

---

## 7. Wiring up `__GFP_SENSITIVE`

The path is already in place:

```
alloc_flags_slowpath(gfp_mask, order)     mm/page_alloc.c   <- derive ALLOC_SENSITIVE here
init_alloc_flags(gfp, alloc_flags)        mm/page_alloc.c   <- ...and here, for the fastpath
  |  both land in ac->alloc_flags
  v
gfp_freetype(gfp_flags, alloc_flags)      mm/page_alloc.h   <- ALLOC_* -> freetype flags
  v
ac->freetype
```

Both conversion points need updating or the fastpath will allocate from the
wrong freetype. `gfp_freetype()` already takes both masks, so a GFP-derived
freetype needs no signature change.

Other things worth knowing:

* `FREETYPE_UNMAPPED` currently implies `MIGRATE_UNMOVABLE`; `separate pcplists
  by freetype flags` leans on that to keep the pcplist growth to one extra bank.
* `always direct compact for unmapped allocs` is deliberately asymmetric — it
  never promotes `!ALLOC_UNMAPPED` allocations, because unmapped blocks hold no
  movable pages so compaction can never free one up. The same reasoning applies
  to sensitive blocks.
* The pageblock flip in `implement FREETYPE_UNMAPPED allocations` uses
  `set_direct_map_valid_noflush()` + `flush_tlb_kernel_range()`, gated on
  `can_set_direct_map() && !(alloc_flags & ALLOC_NOLOCK)`. That is the hook to
  replace with ASI's restricted-pagetable equivalent.
* `mm/tests/page_alloc_kunit.c` still calls `mermap_mm_prepare(current->mm)` in
  `test_alloc_unmapped()`. That is vestigial — v4 dropped allocator-side
  zeroing and the test never passes `__GFP_ZERO` — but harmless with the mermap
  present.
* If you later want `ALLOC_NO_CODETAG` and the public parameter after all,
  replacing the extraction commit (§3.1) with the real `cf3b3031e` pulls
  `82c49de33`, `d65ae4c5f` and alloc-trylock 8–12/18 back with it, and §4.1/§4.2
  can be reverted to upstream's text.
