# ALLOC_UNMAPPED v4: backport from mm-new to v7.2-rc5

This branch is `v7.2-rc5` (`11028ab62899`, "Merge tag 'probes-fixes-v7.2-rc5'")
plus **52 commits**: 25 prerequisite patches cherry-picked from mm-new, then the
b4 cover letter and the 26 patches of the ALLOC_UNMAPPED v4 series.

Source: `origin/alloc-unmapped` = `1315774fcedd` ("mm: add fast path for
AS_NO_DIRECT_MAP"), cover letter `bb1cbf879bcc`, sitting on an mm-new base with
**619** commits between it and `v7.2-rc5`. Of those 619, 25 were needed.

Every backported commit keeps its upstream/mm-new commit id via
`(cherry picked from commit ...)`. Where a conflict had to be resolved, the
resolution is recorded in a `[ Backport to v7.2-rc5: ... ]` block at the end of
that commit's message, so `git log` is the primary record; this file is the
summary.

---

## 1. What was backported, and why

Applied in mm-new order, which is also a valid topological order — the
prerequisite series conflict with each other if reordered (folio-alloc-cleanups
edits `mm/page_alloc.h`, which only exists after alloc-trylock v5 patch 4/18).

### 1.1 gfp-pessimisation v2 — 1 patch
<https://lore.kernel.org/20260629-gfp-pessimisation-v2-1-311ece6a8637@google.com>

| upstream | subject |
|---|---|
| `6176de1460515` | mm/page_alloc: drop flag-conversion "optimisation" |

Named prerequisite in the cover letter. Removes the value-coupling between
`ALLOC_MIN_RESERVE`/`ALLOC_KSWAPD` and `__GFP_HIGH`/`__GFP_KSWAPD_RECLAIM` in
`gfp_to_alloc_flags()` and `alloc_flags_nofragment()`, both of which the series
then restructures. Not strictly build-breaking (no existing `ALLOC_*` value
moves), but it is one self-contained reviewed patch and the series was developed
on top of it.

### 1.2 alloc-trylock v5 — all 18 patches
<https://lore.kernel.org/all/20260703-alloc-trylock-v5-0-c87b714e19d3@google.com/>

The unavoidable one, and it has to be taken whole:

* **`mm/page_alloc.h` does not exist in v7.2.** Patch 4/18 creates it, and it is
  where the series puts `freetype_t` plumbing, `gfp_freetype()`, the `ALLOC_*`
  flags, `ALLOC_UNMAPPED` and `ALLOC_NOBLOCK`. Five of the six mm-new commits
  that touch `mm/page_alloc.h` are in this series.
* Symbols the series references that v7.2 does not have at all: `ALLOC_DEFAULT`
  and `fastpath_alloc_flags` (5/18), `ALLOC_NO_CODETAG` (15/18), `ALLOC_NOLOCK`
  (1/18), one-arg `alloc_flags_cma()` (17/18).
* Patches 8–12 look irrelevant but cannot be dropped: 13/18 deletes
  `__alloc_pages_node()`, so the five treewide conversions have to come along or
  the tree stops building.
* 18/18 (`can_spin_trylock()` into `mm/internal.h`) is a textual dependency of
  the series' `__apply_to_page_range()` patches.

```
4a28f8182df02  1/18  mm/page_alloc: rename ALLOC_TRYLOCK -> ALLOC_NOLOCK
511b762e4bf2e  2/18  mm/page_alloc: some renames to clarify alloc_flags scopes   [conflict]
e11b5c372014f  3/18  mm: name some args in a function declaration
80bbff065d142  4/18  mm: split out internal page_alloc.h                         [conflict]
49b09a465b08d  5/18  mm/page_alloc: unify __alloc_frozen_pages[_nolock]_noprof() [conflict]
e3370af71626a  6/18  mm/page_alloc: relax GFP WARN in nolock allocs
4eb22c26077d1  7/18  mm: move some stuff to mm/page_alloc.h
9b777c01ef8cd  8/18  perf/x86/intel: use higher-level allocator API
3417d8f34b0c4  9/18  KVM: VMX: use higher-level allocator API
b7606739d1951 10/18  x86/virt: use higher-level allocator API
2b5d31f57a70e 11/18  sgi-xp: use higher-level allocator API
010455a92f7d8 12/18  net/funeth: switch to higher-level allocator API
d65ae4c5fbd14 13/18  mm: remove __alloc_pages_node()
82c49de332ab7 14/18  mm: move __alloc_pages() to mm/page_alloc.h
cf3b3031ef7f8 15/18  mm: replace __GFP_NO_CODETAG with ALLOC_NO_CODETAG
3c4fb0280718a 16/18  mm: remove the __GFP_NO_OBJ_EXT flag                        [conflict]
e71e6e115406c 17/18  mm/page_alloc: drop alloc_flags arg from alloc_flags_cma()
0650b25534f9f 18/18  mm: factor out can_spin_trylock()                           [conflict]
```

### 1.3 "mm: fix reclaim storms in defrag_mode" v2 — all 4 patches
<https://lore.kernel.org/20260722150006.3848560-1-hannes@cmpxchg.org>
(Johannes Weiner / Vlastimil Babka; all four carry
`Fixes: e3aa7df331bc ("mm: page_alloc: defrag_mode")` and `Cc: stable`)

```
67d0ba828358b  1/4  mm: page_alloc: __GFP_FS lockdep annotation for direct compaction
0e6379e728690  2/4  mm: compaction: support non-movable compaction for pageblock requests
17f165092b40d  3/4  mm: page_alloc: move capture_control to the page allocator
40685a0b21bb9  4/4  mm: page_alloc: fix non-movable reclaim storm in defrag_mode
```

A genuine hard dependency of series patch "mm/page_alloc: always direct compact
for unmapped allocs":

* 4/4 introduces the `compact_order` local in `__alloc_pages_direct_compact()`;
  the series adds its `FREETYPE_UNMAPPED` promotion right beside defrag_mode's.
  `compact_order` does not exist in v7.2.
* 3/4 reshapes `struct capture_control` from `{ struct compact_control *cc;
  struct page *page; }` to `{ zone, migratetype, order, page }`; the series then
  adds `capc->freetype` and a `freetype_flags(capc->freetype)` check in
  `compaction_capture()`.
* 2/4 changes `compaction_suit_allocation_order()` and the code around it; the
  series inserts a `bool unmapped` parameter and a
  `NR_FREE_PAGES_BLOCKS_MAPPED` branch into exactly that function.

### 1.4 folio-alloc-cleanups — 2 patches
<https://lore.kernel.org/all/20260716-folio-alloc-cleanups-v1-0-5363b8e92d33@google.com/>

```
c34a134c1f242  mm, treewide: replace __folio_alloc_node() with folio_alloc_node()  [conflict]
9c238f9b33a34  mm: move __folio_alloc() to page_alloc.h
```

The series' declared b4 prerequisite, and a hard one: `c34a134c1f242` frees up
the `__`-prefixed name by renaming `__folio_alloc_node()` →
`folio_alloc_node()`, and the series then re-introduces
`__folio_alloc_node_noprof(gfp, order, nid, alloc_flags)` as the new
mm-internal, alloc-flags-taking variant. In v7.2
`__folio_alloc_node_noprof()` still exists with the old 3-arg meaning, so
without this the series would collide with it rather than cleanly rename it.
`9c238f9b33a34` moves `__folio_alloc()` into `mm/page_alloc.h`, where two
later series patches edit it.

**The series' own empty b4 cover-letter commit (`b898edf7c7c9c`, "mm: yet more
cleanups for page_alloc APIs") was deliberately left out**, so this branch has
exactly one `b4-submit-tracking` block and `b4 prep` is not confused by two
cover letters.

### 1.5 ALLOC_UNMAPPED v4 — cover letter + 26 patches

`bb1cbf879bcc` … `1315774fcedd`, in the posted order, unchanged:

| # | group | conflicts |
|---|---|---|
| 1–3 | prep + `AS_NO_DIRECT_MAP` (slow path) | patch 3 |
| 4–8 | prep + x86 mm-local region | — |
| 9–12 | prep + the mermap | patch 11 |
| 13–15 | introduce freetypes | patch 13 |
| 16–25 | introduce `ALLOC_UNMAPPED` | patch 19 |
| 26 | make `AS_NO_DIRECT_MAP` fast | — |

The cover letter commit was reworded: its "Based on mm-new, plus this series"
paragraph now names the prerequisites actually carried here, and the b4
`base-commit` was repointed from `512c82e906fe` (the stale mm-new base, which is
not even in this repository) to `11028ab62899`. The folio-alloc-cleanups
`change-id` prerequisite was dropped from the b4 tracking block since those
patches are now in-branch.

---

## 2. Dependencies *not* backported

### 2.1 Already upstream

**page_alloc-unmapped-prep v1**
(<https://lore.kernel.org/all/20260513-page_alloc-unmapped-prep-v1-0-dacdf5402be8@google.com/>)
landed for v7.2, so nothing to do:
`9c860d1d5` for_each_free_list(), `23378be82` find_suitable_fallback(),
`3687c0fd6` pageblock mask definitions, `248b144a8` + `62f272d2f` pindex
helpers.

### 2.2 Deliberately skipped

| series / commit | reason | cost |
|---|---|---|
| **spin-trylock-followup v3** (`0a542b255`, `d55a77a06`, `2b0016706`, `22d8ef49a`) | Textual only — the series never references `FPI_NOLOCK`. Skipped on request. | Context conflict in `mm: introduce freetype_t`; and `22d8ef49a`'s `VM_BUG_ON` removal interacts with folio-alloc-cleanups (see §3.6). |
| **alloc-nolock-fixes v1** (`8301dbaf7`, `cfbb069cd`) | Only needed as a base for spin-trylock-followup v3, which is skipped. | None observed. |
| **secretmem-highmem v2** (`ad66a8fe9`) | "We don't care about highmem." | `secretmem_file_create()` keeps `GFP_HIGHUSER`; see §3.5 for the (benign) consequence. |
| `7a496b133` mm/page_alloc: use existing highatomic reserves on the buddy fastpath | Unrelated mm patch by JP Kobryn. | Three conflicts (§3.1, §3.3, §3.7) — all mechanical. |
| `311ac72a0` mm: split out mm_init and memblock declarations from internal.h | The commit itself conflicts across four files on v7.2. | Two `mm/internal.h` conflicts (§3.2, §3.8). |
| `6beede602` / `6fba0356a` mm/mlock + `vma_flags_t` rework | Part of a large series. | One-line conflict in `mm/mlock.c` (§3.5). |
| `f51ae275a` mm: constify … alloc_context nodemask | Unrelated. | One `mm/internal.h` line (§3.2). |
| `855c42778` mm: gfp_types: fix `__GFP_ACCOUNT` documentation | Unrelated doc change. | One `gfp_types.h` comment (§3.4). |
| `79fef9054` mm: extract mm_prepare_for_swap_entries() helper | Unrelated. | Anchor context in `mm/internal.h` (§3.4b). |
| `531a2a8e5` mm: move alloc tag to mm | Unrelated. | `mm/Makefile` context (§3.7b). |
| `5350e41f0` `__ASSEMBLY__` → `__ASSEMBLER__`, `ab7eadaca` node_reclaim() return value, `e096cb81a`, `d47cf6797`, `63e392b13`, … | Pure adjacency. | Context only, no conflicts materialised. |

---

## 3. Conflict resolutions

Ten of the 52 commits conflicted, listed below in the order they were applied.
Each is also recorded in its own commit message. (The cover letter also carries
a `[ Backport to v7.2-rc5: ... ]` block, but that records its reword, not a
conflict.)

### 3.1 `mm/page_alloc: some renames to clarify alloc_flags scopes` (trylock 2/18)
**`mm/page_alloc.c`, 3 hunks.** Upstream this patch is a *pure rename*, because
`7a496b133` had already factored `gfp_to_alloc_flags_nonblocking()` out of
`gfp_to_alloc_flags()`. Without `7a496b133` there is no such helper.

Took only the renames later patches depend on:
`gfp_to_alloc_flags()` → `alloc_flags_slowpath()`, `gfp_to_alloc_flags_cma()` →
`alloc_flags_cma()`, and the local `alloc_flags` → `fastpath_alloc_flags` in
`__alloc_frozen_pages_noprof()`. The non-blocking logic stays inline in
`alloc_flags_slowpath()` as v7.2 has it, so `alloc_flags_nonblocking()` is
**not** introduced, and the
`fastpath_alloc_flags |= alloc_flags_nonblocking(gfp, order) & ALLOC_HIGHATOMIC;`
line is dropped — that is `7a496b133`'s functional change, not part of this
rename. Checked: no other commit in the backport references
`alloc_flags_nonblocking()`.

### 3.2 `mm: split out internal page_alloc.h` (trylock 4/18)
**`mm/internal.h`.** This patch deletes the 159-line block that moves into the
new `mm/page_alloc.h`. The deletion did not apply because mm-new also has
`f51ae275a` ("mm: constify … alloc_context nodemask"): mm-new's
`struct alloc_context` has `const nodemask_t *nodemask`, v7.2's has
`nodemask_t *nodemask`. That single line was the *only* difference across the
whole moved block, so the block was deleted as upstream does and the `const` was
then dropped again from `struct alloc_context` in the newly added
`mm/page_alloc.h`.

### 3.3 `mm/page_alloc: unify __alloc_frozen_pages[_nolock]_noprof()` (trylock 5/18)
**`mm/page_alloc.c`.** Same root cause as §3.1. Took the upstream hunk (guarding
the `alloc_flags_nofragment()` call with `!(alloc_flags & ALLOC_NOLOCK)`) and
dropped the one `alloc_flags_nonblocking()` line.

### 3.4 `mm: remove the __GFP_NO_OBJ_EXT flag` (trylock 16/18)
**`include/linux/gfp_types.h`.** mm-new carries `855c42778` ("mm: gfp_types: fix
`__GFP_ACCOUNT`, `GFP_KERNEL_ACCOUNT` documentation"), which reworded the
`__GFP_ACCOUNT` kernel-doc. Kept v7.2's "accounted to kmemcg" wording and only
removed the `__GFP_NO_OBJ_EXT` paragraph, which is what this patch actually
does.

### 3.4b `mm: factor out can_spin_trylock()` (trylock 18/18)
**`mm/internal.h`.** Upstream adds `can_spin_trylock()` immediately after
`mm_prepare_for_swap_entries()`, which comes from `79fef9054` and is not here.
Added only `can_spin_trylock()`, in the same place (end of `mm/internal.h`).
The `mm/page_alloc.c` and `mm/slub.c` hunks that remove the open-coded copies
applied cleanly, which confirms the factored-out helper is a faithful move of
v7.2's logic — including the UP/NMI case, so nothing from alloc-nolock-fixes v1
is silently required here.

### 3.5 `mm: introduce AS_NO_DIRECT_MAP` (series 3/26)
**`mm/mlock.c`.** mm-new carries Lorenzo's `vma_flags_t` rework, so
`vma_flags_same_pair()` there takes `new_vma_flags` where v7.2 passes
`&new_vma_flags`. Kept v7.2's call and applied only this patch's real change,
`vma_is_secretmem()` → `vma_has_no_direct_map()`.

**Plus a deliberate divergence:** `ad66a8fe9` ("mm/secretmem: don't allow
highmem folios") is not backported, so `secretmem_file_create()` still uses
`GFP_HIGHUSER` rather than `GFP_USER`. The `mm/secretmem.c` hunk applied
cleanly anyway.

Consequence on a kernel with both `CONFIG_HIGHMEM` and
`ARCH_HAS_SET_DIRECT_MAP` (in practice 32-bit arm): secretmem can still be
handed a highmem folio, for which `folio_zap_direct_map()` returns `-EINVAL`.
That error propagates out of `prep_add_unmapped_folio()` →
`filemap_add_folio()`, so the fault fails cleanly rather than misbehaving.
This is the same class of pre-existing v7.2 bug that `ad66a8fe9` fixes upstream
and is not made worse here. Pick up `ad66a8fe9` if highmem ever matters.

### 3.6 `mm, treewide: replace __folio_alloc_node() with folio_alloc_node()` (folio-alloc-cleanups)
**`include/linux/gfp.h`.** This patch deletes the static inline
`__folio_alloc_node_noprof()` and replaces it with an out-of-line
`folio_alloc_node_noprof()`, moving the `NUMA_NO_NODE` normalisation and
`warn_if_node_offline()` into `__folio_alloc_noprof()`. The deletion did not
apply because v7.2's inline still carries
`VM_BUG_ON(nid < 0 || nid >= MAX_NUMNODES)`, which mm-new had already dropped in
`22d8ef49a` — part of the spin-trylock-followup series that is deliberately not
backported.

Took the upstream replacement verbatim, so **that assert is lost for the folio
path** as a side effect. Upstream is removing it anyway, and the equivalent
assert in `alloc_pages_node_noprof()` is untouched here. The alternative —
re-adding it inside `__folio_alloc_noprof()` — was rejected because a later
series patch ("mm: plumb alloc flags into some alloc funcs") edits that function
body, and the divergence would just conflict again.

### 3.7 `x86/mm: introduce the mermap` (series 11/26)
**`mm/Makefile`.** mm-new has
`obj-$(CONFIG_MEM_ALLOC_PROFILING) += alloc_tag.o` at the end of the file from
`531a2a8e5` ("mm: move alloc tag to mm"). Added only
`obj-$(CONFIG_MERMAP) += mermap.o`.

### 3.8 `mm: introduce freetype_t` (series 13/26)
**`mm/internal.h`, one hunk.** On the `__putback_isolated_page()` declaration:
in mm-new the `extern void memblock_free_pages(...)` line that follows it in
v7.2 has already been moved out by `311ac72a0`. Applied the
`int mt` → `freetype_t freetype` change and kept the `memblock_free_pages()`
declaration in place.

Worth noting because this was expected to be the worst conflict of the backport
(`mm/internal.h` is the most-churned file in the mm-new delta — 31 commits touch
it): the rest of the patch, the bulk migratetype → freetype conversion across
`mm/page_alloc.c`, `mm/compaction.c`, `mm/page_isolation.c`, `mm/page_owner.c`,
`mm/page_reporting.c` and `mm/show_mem.c`, applied cleanly.

### 3.9 `mm/page_alloc: rename ALLOC_NON_BLOCK back to _HARDER` (series 19/26)
**`mm/page_alloc.c`.** Upstream one of the `ALLOC_NON_BLOCK` → `ALLOC_HARDER`
renames lands inside `alloc_flags_nonblocking()`, which does not exist here
(§3.1). Dropped that hunk and renamed the inline
`alloc_flags |= ALLOC_NON_BLOCK` in `alloc_flags_slowpath()` instead. Verified
no `ALLOC_NON_BLOCK` reference remains anywhere in the tree.

---

## 4. Verification of the result

### 4.1 The backported series is semantically identical to upstream's

`git diff <cover-letter> HEAD` was compared against
`git diff bb1cbf879 1315774fc` (the same 26 patches on mm-new). The whole
diff-of-diffs is 56 lines, and **every one is a context line** reflecting a
dependency that was not backported — `__ASSEMBLY__` vs `__ASSEMBLER__`,
`alloc_tag.o`/`execmem.o` in `mm/Makefile`, `memblock_free_pages()`,
`&new_vma_flags`, `#include "shuffle.h"` vs `"mm_init.h"`,
`FPI_TRYLOCK` vs `FPI_NOLOCK`, `const nodemask_t`, `GFP_HIGHUSER` —
**except** for exactly one relocated `+`/`-` pair:

```
< -	alloc_flags |= ALLOC_NON_BLOCK;      # upstream: inside alloc_flags_nonblocking()
< +	alloc_flags |= ALLOC_HARDER;
> -			alloc_flags |= ALLOC_NON_BLOCK;   # here: inline in alloc_flags_slowpath()
> +			alloc_flags |= ALLOC_HARDER;
```

which is §3.9. In other words: no series hunk was lost, weakened, or altered.

### 4.2 Build

`make mm/` completes with **no errors and no warnings** under x86_64
`defconfig`, which turns on the new code by default:

```
CONFIG_ARCH_SUPPORTS_MM_LOCAL_REGION=y   CONFIG_MM_LOCAL_REGION=y
CONFIG_ARCH_SUPPORTS_MERMAP=y            CONFIG_MERMAP=y
CONFIG_PAGE_ALLOC_UNMAPPED=y
```

so `mm/mermap.c` and all the `FREETYPE_UNMAPPED` paths did get compiled.

**Not yet built** (the VM this was done in is too small):
full `defconfig` / `allmodconfig` link, `arch/x86/`, `kernel/`, the treewide
`use higher-level allocator API` call sites in `drivers/`, `net/` and
`arch/x86/kvm/`, i386 + `CONFIG_X86_PAE` with and without PTI, and the KUnit
tests (`CONFIG_KUNIT` is off in defconfig, so
`mm/tests/mermap_kunit.c` and `mm/tests/page_alloc_kunit.c` have not been
compiled at all).

### 4.3 Suggested checks on a bigger machine

```sh
make -j$(nproc) defconfig      && make -j$(nproc)
make -j$(nproc) allmodconfig   && make -j$(nproc)
make -j$(nproc) ARCH=i386 defconfig && ./scripts/config --enable X86_PAE && make -j$(nproc)
#   ... and again with MITIGATION_PAGE_TABLE_ISOLATION toggled
./scripts/config --disable MERMAP --disable PAGE_ALLOC_UNMAPPED && make -j$(nproc)
./scripts/config --enable MEM_ALLOC_PROFILING && make -j$(nproc)   # ALLOC_NO_CODETAG

tools/testing/kunit/kunit.py run --arch=x86_64 "page_alloc.*" \
    --kconfig_add CONFIG_MERMAP=y --kconfig_add CONFIG_PAGE_ALLOC_UNMAPPED=y
tools/testing/kunit/kunit.py run --arch=x86_64 "mermap.*" \
    --kconfig_add CONFIG_MERMAP=y
```

Runtime: boot-test `memfd_secret()` on both the `AS_NO_DIRECT_MAP` slow path and
the `ALLOC_UNMAPPED` fast path, and sanity-check `vm.defrag_mode=1`, since the
reclaim-storm series is now in-branch and "always direct compact for unmapped
allocs" extends its compaction promotion.

---

## 4.4 A smaller alternative

Branch `claude/alloc-unmapped-backport-minimal-psfpcn` carries the same 26
patches over only the individually-required prerequisite commits (20 instead of
25, so 47 commits instead of 53), with its own
`alloc-unmapped-backport-notes-minimal.md`. Trimming saves five patches:
`e11b5c372`, `e3370af71`, `3c4fb0280`, `0650b2553` and `67d0ba828`. Prefer this
branch if you would rather the prerequisite series behave exactly as they will
upstream, or if the branch may be rebased forward onto a tree that has already
picked them up.

Two things that look droppable are not, and are documented there: `6176de146`
(without it the alloc-trylock rename stops being mechanical) and `0e6379e72`
(a functional dependency of the series' compaction promotion that no
symbol-level analysis can see).

---

## 5. Reproducing the dependency analysis

1. `git rev-list origin/master..bb1cbf879` → 619 candidate mm-new commits
   (`master` fetched with `--shallow-since=2026-06-01`, series history with
   `--shallow-exclude=master`).
2. For each of the 26 series patches, `git blame` the pre-image lines every hunk
   touches, ±6 lines of context, and keep blamed commits that are in the
   candidate set; iterate to a fixpoint → 32 commits.
3. Extract all 1606 identifiers from the series' added lines, subtract every
   identifier present anywhere in v7.2's `mm/ include/linux/ arch/x86/ lib/
   kernel/ fs/`, intersect with identifiers present in the mm-new base → exactly
   6 hard, build-breaking gaps: `ALLOC_DEFAULT`, `ALLOC_NOLOCK`,
   `ALLOC_NO_CODETAG`, `alloc_flags_cma`, `compact_order`,
   `fastpath_alloc_flags`.
4. Group the closure by the `Link:` trailers akpm adds → the series in §1
   and §2.2.
5. Spot-check APIs that exist in both trees but differ:
   `struct capture_control`, `compaction_suit_allocation_order()`,
   `__folio_alloc_node_noprof()`, and the existence of `mm/page_alloc.h`.
