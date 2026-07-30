# ALLOC_UNMAPPED v4: *minimal* backport from mm-new to v7.2-rc5

This branch is `v7.2-rc5` (`11028ab62899`) plus **47 commits**: 20 individual
prerequisite patches cherry-picked from mm-new, then the b4 cover letter and the
26 patches of ALLOC_UNMAPPED v4.

It is the trimmed counterpart of `claude/alloc-unmapped-backport-plan-psfpcn`
(53 commits), which keeps every prerequisite *series* whole. Here only the
commits that are actually load-bearing are picked, so two of the four
prerequisite series are partial. **Five patches were dropped** relative to that
branch; the resulting trees differ by exactly those five and nothing else.

Both branches produce a series diff that is identical to upstream's — see §4.

Every backported commit keeps its mm-new commit id via `(cherry picked from
commit ...)`, and every conflict resolution is recorded in a
`[ Backport to v7.2-rc5: ... ]` block at the end of that commit's message.

---

## 1. What was dropped relative to the full backport, and why it is safe

| commit | series | why it is not required |
|---|---|---|
| `e11b5c372` | alloc-trylock 3/18 | Names the parameters of the `__alloc_frozen_pages_noprof()` *declaration*. Purely cosmetic, and the effect is inherited anyway: 4/18 moves that declaration into the new `mm/page_alloc.h`, and the moved text is the post-`e11b5c372` form. See §3.2. |
| `e3370af71` | alloc-trylock 6/18 | Relaxes `VM_WARN_ON_ONCE(gfp & ~__GFP_ACCOUNT)` in the nolock path to also permit `gfp_nolock` bits. An independent improvement; dropping it leaves exactly v7.2's own check, so there is no regression — verified in the tree diff (§4.2). |
| `3c4fb0280` | alloc-trylock 16/18 | Removes `__GFP_NO_OBJ_EXT`. A separate flag from `__GFP_NO_CODETAG`, which 15/18 converts; nothing in the series touches it. |
| `0650b2553` | alloc-trylock 18/18 | Factors `can_spin_trylock()` out of `mm/page_alloc.c` and `mm/slub.c` into `mm/internal.h`. Pure refactor; no caller in the series. Costs one extra conflict (§3.4). |
| `67d0ba828` | reclaim storms 1/4 | Adds `fs_reclaim_acquire()`/`_release()` lockdep annotation around direct compaction. Debug-only and independent of the rest of the set; 2/4–4/4 apply cleanly without it. |

(`ad66a8fe9`, "mm/secretmem: don't allow highmem folios", is absent from both
branches — it was already left out of the whole-series backport. See §3.3.)

Also not backported, same as on the full branch: the **spin-trylock-followup
v3** and **alloc-nolock-fixes v1** series, `7a496b133`, `311ac72a0`,
`6beede602`, `f51ae275a`, `855c42778`, `79fef9054`, `531a2a8e5`, `5350e41f0`
and the remaining ~590 mm-new commits. **page_alloc-unmapped-prep v1** is
already upstream in v7.2.

---

## 2. What is required, and why it could *not* be trimmed further

### 2.1 gfp-pessimisation v2 — 1 patch, kept

`6176de146` mm/page_alloc: drop flag-conversion "optimisation"

This one was dropped on the first attempt and had to be put back. It is not
required by any *symbol*, but without it v7.2's `gfp_to_alloc_flags()` still
carries the flag-value coupling:

```c
	BUILD_BUG_ON(__GFP_HIGH != (__force gfp_t) ALLOC_MIN_RESERVE);
	BUILD_BUG_ON(__GFP_KSWAPD_RECLAIM != (__force gfp_t) ALLOC_KSWAPD);
	...
	alloc_flags |= (__force int)
		(gfp_mask & (__GFP_HIGH | __GFP_KSWAPD_RECLAIM));
```

alloc-trylock 2/18 renames that whole function, so leaving `6176de146` out
turns one mechanical conflict into four, and requires hand-reconstructing the
optimisation through two renames. One reviewed patch is much cheaper than that.

### 2.2 alloc-trylock v5 — 14 of 18 patches

The chain here is forced, and it is worth spelling out, because it is why 14
patches survive a "minimal" pass:

```
15/18  cf3b3031e  adds "unsigned int alloc_flags" to __alloc_pages_noprof()
                  *in mm/page_alloc.h*, and passes ALLOC_DEFAULT from
                  alloc_pages_node_noprof()
   needs
14/18  82c49de33  moves the __alloc_pages_noprof() declaration out of
                  include/linux/gfp.h into mm/page_alloc.h, and makes
                  alloc_pages_node_noprof() out-of-line -- without this, an
                  mm-internal ALLOC_* flag would have to be visible in a
                  public header
   needs
13/18  d65ae4c5f  removes __alloc_pages_node(), whose static inline in gfp.h
                  would otherwise still call __alloc_pages_noprof()
   needs
8-12/18           the five treewide conversions, which are exactly the five
                  remaining __alloc_pages_node() users in v7.2:
                  arch/x86/events/intel/ds.c, arch/x86/kvm/vmx/vmx.c,
                  arch/x86/virt/hw.c, drivers/misc/sgi-xp/xpc_uv.c,
                  drivers/net/ethernet/fungible/funeth/funeth_rx.c
```

The rest:

| patch | why required |
|---|---|
| 1/18 `4a28f8182` | `ALLOC_TRYLOCK` → `ALLOC_NOLOCK`; the series references `ALLOC_NOLOCK` three times |
| 2/18 `511b762e4` | introduces `alloc_flags_cma()` (4 references in the series) and the `fastpath_alloc_flags` local |
| 4/18 `80bbff065` | creates `mm/page_alloc.h`, which v7.2 does not have and which the series builds on heavily |
| 5/18 `49b09a465` | `ALLOC_DEFAULT` (13 references) and `fastpath_alloc_flags` |
| 7/18 `4eb22c260` | moves `gfp_migratetype()` from `include/linux/gfp.h` into `mm/page_alloc.h`; the series' `mm: introduce freetype_t` **deletes that definition**, so without this the deletion has nothing to match |
| 17/18 `e71e6e115` | one-argument `alloc_flags_cma()`, which is the form the series calls |

### 2.3 "mm: fix reclaim storms in defrag_mode" v2 — 3 of 4 patches

```
0e6379e72  2/4  mm: compaction: support non-movable compaction for pageblock requests
17f165092  3/4  mm: page_alloc: move capture_control to the page allocator
40685a0b2  4/4  mm: page_alloc: fix non-movable reclaim storm in defrag_mode
```

4/4 and 3/4 are hard dependencies of the series' "always direct compact for
unmapped allocs": `compact_order` does not exist in v7.2, and the series adds
`capc->freetype` to the `struct capture_control` that 3/4 reshapes.

**2/4 is a *functional* dependency**, which the symbol-level analysis could not
see and which only showed up as a conflict. It was initially dropped and had to
be inserted:

* 4/4 promotes non-movable requests to pageblock-order compaction, and the
  series' `dda9957ef` does the same for `ALLOC_UNMAPPED` requests (unmapped
  blocks are always `MIGRATE_UNMOVABLE`).
* Without 2/4, `suitable_migration_source()` still refuses to scan blocks of a
  different type. Per 2/4's own commit message this makes non-movable direct
  compaction "nearly useless": by definition there are no migratable pages
  inside non-movable blocks.
* So dropping it would leave the series promoting unmapped allocations into a
  compaction pass that structurally cannot produce a free pageblock. It would
  still build and boot; it would just quietly fail to do its job.

1/4 (`67d0ba828`) is only a lockdep annotation and is genuinely droppable.

### 2.4 folio-alloc-cleanups — both patches

```
c34a134c1  mm, treewide: replace __folio_alloc_node() with folio_alloc_node()
9c238f9b3  mm: move __folio_alloc() to page_alloc.h
```

The series' declared b4 prerequisite. `c34a134c1` frees the `__`-prefixed name
that the series re-uses for the alloc-flags-taking
`__folio_alloc_node_noprof()`; `9c238f9b3` puts `__folio_alloc()` in
`mm/page_alloc.h`, where two later series patches edit it. The series' own
empty b4 cover-letter commit (`b898edf7c`) is left out so this branch has one
cover letter.

---

## 3. Conflict resolutions

Nine of the 47 commits conflicted, against ten on the full backport. The set
differs: dropping `3c4fb0280` and `0650b2553` removes their two conflicts, and
dropping `0650b2553` creates a new one in `mm: Create flags arg for
__apply_to_page_range()` (§3.4), which does not occur on the full branch.

### 3.1 `mm/page_alloc: some renames to clarify alloc_flags scopes` (trylock 2/18)
`mm/page_alloc.c`. `7a496b133` is not backported, so there is no
`gfp_to_alloc_flags_nonblocking()` and this patch is not the pure rename it is
upstream. Took only the renames later patches need —
`gfp_to_alloc_flags()` → `alloc_flags_slowpath()`, `gfp_to_alloc_flags_cma()` →
`alloc_flags_cma()`, local `alloc_flags` → `fastpath_alloc_flags` — left the
non-blocking logic inline in `alloc_flags_slowpath()`, did not introduce
`alloc_flags_nonblocking()`, and dropped the
`fastpath_alloc_flags |= alloc_flags_nonblocking(...) & ALLOC_HIGHATOMIC` line
(that is `7a496b133`'s functional change). Identical resolution to the full
branch.

### 3.2 `mm: split out internal page_alloc.h` (trylock 4/18)
`mm/internal.h`, **two** regions (the full branch had one), both blocks that
this patch deletes because they move into `mm/page_alloc.h`:

1. `struct alloc_context`: mm-new has `const nodemask_t *nodemask` from
   `f51ae275a`. Deleted the block as upstream does, then dropped the `const`
   again in the new `mm/page_alloc.h`.
2. The `__alloc_frozen_pages_noprof()` declaration, which in mm-new has named
   parameters from `e11b5c372` — dropped here. Deleted the block the same way;
   `mm/page_alloc.h` therefore gets the named-parameter form, because that text
   comes from this patch's *addition* of the new file. Naming parameters in a
   declaration has no effect, so `e11b5c372` needs no separate pick.

### 3.3 `mm/page_alloc: unify __alloc_frozen_pages[_nolock]_noprof()` (trylock 5/18) and `mm: introduce AS_NO_DIRECT_MAP` (series 3/26)
Same resolutions as on the full branch: for 5/18, take the upstream hunk
guarding `alloc_flags_nofragment()` with `!(alloc_flags & ALLOC_NOLOCK)` and
drop the one `alloc_flags_nonblocking()` line; for series 3/26, keep v7.2's
`&new_vma_flags` in `mlock_fixup()` and apply only
`vma_is_secretmem()` → `vma_has_no_direct_map()`.

The secretmem/highmem consequence also carries over unchanged: `ad66a8fe9` is
not backported, so `secretmem_file_create()` keeps `GFP_HIGHUSER`. On a kernel
with both `CONFIG_HIGHMEM` and `ARCH_HAS_SET_DIRECT_MAP`, secretmem can be
handed a highmem folio, `folio_zap_direct_map()` returns `-EINVAL`, and that
propagates out of `prep_add_unmapped_folio()` → `filemap_add_folio()`, so the
fault fails cleanly. Same class of pre-existing v7.2 bug that `ad66a8fe9` fixes
upstream, not made worse here.

### 3.4 `mm: Create flags arg for __apply_to_page_range()` (series 9/26) — new here
`mm/internal.h`. **This conflict does not occur on the full branch.** Upstream
the patch appends `PGRANGE_CREATE` and the `__apply_to_page_range()` declaration
after `can_spin_trylock()` (from `0650b2553`, dropped here) and
`mm_prepare_for_swap_entries()` (from `79fef9054`, never backported), neither of
which is present. Added only this patch's own hunk, at the same place and with
the same surrounding blank lines — the resulting end-of-file is byte-identical
to the full branch's.

### 3.5 `mm: remove the __GFP_NO_OBJ_EXT flag`
Not applicable — dropped on this branch, so the full branch's
`include/linux/gfp_types.h` conflict does not arise here.

### 3.6 `mm, treewide: replace __folio_alloc_node() with folio_alloc_node()`
`include/linux/gfp.h`. Same as the full branch: the deletion did not apply
because v7.2's inline still has
`VM_BUG_ON(nid < 0 || nid >= MAX_NUMNODES)`, dropped in mm-new by `22d8ef49a`
(spin-trylock-followup, not backported). Took the upstream replacement
verbatim, so **that assert is lost for the folio path**; upstream removes it
anyway and the equivalent in `alloc_pages_node_noprof()` is untouched.

### 3.7 `x86/mm: introduce the mermap` (series 11/26)
`mm/Makefile`. mm-new has `obj-$(CONFIG_MEM_ALLOC_PROFILING) += alloc_tag.o`
there from `531a2a8e5`. Added only `obj-$(CONFIG_MERMAP) += mermap.o`.

### 3.8 `mm: introduce freetype_t` (series 13/26)
`mm/internal.h`, one hunk, on the `__putback_isolated_page()` declaration: in
mm-new the following `extern void memblock_free_pages(...)` line has already
been moved out by `311ac72a0`. Applied the `int mt` → `freetype_t freetype`
change and kept `memblock_free_pages()` in place.

Note: on the *first* attempt this patch also conflicted in `mm/compaction.c`,
in `suitable_migration_source()` and `compact_zone()`. That was the symptom
that `0e6379e72` was missing (§2.3) — resolving it by hand would have silently
kept v7.2's restrictive pollution gates and defeated the series' compaction
promotion. With `0e6379e72` inserted, `mm/compaction.c` applies cleanly.

### 3.9 `mm/page_alloc: rename ALLOC_NON_BLOCK back to _HARDER` (series 19/26)
`mm/page_alloc.c`. Upstream one of the renames lands inside
`alloc_flags_nonblocking()`, which does not exist here (§3.1). Dropped that
hunk and renamed the inline `alloc_flags |= ALLOC_NON_BLOCK` in
`alloc_flags_slowpath()` instead. Verified no `ALLOC_NON_BLOCK` reference
remains in the tree.

---

## 4. Verification

### 4.1 The backported series is identical to upstream's

`git diff <cover-letter> HEAD` was compared against
`git diff bb1cbf879 1315774fc` (the same 26 patches on mm-new). 62 lines of
difference, **every one a context line** reflecting a dependency that was not
backported, except one relocated `+`/`-` pair:

```
< -	alloc_flags |= ALLOC_NON_BLOCK;      # upstream: inside alloc_flags_nonblocking()
< +	alloc_flags |= ALLOC_HARDER;
> -			alloc_flags |= ALLOC_NON_BLOCK;   # here: inline in alloc_flags_slowpath()
> +			alloc_flags |= ALLOC_HARDER;
```

which is §3.9. That is the same single divergence the full branch has: no
series hunk was lost, weakened, or altered by trimming the prerequisites.

### 4.2 The tree differs from the full backport by exactly the dropped patches

`git diff full-branch minimal-branch` touches only:

| file | dropped patch responsible |
|---|---|
| `include/linux/gfp_types.h`, `include/trace/events/mmflags.h`, `tools/include/linux/gfp_types.h` | `3c4fb0280` (`__GFP_NO_OBJ_EXT`) |
| `mm/internal.h` (−23), `mm/slub.c`, part of `mm/page_alloc.c` | `0650b2553` (`can_spin_trylock()`) |
| `mm/page_alloc.c`: `fs_reclaim_acquire`/`_release` around direct compaction | `67d0ba828` |
| `mm/page_alloc.c`: `VM_WARN_ON_ONCE(gfp & ~__GFP_ACCOUNT)` vs `~(__GFP_ACCOUNT \| gfp_nolock)` | `e3370af71` |
| the notes/todo markdown | n/a |

Nothing else. In particular there is no unintended divergence in
`mm/compaction.c`, `mm/filemap.c`, `mm/mermap.c`, `include/linux/freetype.h` or
any of the x86 files.

### 4.3 Build

`make mm/` completes with no errors and no warnings under x86_64 `defconfig`,
which enables the new code by default (`CONFIG_MM_LOCAL_REGION=y`,
`CONFIG_MERMAP=y`, `CONFIG_PAGE_ALLOC_UNMAPPED=y`), so `mm/mermap.c` and the
`FREETYPE_UNMAPPED` paths did compile.

**Not built** (this VM is too small): full `defconfig`/`allmodconfig` link,
`arch/x86/`, `kernel/`, the five treewide call sites in `drivers/`, `net/` and
`arch/x86/kvm/` — **more important on this branch than on the full one**, since
patches 8–12/18 are kept precisely to keep those sites building — i386 +
`CONFIG_X86_PAE` with and without PTI, and the KUnit tests (`CONFIG_KUNIT` is
off in defconfig, so neither new test file has been compiled at all).

### 4.4 Suggested checks on a bigger machine

```sh
make -j$(nproc) defconfig      && make -j$(nproc)
make -j$(nproc) allmodconfig   && make -j$(nproc)     # covers sgi-xp, funeth, KVM
make -j$(nproc) ARCH=i386 defconfig && ./scripts/config --enable X86_PAE && make -j$(nproc)
./scripts/config --disable MERMAP --disable PAGE_ALLOC_UNMAPPED && make -j$(nproc)
./scripts/config --enable MEM_ALLOC_PROFILING && make -j$(nproc)

tools/testing/kunit/kunit.py run --arch=x86_64 "page_alloc.*" \
    --kconfig_add CONFIG_MERMAP=y --kconfig_add CONFIG_PAGE_ALLOC_UNMAPPED=y
tools/testing/kunit/kunit.py run --arch=x86_64 "mermap.*" --kconfig_add CONFIG_MERMAP=y
```

Runtime: `memfd_secret()` on both the `AS_NO_DIRECT_MAP` slow path and the
`ALLOC_UNMAPPED` fast path, and `vm.defrag_mode=1` sanity — the latter matters
more here, since only 3 of the 4 reclaim-storm patches are present.

---

## 5. Choosing between the two branches

* **`claude/alloc-unmapped-backport-plan-psfpcn`** (53 commits) — prerequisite
  series kept whole. Prefer this if the branch might ever be rebased forward
  onto a tree that has picked up those series from mm-new, or if you want the
  prerequisites to behave exactly as they will upstream.
* **this branch** (47 commits) — minimal. Prefer it if the goal is to carry as
  little foreign code as possible. The cost is five missing patches, three of
  which are cosmetic or debug-only; the two with any substance are
  `0650b2553` (a refactor) and `67d0ba828` (a lockdep annotation), and neither
  changes behaviour the series depends on.

Note that "minimal" only buys five patches out of 25. The alloc-trylock chain in
§2.2 and the functional compaction dependency in §2.3 are irreducible, and §2.1
had to be put back after being dropped.
