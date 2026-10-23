# Port report — CVE-2026-109618 / CVE-2026-109619 on PHP 7.3.33

Date: 2026-10-22
Subject tree: `php-7.3.33/php-7.3.33` (official `php.net` 7.3.33 tarball, extracted, unmodified)
Reference: `images/7.4-fpm-bullseye/patches/0002-CVE-2026-109618-109619-official-php-7.4.patch`
(official 7.4 backport, commit `712e60f9edfd03f0960fc4fc3c2c375f42b90aa2`)
Deliverable: `patches-7.3.33/0001-version-marker.diff`,
`patches-7.3.33/0002-CVE-2026-109618-109619-php-7.3.patch`

## 1. Verdict

**The official 7.4 patch cannot be used directly on PHP 7.3.33.**

Dry-run against the pristine 7.3.33 tree with `patch -p1 --fuzz=0`:

| | |
|---|---|
| Hunks in the official patch | 78 |
| Hunks applied | 45 |
| **Hunks rejected** | **33** |
| Files with rejected hunks | 6 of 17 |

Failing hunks per file:

| File | Hunks | Rejected |
|---|---|---|
| `Zend/zend_alloc.c` | 9 | 1 |
| `Zend/zend_alloc.h` | 1 | 1 |
| `Zend/zend_execute_API.c` | 2 | 2 |
| `Zend/zend_hash.h` | 1 | 1 |
| `Zend/zend_vm_def.h` | 4 | 3 |
| `Zend/zend_vm_execute.h` | 34 | 25 |
| (11 other files) | 26 | 0 |

Rejecting is the benign outcome. The dangerous outcome is that a partially
applied tree would also **not compile**, because the patch depends on
`ZSTR_MAX_LEN`, which does not exist anywhere in 7.3 (`ZSTR_MAX_OVERHEAD` /
`ZSTR_MAX_LEN` were introduced in 7.4). Even a fuzz-tolerant apply
(`--fuzz=2`/`3`) therefore produces a broken tree, not a working one, and would
additionally mis-place hunks inside `zend_vm_execute.h`.

So the fix was **ported**, not force-applied.

## 2. Root causes

1. **Missing API.** `ZSTR_MAX_LEN` / `ZSTR_MAX_OVERHEAD` (`Zend/zend_string.h`,
   7.4 only). Used by the overflow guards added in `zend_vm_*.h`.
2. **`shutdown_executor()` restructured.** In 7.4 the non-fast path is
   `if (!fast_shutdown)`, followed by
   `zend_objects_store_free_object_storage()`, followed by
   `zend_weakrefs_shutdown()`. In 7.3 it is `if (fast_shutdown) { … } else { … }`
   with `zend_objects_store_free_object_storage()` *before* the branch and **no**
   `zend_weakrefs_shutdown()` (WeakReference is 7.4+). Both official hunks
   therefore have no anchor.
3. **VM handler bodies differ.** `ZEND_CONCAT`'s in-place branch already had a
   `ZSTR_MAX_LEN` guard in 7.4, which the official patch re-pointed to
   `zend_mm_safe_error_ex()`; 7.3 has **no** such guard at all. Operand release
   is `FREE_OPn()` in 7.3 vs explicit
   `if (OPn_TYPE & (IS_TMP_VAR|IS_VAR)) zend_string_release_ex(…)` in 7.4, so
   every "insert a guard into the `else` branch" hunk also fails.
4. **Minor anchor drift.** 7.3 wraps `<signal.h>` in `HAVE_SIGNAL_H`
   (`zend_alloc.c`); 7.3's `zend_alloc.h` tail is the commented-out APC block with
   no `zend_mm_globals_size()`; 7.3's `zend_hash.h` has no `zend_new_pair()`.

The remaining 45 hunks (session, multipart parser, SAPI, main, GPC variables,
hash/strtod/multiply overflow conversions, `HT_HASH_RESET`, `zend_llist`) applied
verbatim, only with line offsets — the code they target is identical in 7.3.

## 3. What the port does

Every fix of the official patch is reproduced; only anchors and 7.4-only
constructs were adapted (details and rationale in `README.md`, table there).
Net: 18 files, 60 hunks, +264/−52 — i.e. the 17 official files plus
`Zend/zend_string.h`, with `zend_vm_execute.h` folded from 34 hunks to 17
(one per handler) plus 8 in-place guards, instead of 8 "replace" + 26 "insert".

No mitigation was dropped or weakened: the `_exit(1)` conversions, the
`session.upload_progress` shutdown, the multipart header/body-part limits, the
SAPI/global resets and the concat overflow guards are all present.

## 4. Verification performed

**V1 — clean application (strict).** Both patches applied in order to a fresh
copy of the pristine tree with `patch -p1 --fuzz=0`:

```
patching file configure … patching file main/rfc1867.c
exit codes: 0, 0   rejects: 0   files patched: 20/20
```

**V2 — reproducibility (byte level).** SHA256 comparison of all **20,147** files
between the reviewed work tree and the independently patched tree:
**0 differences**. The patch series is exactly the reviewed change set, nothing
else.

**V3 — semantic parity with the official 7.4 backport.** The official patch was
applied to a pristine 7.4.33 tree (it applies 100% cleanly — control), then the
counts of every mitigation construct were compared across the 18 touched files:

| construct | 7.3.33 port | 7.4.33 official |
|---|---|---|
| `zend_mm_safe_error_ex(` | 53 | 53 |
| `_exit(1)` | 3 | 3 |
| `ZSTR_MAX_LEN` | 39 | 39 |
| `array_init_singleton(` | 5 | 5 |
| `zend_new_array_singleton` | 3 | 3 |
| `max_multipart_body_parts` | 3 | 3 |
| `body_parts_cnt` | 5 | 5 |
| `php_mime_should_save_hdr` | 2 | 2 |
| `SG(request_info).*= NULL` | 22 | 22 |
| `PG(modules_activated) = 0` | 2 | 2 |
| `ZVAL_UNDEF(&PG(http_globals)[i])` | 1 | 1 |
| `EG(objects_store).object_buckets = NULL` | 1 | 1 |
| `EG(error_handling) = EH_NORMAL` | 2 | 2 |
| `|| true` (session) | 1 | 1 |
| `substring_conf(char *start, size_t len` | 1 | 1 |

All 15 match. Residual deprecated patterns (`zend_error_noreturn(E_ERROR,
"Possible integer overflow…")`, `heap->overflow`) are also identical in both
patched trees.

**V4 — VM guard symmetry.** Per-handler guard placement in the generated
`Zend/zend_vm_execute.h`, computed independently for both patched trees:

| | in-place branch | allocating branch | total | handlers |
|---|---|---|---|---|
| 7.3.33 port | 17 | 17 | 34 | 17 |
| 7.4.33 official | 17 | 17 | 34 | 17 |

Handler sets are identical (same 17 `ZEND_CONCAT_SPEC_*` / `ZEND_FAST_CONCAT_SPEC_*`
names). Each handler has exactly one in-place guard and one allocating-branch
guard; the second-phase allocation inside FAST_CONCAT handlers is deliberately
left untouched, as in the official patch.

**V5 — dependency check.** Every symbol the new code uses exists in 7.3.33:

* `zend_is_executing`, `zend_get_executed_filename_ex`,
  `zend_get_executed_lineno` — `Zend/zend_execute.h:297-301`
* `zend_is_compiling`, `zend_get_compiled_filename`,
  `zend_get_compiled_lineno` — `Zend/zend_compile.h:730,731,806`
  (pulled in by `zend_execute.h`, which `zend_alloc.c` now includes)
* `ZEND_MM_ALIGNED_SIZE` — `zend_alloc.h`, included by `zend.h` **before**
  `zend_string.h`, so the added `ZSTR_MAX_*` macros are well-ordered
* `HT_INVALID_IDX` — the small-size branch added to `HT_HASH_RESET` uses the same
  `memset(..., HT_INVALID_IDX, …)` idiom as the existing non-SSE fallback
* every user of `zend_mm_safe_error_ex()` (`zend_hash.c`, `zend_multiply.h`,
  `zend_strtod.c`, `zend_vm_*.h`, `zend_alloc.c`) reaches its declaration
  through `zend.h` → `zend_alloc.h`

**V6 — scope check.** Changed-file set is exactly the 18 expected files; no
file added or deleted; `zend_vm_def.h` (source) and `zend_vm_execute.h`
(generated) changed in lockstep. The only remaining `zend_bailout()` calls in
`zend_vm_execute.h` are the four `ZEND_EXIT` handlers, which neither the
official patch nor this port touches.

## 5. What was **not** verified (and why)

No compile or runtime test could be performed on this host: it has no PHP
toolchain, no `make`, no Docker and no WSL distribution, and PHP cannot be built
natively with MinGW (the Windows build requires MSVC). Verification above is
therefore source-level and equivalence-based; it is strong (the port is
site-for-site identical to the official 7.4 fix), but it is not a build.

Build-verify before shipping (Linux, amd64), roughly:

```sh
curl -LO https://museum.php.net/php7/php-7.3.33.tar.xz && tar xf php-7.3.33.tar.xz
cd php-7.3.33
for p in <series>/0001-version-marker.diff <series>/0002-CVE-2026-109618-109619-php-7.3.patch; do
	patch -p1 --no-backup-if-mismatch -i "$p"
done
./configure --enable-fpm --with-fpm-user=www-data --with-fpm-group=www-data \
            --with-openssl --with-zlib --with-curl --enable-mbstring --enable-opcache
make -j"$(nproc)"
./sapi/cli/php -v          # expect: PHP 7.3.33-CVE-2026-109618
```

Then a functional smoke test rather than only a build:

1. `php -i | grep max_multipart_body_parts` → present, default `-1`
   (effective limit = `max_input_vars + max_file_uploads`).
2. Normal multipart upload (single and multi-file) still works and `$_FILES`
   is populated; only `Content-Disposition`/`Content-Type` are retained in the
   parsed headers, duplicates ignored.
3. `session.upload_progress.enabled=1` no longer triggers the upload-progress
   session write path at request startup; ordinary sessions still work.
4. A memory-limit-triggering request aborts the FPM worker with
   `Fatal error: Allowed memory size …` on stderr and the worker exits
   (`_exit(1)`) rather than recovering — this is the intended, deliberate
   behaviour change.
5. `Zend/zend_vm_execute.h` consistency: if a future rebuilds regenerates it via
   `Zend/zend_vm_gen.php`, the output must contain the same 34 guards.

## 6. Follow-ups not in scope

* A `images/7.3-fpm-bullseye` (or Alpine) variant and Debian/rpm package
  builders for 7.3.33 — the existing 7.4 packaging directories can be cloned,
  but they would need a real build/test cycle on Linux.
* The project's overall roadmap item "additional legacy PHP versions
  (7.0, 7.1, 7.2)": each of those needs its own audit; the 7.3 adaptation here
  is a template for the VM-file handling, but the anchors shift again per branch.
