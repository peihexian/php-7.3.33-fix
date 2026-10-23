# Patch series — PHP 7.3.33 (CVE-2026-109618 / CVE-2026-109619)

Drop-in patch series for a **pristine PHP 7.3.33 source tree** (official
`php.net` tarball). It is the backport of the official PHP 7.4 security
backport, re-anchored for 7.3.33.

> PHP 7.3 reached EOL on 2021-12-06. There is **no** official 7.3 build of this
> fix — the official mitigation only exists for 7.4
> (`PHP-7.4-CVE-2026-109618-109619`). This series is a port, not an upstream
> artifact: every fix of the official patch is reproduced, with the anchors and
> the handful of 7.4-only constructs adapted. See
> [`PORT-REPORT.md`](PORT-REPORT.md) for the hunk-by-hunk analysis and the
> verification evidence.

## Applying

```sh
cd php-7.3.33
for p in 0001-version-marker.diff 0002-CVE-2026-109618-109619-php-7.3.patch; do
	patch -p1 --no-backup-if-mismatch --input="$p"
done
```

Applies with **zero fuzz** (`--fuzz=0`) to an unmodified 7.3.33 tree.

On Windows/MSYS hosts whose GNU `patch` is the old 2.5.9 build (e.g. Strawberry
Perl), add `--binary`; that build otherwise asserts in text mode when reading an
LF-only patch file. It is a host quirk, not a problem with the patch — on Linux
(the actual build environment) `patch` 2.7.x applies it as-is.

## Patches

| File | Purpose |
|---|---|
| `0001-version-marker.diff` | Stamps `PHP_VERSION` as `7.3.33-CVE-2026-109618` |
| `0002-CVE-2026-109618-109619-php-7.3.patch` | CVE-2026-109618 / CVE-2026-109619 mitigation, ported from the official 7.4 backport |

18 files changed, 60 hunks, +264 / −52.

## Relationship to the 7.4 series

Source of the fix:
[`PHP-7.4-CVE-2026-109618-109619`](https://github.com/php/php-src/tree/PHP-7.4-CVE-2026-109618-109619),
commit [`712e60f9`](https://github.com/php/php-src/commit/712e60f9edfd03f0960fc4fc3c2c375f42b90aa2),
*"Avoid state corruption via bailout — Minimal mitigation for EOL version"*
(Arnaud Le Blanc, co-authored by Ilija Tovilo).

The official 7.4 patch does **not** apply to 7.3.33: 33 of its 78 hunks fail,
and it references `ZSTR_MAX_LEN`, which does not exist in 7.3 at all. Five
adaptations were required; none of them changes the mitigation itself:

| # | File | Why 7.3 differs | Adaptation |
|---|---|---|---|
| 1 | `Zend/zend_string.h` | `ZSTR_MAX_OVERHEAD` / `ZSTR_MAX_LEN` were introduced in 7.4 | Added verbatim from 7.4 |
| 2 | `Zend/zend_alloc.c` | 7.3 wraps `<signal.h>` in `HAVE_SIGNAL_H`, so the include hunk has no anchor | `#include "zend_execute.h"` inserted after `zend_bitset.h` |
| 3 | `Zend/zend_alloc.h` | 7.3 has no `zend_mm_globals_size()` declaration (that tail is the commented-out APC block) | Declaration emitted before `END_EXTERN_C()` |
| 4 | `Zend/zend_execute_API.c` | `shutdown_executor()` in 7.3 has the `fast_shutdown` branch **inverted** vs 7.4, calls `zend_objects_store_free_object_storage()` *before* it, and has no `zend_weakrefs_shutdown()` | Handler/object-store resets placed in 7.3's `if (fast_shutdown)` branch; `EG(error_handling)`/`EG(exception)` normalized after table teardown |
| 5 | `Zend/zend_vm_def.h`, `Zend/zend_vm_execute.h` | 7.3's `ZEND_CONCAT` has no pre-existing `ZSTR_MAX_LEN` guard (7.4's already had one, which the official patch merely re-pointed at `zend_mm_safe_error_ex`), operands are released with `FREE_OPn()` instead of explicit `zend_string_release_ex()`, and `zend_new_pair()` does not exist | Guards added to **both** the in-place and the allocating branch of all 17 generated handlers (34 sites), keeping the generated file consistent with `zend_vm_def.h` |

`zend_vm_execute.h` is a generated file (`Zend/zend_vm_gen.php`). No PHP
interpreter was available to regenerate it, so it was edited to match what the
generator emits for the patched `zend_vm_def.h`; the per-handler guard
distribution is identical to the official patched 7.4 tree (17 in-place +
17 else-branch guards).

## What the mitigation does (unchanged from official)

* **CVE-2026-109618** — `ext/session/session.c`: `session.upload_progress` is
  disabled in `php_session_rfc1867_callback()` (`|| true`), so no untrusted
  session deserialization happens before RINIT.
* **CVE-2026-109619** — `main/rfc1867.c`: only `Content-Disposition` and
  `Content-Type` headers are kept, duplicates are ignored, and
  `max_multipart_body_parts` (default `max_input_vars + max_file_uploads`)
  caps the number of body parts; `substring_conf()` uses `size_t` lengths.
* **Bailout/OOM** — `Zend/zend_alloc.c` and friends: memory-limit and
  integer-overflow conditions call `zend_mm_safe_error_ex()` → `_exit(1)`
  instead of `zend_bailout()` (`longjmp`) into half-initialized shutdown state.
  Concatenation overflow is guarded in `zend_vm_def.h` / `zend_vm_execute.h`.
* **State hygiene** — `main/SAPI.c` nulls the deallocated `auth_*`,
  `content_type_dup` and `current_user` pointers; `main/main.c` registers
  `max_multipart_body_parts`, undefines `PG(http_globals)` and clears
  `PG(modules_activated)` on request shutdown; `Zend/zend_execute_API.c`
  normalizes error-handler stacks, `EG(error_handling)` and `EG(exception)`;
  `main/php_variables.c` uses `array_init_singleton()` (with
  `zend_new_array_singleton()` and the small-size `HT_HASH_RESET` fix) so GPC
  arrays no longer force the 64-byte SSE reset path.

Normal file uploads and sessions are unaffected; no configuration or opt-outs
are needed.
