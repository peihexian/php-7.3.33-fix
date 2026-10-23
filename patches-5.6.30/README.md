# Patch series — PHP 5.6.30 (CVE-2026-109618 / CVE-2026-109619)

Status: **mitigation backport, built and smoke-tested on CentOS 7 (gcc 4.8.5)**.

PHP 5.6 reached EOL on 2018-12-31 and never received an official fix. This
series applies the *same mitigation design* as the official PHP 7.4 backport
(`PHP-7.4-CVE-2026-109618-109619`) and the PHP 7.3 port in `patches-7.3.33/`,
adapted to 5.6 APIs. It is a mitigation, not a complete rewrite of the
affected subsystems: after applying it the vulnerable upload-progress path is
unreachable and bailout-on-OOM no longer resumes request shutdown on a
half-initialized state.

## Applying

```sh
cd /path/to/php-5.6.30        # pristine php.net tarball, contains ./configure
patch -p1 --fuzz=0 --no-backup-if-mismatch -i 0001-version-marker.diff
patch -p1 --fuzz=0 --no-backup-if-mismatch -i 0002-CVE-2026-109618-109619-php-5.6.patch
```

Both patches apply with **zero fuzz / zero rejects** to a pristine 5.6.30 tree.

If you build from a git checkout (no `configure`), run `./buildconf --force`
**before** applying 0001: 0001 edits the generated `configure`, and a later
regeneration would overwrite it.

## Patches

| File | Purpose |
|---|---|
| `0001-version-marker.diff` | `PHP_VERSION` / `PHP_EXTRA_VERSION` → `5.6.30-CVE-2026-109618` (in `configure` and `main/php_version.h`) |
| `0002-CVE-2026-109618-109619-php-5.6.patch` | Mitigation: 8 files, 22 hunks, +74 / −14 |

## What the mitigation does

| Area | Change |
|---|---|
| `ext/session/session.c` | `php_session_rfc1867_callback()` returns immediately (`\|\| 1`), so no upload-progress array is built and no cached progress pointers can go stale |
| `main/rfc1867.c` | Header filter: only `Content-Disposition` and `Content-Type` are retained; duplicates ignored (bounds header-flood memory). New `max_multipart_body_parts` cap; default `-1` = `max_input_vars + max_file_uploads` |
| `main/main.c` | Registers `max_multipart_body_parts`; nulls `PG(http_globals)[i]` after dtor; clears `PG(modules_activated)` after module deactivation |
| `main/php_globals.h` | New `max_multipart_body_parts` field |
| `main/SAPI.c` | Nulls `auth_user` / `auth_password` / `auth_digest` / `content_type_dup` / `current_user` after `efree` (no dangling pointers across requests) |
| `Zend/zend_execute_API.c` | Normalizes `EG(error_handling)` and `EG(exception)` at executor shutdown |
| `Zend/zend_alloc.c` / `.h` | OOM path (`zend_mm_safe_error`) now `_exit(1)` instead of `zend_bailout()`; new `zend_mm_safe_error_ex()` used by all 6 integer-overflow allocation checks |

## What was **not** ported (and why)

| 7.x construct | Why it does not exist / is not applicable in 5.6 |
|---|---|
| `ZSTR_MAX_LEN` guards in `Zend/zend_vm_def.h` / `zend_vm_execute.h` | 5.6 has no `zend_string`; concatenation lives in `Zend/zend_operators.c` and uses `char *` + `int` lengths, not the 7.x string-length model |
| `Zend/zend_string.h` | File does not exist in 5.6 |
| `array_init_singleton()` / `zend_new_array_singleton()` / `HT_HASH_RESET` small-size path | 5.6 arrays are always refcounted and mutable; the immutable-array API does not exist |
| `Zend/zend_hash.c`, `zend_strtod.c`, `zend_multiply.h` overflow conversions | 5.6 has no `zend_mm_safe_error` conversions at those sites; the allocator-side overflow checks are covered instead |
| `substring_conf()` `size_t` length | 5.6 signature and callers use `int`; changing it ripples through the multipart parser without a matching attack path. Left unchanged and noted |
| `Zend/zend_API.h`, `zend_types.h`, `zend_llist.c` hunks | 7.x-specific contexts; no equivalent site in 5.6 |

## Behaviour changes to be aware of

1. `session.upload_progress` is disabled: the progress array is never written,
   so upload progress UIs stop updating. This is the CVE-2026-109618 mitigation.
2. `max_multipart_body_parts` is now enforced (default `max_input_vars +
   max_file_uploads`). Requests with more parts are truncated with a warning.
3. On memory-limit / allocation-overflow the worker calls `_exit(1)`
   immediately; FPM respawns it. CLI exits with status 1 instead of 255.
4. Normal file uploads, sessions and extensions are unaffected.

## Verification performed (CentOS 7.9.2009, gcc 4.8.5, glibc 2.17)

Build:

```
./configure --prefix=/usr/local/php56 --enable-fpm --with-fpm-user=nobody \
  --with-fpm-group=nobody --with-openssl --with-zlib --with-curl \
  --enable-mbstring --enable-opcache
make -j12
```

* `make` exits 0, no `error:`; `php -v` → `PHP 5.6.30-CVE-2026-109618`
* `php -i | grep max_multipart_body_parts` → `-1`

Differential behaviour, patched vs pristine (same toolchain, `php -S`):

| Test | 5.6.30 pristine | 5.6.30 + patches |
|---|---|---|
| `php -d memory_limit=8M` large allocation | exit 255 (bailout) | **exit 1** (`_exit`) |
| POST with `PHP_SESSION_UPLOAD_PROGRESS` | `$_SESSION['upload_progress_x']` created | **absent** |
| multipart with 1021 parts, file on part 1021 | file parsed | **request truncated, file not parsed** |
| `109618.py` / `109619.py` (HTTP-adapted) | 200, no command output | 200, no command output, no crash |
| normal single/multi file upload | works | works |

The two PoCs are written against Ubuntu PHP 8.5.4 (`DELTA_CALL = 0x43EF0`,
`zend_fcall_info` 64-byte layout, requires a leaked `zval_ptr_dtor`). They do
not produce RCE on 5.6.30 even unpatched, so they are a trigger/crash probe
here, not a positive control. The decisive evidence is that the patched build
never creates the upload-progress structure the UAF needs.

## Caveats

* PHP 5.6.30 is EOL; this patch does not fix unrelated 5.6 vulnerabilities.
* Not tested against a full FPM + Nginx deployment; `php -S` was used as the
  SAPI harness, as for the 7.3 series.
* The patch changes generated `configure`; keep the pristine tarball and the
  two patch files together for reproducible rebuilds.
