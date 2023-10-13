# Addendum readme for the wolfssl xmss-reference integration patch

This patch contains a number of changes that were primarily motivated to
facilitate wolfBoot XMSS support for embedded-targets. Specifically, the
following changes have been made:

- All variable-length arrays (VLAs) necessary have been guarded with the define
  `WOLFBOOT_SIGN_XMSS`, and replaced with static compile-time constant arrays,
  with constants such as `XMSS_SHA256_WOTS_LEN` that have been defined in `params.h`.
  They assume that the choice of SHA256 as the hashing function is a compile
  time constant, and the function `core_hash()` has been updated to reflect this.
  The param parsing logic in `params.c` has not been touched though, to allow for
  in the future changing the underlying hash function at compile time if desired.
- The signing and verifying APIs (`xmss_sign()`, `xmssmt_sign()`,`xmss_sign_open()`,
  `xmssmt_sign_open()`) have been updated so that the message and signature are
  passed as separate args, rather than a concatenated array. Additionally, for
  wolfBoot builds the message length has been restricted to the compile time
  constant of `XMSS_SHA256_MAX_MSG_LEN`. The appropriate APIs have had their
  comments updates, and include an additional comment explaining this:
```
 * Note: in WOLFBOOT_SIGN_XMSS build, the max allowed message length (msglen)
 * is XMSS_SHA256_MAX_MSG_LEN. This is to facilitate having a manageable small
 * static array, rather than a variable length array, for the message hash.
```
- SHA256 and RNG operations are handled by registered callback functions. See
  the header `xmss_callbacks.h` for the callback setter functions. This allows
  offloading of SHA and RNG operations to wolfCrypt.
- The tree-hash sources `hash.c` and `hash.h` were renamed to `thash.[c,h]`, to
  avoid potential confusion with similarly named targets in wolfBoot.
- The `Makefile` has been updated to build static libraries `xmss_lib.a`,
  and `xmss_verify_lib.a`. The `xmss_verify_lib.a` is a verify-only build,
  with an additional define `XMSS_VERIFY_ONLY` that guards out keygen
  and signing functions.
- The `Makefile` has been updated to link against wolfSSL `LDLIBS = -lwolfssl`
  for the building of the tests in `test/`. The linking is *not* done for
  building the static libs though, to avoid a circular dependency. Linking with
  wolfssl to build the static libs is not necessary because the RNG and SHA
  operations are provided by setting callbacks.
- The tests in `test/` have been updated to reflect these changes.
- Some minor changes were made to fix warnings from clang `-fsanitize=memory`.
- Some minor cosmetic changes were made (cleanup trailing space, wrap long lines,
  etc).
