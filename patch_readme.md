# Addendum readme for the wolfssl xmss-reference integration patch

This patch contains a number of changes, that were primarily motivated to
facilitate wolfBoot XMSS support for embedded-targets. Specifically, the
following changes have been made:

- All variable-length arrays (VLAs) necessary have been guarded with the define
  `WOLFBOOT_SIGN_XMSS`, and replaced with static compile-time constant arrays.
   E.g. in `wots.c`:
```
#if defined WOLFBOOT_SIGN_XMSS
    int lengths[XMSS_SHA256_WOTS_LEN];
#else
    int lengths[params->wots_len];
#endif
```
  The constants such as `XMSS_SHA256_WOTS_LEN` have been defined in `params.h`.
  They assume that the choice of SHA256 as the hashing function is a compile
  time constant, and the function `core_hash()` has been updated to reflect this.
- SHA256 and RNG operations are handled by a registered callback function. See
  the header `xmss_callbacks.h`. This allows offloading of SHA and RNG operations
  to wolfCrypt.
- The tree-hash sources `hash.c` and `hash.h` were renamed to `thash.*`, to
  avoid potential confusion with similarly named targets in wolfBoot.
- The `Makefile` has been updated to add static library builds `xmss_lib.a`,
  and `xmss_verify_lib.a`. The `xmss_verify_lib.a` is a verify-only build,
  with an additional define `XMSS_VERIFY_ONLY` that guards out any keygen
  and signing functions.
- The `Makefile` has been updated to link against wolfSSL `LDLIBS = -lwolfssl`
  for the building of the tests in `test/`. The linking is *not* done for
  building the static libs, to avoid a circular dependency. Linking with
  wolfssl to build the static libs is not necessary because the RNG and SHA
  operations are provided by setting callbacks.
- The tests in `test/` have been updated to reflect these changes.
