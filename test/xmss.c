#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "../xmss.h"
#include "../xmss_callbacks.h"
#include "../params.h"
#include "../randombytes.h"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/random.h>

#define XMSS_MLEN 32

#ifndef XMSS_SIGNATURES
    #define XMSS_SIGNATURES 16
#endif

#ifdef XMSSMT
    #define XMSS_PARSE_OID xmssmt_parse_oid
    #define XMSS_STR_TO_OID xmssmt_str_to_oid
    #define XMSS_KEYPAIR xmssmt_keypair
    #define XMSS_SIGN xmssmt_sign
    #define XMSS_SIGN_OPEN xmssmt_sign_open
    #define XMSS_VARIANT "XMSSMT-SHA2_20/2_256"
#else
    #define XMSS_PARSE_OID xmss_parse_oid
    #define XMSS_STR_TO_OID xmss_str_to_oid
    #define XMSS_KEYPAIR xmss_keypair
    #define XMSS_SIGN xmss_sign
    #define XMSS_SIGN_OPEN xmss_sign_open
    #define XMSS_VARIANT "XMSS-SHA2_10_256"
#endif

static int rng_cb(void * output, size_t length);
static int sha256_cb(const unsigned char *in, unsigned long long inlen,
                     unsigned char *out);

static WC_RNG rng;

int main()
{
    xmss_params params;
    uint32_t oid;
    int ret = 0;
    int i;

    // TODO test more different variants
    XMSS_STR_TO_OID(&oid, XMSS_VARIANT);
    XMSS_PARSE_OID(&params, oid);

    unsigned char pk[XMSS_OID_LEN + params.pk_bytes];
    unsigned char sk[XMSS_OID_LEN + params.sk_bytes];
    unsigned char *msg = malloc(XMSS_MLEN);
    unsigned char *sig = malloc(params.sig_bytes);
    unsigned long long siglen = params.sig_bytes;
    unsigned long long msglen = XMSS_MLEN;

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("error: init rng failed: %d\n", ret);
        return -1;
    }

    ret = xmss_set_sha_cb(sha256_cb);
    if (ret != 0) {
        printf("error: xmss_set_sha_cb failed");
        return -1;
    }

    ret = xmss_set_rng_cb(rng_cb);
    if (ret != 0) {
        printf("error: xmss_set_rng_cb failed");
        return -1;
    }

    randombytes(msg, XMSS_MLEN);

    XMSS_KEYPAIR(pk, sk, oid);

    printf("Testing %d %s signatures.. \n", XMSS_SIGNATURES, XMSS_VARIANT);

    for (i = 0; i < XMSS_SIGNATURES; i++) {
        printf("  - iteration #%d:\n", i);

        if (XMSS_SIGN(sk, sig, &siglen, msg, XMSS_MLEN)) {
            printf("  sign failed!\n");
            ret = -1;
        }

        if (siglen != params.sig_bytes) {
            printf("  X siglen incorrect [%llu != %u]!\n",
                   siglen, params.sig_bytes);
            ret = -1;
        }
        else {
            printf("    siglen as expected [%llu].\n", siglen);
        }

        /* Test if signature is valid. */
        if (XMSS_SIGN_OPEN(msg, &msglen, sig, siglen, pk)) {
            printf("  X verification failed!\n");
            ret = -1;
        }
        else {
            printf("    verification succeeded.\n");
        }

        /* Test if the correct message was recovered. */
        if (msglen != XMSS_MLEN) {
            printf("  X msglen incorrect [%llu != %u]!\n", msglen, XMSS_MLEN);
            ret = -1;
        }
        else {
            printf("    msglen as expected [%llu].\n", msglen);
        }

        /* Test if flipping bits invalidates the signature (it should). */

        /* Flip the first bit of the message. Should invalidate. */
        msg[0] ^= 1;
        if (!XMSS_SIGN_OPEN(msg, &msglen, sig, siglen, pk)) {
            printf("  X flipping a bit of m DID NOT invalidate signature!\n");
            ret = -1;
        }
        else {
            printf("    flipping a bit of m invalidates signature.\n");
        }
        msg[0] ^= 1;

#ifdef XMSS_TEST_INVALIDSIG
        int j;
        /* Flip one bit per hash; the signature is almost entirely hashes.
           This also flips a bit in the index, which is also a useful test. */
        for (j = 0; j < (int)(siglen); j += params.n) {
            sig[j] ^= 1;
            if (!XMSS_SIGN_OPEN(msg, &msglen, sig, siglen, pk)) {
                printf("  X flipping bit %d DID NOT invalidate sig + m!\n", j);
                sig[j] ^= 1;
                ret = -1;
                break;
            }
            sig[j] ^= 1;
        }
        if (j >= (int)(siglen)) {
            printf("    changing any signature hash invalidates signature.\n");
        }
#endif
    }

    free(msg);
    free(sig);

    return ret;
}

static int rng_cb(void * output, size_t length)
{
    int ret = 0;

    if (output == NULL) {
        return -1;
    }

    if (length == 0) {
        return 0;
    }

    ret = wc_RNG_GenerateBlock(&rng, output, (word32) length);

    if (ret) {
        printf("error: xmss rng_cb failed");
        return -1;
    }

    return 0;
}

static int sha256_cb(const unsigned char *in, unsigned long long inlen,
                     unsigned char *out)
{
    wc_Sha256 sha;

    if (wc_InitSha256_ex(&sha, NULL, INVALID_DEVID) != 0) {
        printf("SHA256 Init failed");
        return -1;
    }

    if (wc_Sha256Update(&sha, in, (word32) inlen) != 0) {
        printf("SHA256 Update failed");
        return -1;
    }

    if (wc_Sha256Final(&sha, out) != 0) {
        printf("SHA256 Final failed");
        wc_Sha256Free(&sha);
        return -1;
    }
    wc_Sha256Free(&sha);

    return 0;
}
