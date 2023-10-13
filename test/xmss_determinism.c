#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "../params.h"
#include "../xmss_callbacks.h"
#include "../xmss.h"
#include "../randombytes.h"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/random.h>

#define MLEN 32

static int rng_cb(void * output, size_t length);
static int sha256_cb(const unsigned char *in, unsigned long long inlen,
                     unsigned char *out);

static WC_RNG rng;

int main(void)
{
    xmss_params params;
    char *oidstr = "XMSS-SHA2_10_256";
    uint32_t oid;
    unsigned int i;
    int ret = -1;

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

    fprintf(stderr, "Testing if XMSS-SHA2_10_256 signing is deterministic.. ");

    xmss_str_to_oid(&oid, oidstr);
    xmss_parse_oid(&params, oid);

    unsigned char pk[XMSS_OID_LEN + params.pk_bytes];
    unsigned char sk[XMSS_OID_LEN + params.sk_bytes];
    unsigned char sk2[XMSS_OID_LEN + params.sk_bytes];

    unsigned char msg[MLEN];
    unsigned char sig[params.sig_bytes];
    unsigned char sig2[params.sig_bytes];
    unsigned long long siglen = params.sig_bytes;

    xmss_keypair(pk, sk, oid);

    /* Duplicate the key, because the original will be modified. */
    memcpy(sk2, sk, XMSS_OID_LEN + params.sk_bytes);

    /* Sign a random message (but twice the same one). */
    randombytes(msg, MLEN);

    xmss_sign(sk, sig, &siglen, msg, MLEN);
    xmss_sign(sk2, sig2, &siglen, msg, MLEN);

    /* Compare signature, and, if applicable, print the differences. */
    if (memcmp(sig, sig2, params.sig_bytes)) {
        fprintf(stderr, "signatures differ!\n");
        for (i = 0; i < params.sig_bytes + MLEN; i++) {
            fprintf(stderr, (sig[i] != sig2[i] ? "x" : "."));
        }
        fprintf(stderr, "\n");
        return -1;
    }
    else {
        fprintf(stderr, "signatures are identical.\n");
    }

    return 0;
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
