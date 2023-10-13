#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "../wots.h"
#include "../xmss_callbacks.h"
#include "../randombytes.h"
#include "../params.h"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/random.h>

static int rng_cb(void * output, size_t length);
static int sha256_cb(const unsigned char *in, unsigned long long inlen,
                     unsigned char *out);

static WC_RNG rng;

int main(void)
{
    xmss_params params;
    // TODO test more different OIDs
    uint32_t oid = 0x00000001;
    int ret = -1;

    /* For WOTS it doesn't matter if we use XMSS or XMSSMT. */
    xmss_parse_oid(&params, oid);

    unsigned char seed[params.n];
    unsigned char pub_seed[params.n];
    unsigned char pk1[params.wots_sig_bytes];
    unsigned char pk2[params.wots_sig_bytes];
    unsigned char sig[params.wots_sig_bytes];
    unsigned char m[params.n];
    uint32_t addr[8] = {0};

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

    randombytes(seed, params.n);
    randombytes(pub_seed, params.n);
    randombytes(m, params.n);
    randombytes((unsigned char *)addr, 8 * sizeof(uint32_t));

    printf("Testing WOTS signature and PK derivation.. ");

    wots_pkgen(&params, pk1, seed, pub_seed, addr);
    wots_sign(&params, sig, m, seed, pub_seed, addr);
    wots_pk_from_sig(&params, pk2, sig, m, pub_seed, addr);

    if (memcmp(pk1, pk2, params.wots_sig_bytes)) {
        printf("failed!\n");
        return -1;
    }
    printf("successful.\n");
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
