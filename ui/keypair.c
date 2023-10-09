#include <stdio.h>
#include <stdint.h>

#include "../params.h"
#include "../xmss.h"
#include "../xmss_callbacks.h"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/random.h>

#ifdef XMSSMT
    #define XMSS_STR_TO_OID xmssmt_str_to_oid
    #define XMSS_PARSE_OID xmssmt_parse_oid
    #define XMSS_KEYPAIR xmssmt_keypair
#else
    #define XMSS_STR_TO_OID xmss_str_to_oid
    #define XMSS_PARSE_OID xmss_parse_oid
    #define XMSS_KEYPAIR xmss_keypair
#endif

static WC_RNG rng;

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

int main(int argc, char **argv)
{
    xmss_params params;
    uint32_t oid = 0;
    int parse_oid_result = 0;
    int ret = -1;

    if (argc != 2) {
        fprintf(stderr, "Expected parameter string (e.g. 'XMSS-SHA2_10_256')"
                        " as only parameter.\n"
                        "The keypair is written to stdout.\n");
        return -1;
    }

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

    XMSS_STR_TO_OID(&oid, argv[1]);
    parse_oid_result = XMSS_PARSE_OID(&params, oid);
    if (parse_oid_result != 0) {
        fprintf(stderr, "Error parsing oid.\n");
        return parse_oid_result;
    }

    unsigned char pk[XMSS_OID_LEN + params.pk_bytes];
    unsigned char sk[XMSS_OID_LEN + params.sk_bytes];

    XMSS_KEYPAIR(pk, sk, oid);

    fwrite(pk, 1, XMSS_OID_LEN + params.pk_bytes, stdout);
    fwrite(sk, 1, XMSS_OID_LEN + params.sk_bytes, stdout);

    fclose(stdout);

    return 0;
}
