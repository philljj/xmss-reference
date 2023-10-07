#include <stdint.h>
#include <stdio.h>
#include <string.h>

/*
#if !defined WOLFBOOT_SIGN_XMSS
    #include <wolfssl/options.h>
#endif
*/

/*
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
*/

#include "xmss_callbacks.h"
#include "hash_address.h"
#include "utils.h"
#include "params.h"
#include "thash.h"

static sha_cb_t sha_cb = NULL;

#define XMSS_HASH_PADDING_F 0
#define XMSS_HASH_PADDING_H 1
#define XMSS_HASH_PADDING_HASH 2
#define XMSS_HASH_PADDING_PRF 3
#define XMSS_HASH_PADDING_PRF_KEYGEN 4

/*
static int sha256(const unsigned char *in, unsigned long long inlen,
                  unsigned char *out)
{
    wc_Sha256 sha;

    if (wc_InitSha256_ex(&sha, NULL, INVALID_DEVID) != 0) {
#if !defined WOLFBOOT_SIGN_XMSS
        fprintf(stderr, "SHA256 Init failed");
#endif
        return -1;
    }

    if (wc_Sha256Update(&sha, in, (word32) inlen) != 0) {
#if !defined WOLFBOOT_SIGN_XMSS
        fprintf(stderr, "SHA256 Update failed");
#endif
        return -1;
    }

    if (wc_Sha256Final(&sha, out) != 0) {
#if !defined WOLFBOOT_SIGN_XMSS
        fprintf(stderr, "SHA256 Final failed");
#endif
        wc_Sha256Free(&sha);
        return -1;
    }
    wc_Sha256Free(&sha);

    return 0;
}
*/

static int sha512(const unsigned char *in, unsigned long long inlen,
                  unsigned char *out)
{
    /* Disabling everything but sha256 for now. */
    (void) in;
    (void) inlen;
    (void) out;
    return -1;
}

static int shake128(unsigned char *out, unsigned long long outlen,
                    const unsigned char *in, unsigned long long inlen)
{
    /* Disabling everything but sha256 for now. */
    (void) in;
    (void) inlen;
    (void) out;
    (void) outlen;
    return -1;
}

static int shake256(unsigned char *out, unsigned long long outlen,
                    const unsigned char *in, unsigned long long inlen)
{
    /* Disabling everything but sha256 for now. */
    (void) in;
    (void) inlen;
    (void) out;
    (void) outlen;
    return -1;
}

void addr_to_bytes(unsigned char *bytes, const uint32_t addr[8])
{
    int i;
    for (i = 0; i < 8; i++) {
        ull_to_bytes(bytes + i*4, 4, addr[i]);
    }
}

int xmss_set_sha_cb(sha_cb_t cb)
{
    if (cb == NULL) {
        return -1;
    }
    sha_cb = cb;
    return 0;
}

static int core_hash(const xmss_params *params,
                     unsigned char *out,
                     const unsigned char *in, unsigned long long inlen)
{
    unsigned char buf[64];
    int           ret = -1;

    if (params == NULL || out == NULL || in == NULL) {
        return -1;
    }

    if (params->n == 24 && params->func == XMSS_SHA2) {
     /* ret = sha256(in, inlen, buf); */
     /* ret = params->sha_cb(in, inlen, out); */
        ret = sha_cb(in, inlen, out);
        memcpy(out, buf, 24);
    }
    else if (params->n == 24 && params->func == XMSS_SHAKE256) {
        ret = shake256(out, 24, in, inlen);
    }   
    else if (params->n == 32 && params->func == XMSS_SHA2) {
     /* if (params->sha_cb == NULL) { */
        if (sha_cb == NULL) {
#if !defined WOLFBOOT_SIGN_XMSS
            fprintf(stderr, "errorzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz: sha_cb is null\n");
#endif
        }
        else {
         /* ret = params->sha_cb(in, inlen, out); */
            ret = sha_cb(in, inlen, out);
        }
      /*ret = sha256(in, inlen, out); */
    }
    else if (params->n == 32 && params->func == XMSS_SHAKE128) {
        ret = shake128(out, 32, in, inlen);
    }
    else if (params->n == 32 && params->func == XMSS_SHAKE256) {
        ret = shake256(out, 32, in, inlen);
    }
    else if (params->n == 64 && params->func == XMSS_SHA2) {
        ret = sha512(in, inlen, out);
    }
    else if (params->n == 64 && params->func == XMSS_SHAKE256) {
        ret = shake256(out, 64, in, inlen);
    }
    else {
        return -1;
    }

    if (ret != 0) { return ret; }
    return 0;
}

/*
 * Computes PRF(key, in), for a key of params->n bytes, and a 32-byte input.
 */
int prf(const xmss_params *params,
        unsigned char *out, const unsigned char in[32],
        const unsigned char *key)
{
#if defined WOLFBOOT_SIGN_XMSS
    unsigned char buf[XMSS_SHA256_PADDING_LEN + XMSS_SHA256_N + 32];
#else
    unsigned char buf[params->padding_len + params->n + 32];
#endif

    ull_to_bytes(buf, params->padding_len, XMSS_HASH_PADDING_PRF);
    memcpy(buf + params->padding_len, key, params->n);
    memcpy(buf + params->padding_len + params->n, in, 32);

    return core_hash(params, out, buf, params->padding_len + params->n + 32);
}

/*
 * Computes PRF_keygen(key, in), for a key of params->n bytes, and an input
 * of 32 + params->n bytes
 */
int prf_keygen(const xmss_params *params,
        unsigned char *out, const unsigned char *in,
        const unsigned char *key)
{
#if defined WOLFBOOT_SIGN_XMSS
    unsigned char buf[XMSS_SHA256_PADDING_LEN + 2 * XMSS_SHA256_N + 32];
#else
    unsigned char buf[params->padding_len + 2*params->n + 32];
#endif

    ull_to_bytes(buf, params->padding_len, XMSS_HASH_PADDING_PRF_KEYGEN);
    memcpy(buf + params->padding_len, key, params->n);
    memcpy(buf + params->padding_len + params->n, in, params->n + 32);

    return core_hash(params, out, buf, params->padding_len + 2*params->n + 32);
}

/*
 * Computes the message hash using R, the public root, the index of the leaf
 * node, and the message. Notably, it requires m_with_prefix to have 3*n plus
 * the length of the padding as free space available before the message,
 * to use for the prefix. This is necessary to prevent having to move the
 * message around (and thus allocate memory for it).
 */
int hash_message(const xmss_params *params, unsigned char *out,
                 const unsigned char *R, const unsigned char *root,
                 unsigned long long idx,
                 unsigned char *m_with_prefix, unsigned long long mlen)
{
    /* We're creating a hash using input of the form:
       toByte(X, 32) || R || root || index || M */
    ull_to_bytes(m_with_prefix, params->padding_len, XMSS_HASH_PADDING_HASH);
    memcpy(m_with_prefix + params->padding_len, R, params->n);
    memcpy(m_with_prefix + params->padding_len + params->n, root, params->n);
    ull_to_bytes(m_with_prefix + params->padding_len + 2*params->n, params->n, idx);

    return core_hash(params, out, m_with_prefix, mlen + params->padding_len + 3*params->n);
}

/**
 * We assume the left half is in in[0]...in[n-1]
 */
int thash_h(const xmss_params *params,
            unsigned char *out, const unsigned char *in,
            const unsigned char *pub_seed, uint32_t addr[8])
{
#if defined WOLFBOOT_SIGN_XMSS
    unsigned char buf[XMSS_SHA256_PADDING_LEN + 3 * XMSS_SHA256_N];
    unsigned char bitmask[2 * XMSS_SHA256_N];
#else
    unsigned char buf[params->padding_len + 3 * params->n];
    unsigned char bitmask[2 * params->n];
#endif
    unsigned char addr_as_bytes[32];
    unsigned int i;

    /* Set the function padding. */
    ull_to_bytes(buf, params->padding_len, XMSS_HASH_PADDING_H);

    /* Generate the n-byte key. */
    set_key_and_mask(addr, 0);
    addr_to_bytes(addr_as_bytes, addr);
    prf(params, buf + params->padding_len, addr_as_bytes, pub_seed);

    /* Generate the 2n-byte mask. */
    set_key_and_mask(addr, 1);
    addr_to_bytes(addr_as_bytes, addr);
    prf(params, bitmask, addr_as_bytes, pub_seed);

    set_key_and_mask(addr, 2);
    addr_to_bytes(addr_as_bytes, addr);
    prf(params, bitmask + params->n, addr_as_bytes, pub_seed);

    for (i = 0; i < 2 * params->n; i++) {
        buf[params->padding_len + params->n + i] = in[i] ^ bitmask[i];
    }
    return core_hash(params, out, buf, params->padding_len + 3 * params->n);
}

int thash_f(const xmss_params *params,
            unsigned char *out, const unsigned char *in,
            const unsigned char *pub_seed, uint32_t addr[8])
{
#if defined WOLFBOOT_SIGN_XMSS
    unsigned char buf[XMSS_SHA256_PADDING_LEN + 2 * XMSS_SHA256_N];
    unsigned char bitmask[XMSS_SHA256_N];
#else
    unsigned char buf[params->padding_len + 2 * params->n];
    unsigned char bitmask[params->n];
#endif
    unsigned char addr_as_bytes[32];
    unsigned int i;

    /* Set the function padding. */
    ull_to_bytes(buf, params->padding_len, XMSS_HASH_PADDING_F);

    /* Generate the n-byte key. */
    set_key_and_mask(addr, 0);
    addr_to_bytes(addr_as_bytes, addr);
    prf(params, buf + params->padding_len, addr_as_bytes, pub_seed);

    /* Generate the n-byte mask. */
    set_key_and_mask(addr, 1);
    addr_to_bytes(addr_as_bytes, addr);
    prf(params, bitmask, addr_as_bytes, pub_seed);

    for (i = 0; i < params->n; i++) {
        buf[params->padding_len + params->n + i] = in[i] ^ bitmask[i];
    }
    return core_hash(params, out, buf, params->padding_len + 2 * params->n);
}
