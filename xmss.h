#ifndef XMSS_H
#define XMSS_H

#include <stdint.h>

#ifndef XMSS_VERIFY_ONLY
/**
 * Generates a XMSS key pair for a given parameter set.
 * Format sk: [OID || (32bit) idx || SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [OID || root || PUB_SEED]
 */
int xmss_keypair(unsigned char *pk, unsigned char *sk, const uint32_t oid);

/**
 * Signs a message using an XMSS secret key.
 * Returns
 * 1. an array containing the signature AND
 * 2. an updated secret key!
 */
int xmss_sign(unsigned char *sk,
              unsigned char *sig, unsigned long long *siglen,
              const unsigned char *msg, unsigned long long msglen);

/*
 * Generates a XMSSMT key pair for a given parameter set.
 * Format sk: [OID || (ceil(h/8) bit) idx || SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [OID || root || PUB_SEED]
 */
int xmssmt_keypair(unsigned char *pk, unsigned char *sk, const uint32_t oid);

/**
 * Signs a message using an XMSSMT secret key.
 * Returns
 * 1. an array containing the signature AND
 * 2. an updated secret key!
 */
int xmssmt_sign(unsigned char *sk,
                unsigned char *sig, unsigned long long *siglen,
                const unsigned char *msg, unsigned long long msglen);
#endif /* ifndef XMSS_VERIFY_ONLY */

/**
 * Verifies a given signature using a given public key.
 *
 * - msg is the input message of length msglen.
 * - sig is the signature to verify, of length siglen.
 * - pk is the public key without an OID.
 */
int xmss_sign_open(const unsigned char *msg, unsigned long long *msglen,
                   const unsigned char *sig, unsigned long long siglen,
                   const unsigned char *pk);

/**
 * Verifies a given signature using a given public key.
 *
 * - msg is the input message of length msglen.
 * - sig is the signature to verify, of length siglen.
 * - pk is the public key without an OID.
 */
int xmssmt_sign_open(const unsigned char *msg, unsigned long long *msglen,
                     const unsigned char *sig, unsigned long long siglen,
                     const unsigned char *pk);
#endif
