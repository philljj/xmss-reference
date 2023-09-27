#ifndef XMSS_H
#define XMSS_H

#include <stdint.h>

#ifndef XMSS_VERIFY_ONLY
/**
 * Generates a XMSS key pair for a given parameter set.
 * Format sk: [OID || (32bit) idx || SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [OID || root || PUB_SEED]
 */
int xmss_keypair(unsigned char *pk, unsigned char *sk, const uint32_t oid,
                 void * rng);

/**
 * Signs a message using an XMSS secret key.
 * Returns
 * 1. an array containing the signature AND
 * 2. an updated secret key!
 */
int xmss_sign(unsigned char *sk,
              unsigned char *sm, unsigned long long *smlen,
              const unsigned char *m, unsigned long long mlen);

/*
 * Generates a XMSSMT key pair for a given parameter set.
 * Format sk: [OID || (ceil(h/8) bit) idx || SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [OID || root || PUB_SEED]
 */
int xmssmt_keypair(unsigned char *pk, unsigned char *sk, const uint32_t oid,
                   void * rng);

/**
 * Signs a message using an XMSSMT secret key.
 * Returns
 * 1. an array containing the signature AND
 * 2. an updated secret key!
 */
int xmssmt_sign(unsigned char *sk,
                unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen);
#endif /* ifndef XMSS_VERIFY_ONLY */

/**
 * Verifies a given message signature pair using a given public key.
 *
 * Note: m and mlen are pure outputs which carry the message in case
 * verification succeeds. The (input) message is assumed to be contained in sm
 * which has the form [signature || message].
 */
int xmss_sign_open(const unsigned char *msg, unsigned long long *msglen,
                   const unsigned char *sm, unsigned long long smlen,
                   const unsigned char *pk);

/**
 * Verifies a given message signature pair using a given public key.
 *
 * Note: m and mlen are pure outputs which carry the message in case
 * verification succeeds. The (input) message is assumed to be contained in sm
 * which has the form [signature || message].
 */
int xmssmt_sign_open(const unsigned char *msg, unsigned long long *msglen,
                     const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *pk);
#endif
