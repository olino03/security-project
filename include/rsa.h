#ifndef RSA_H
#define RSA_H

#include "tommath.h" // LibTomMath main header

#define NUM_SMALL_PRIMES 1024 

typedef struct {
    mp_int p, q;     // Private prime factors
    mp_int n;        // Public modulus n = p*q
    mp_int e;        // Public exponent
    mp_int d;        // Private exponent
    mp_int dp;       // CRT exponent dP = d mod (p-1)
    mp_int dq;       // CRT exponent dQ = d mod (q-1)
    mp_int qinv;     // CRT coefficient qInv = q^-1 mod p
    // int keysize;  // Optional: store keysize
} rsa_ctx;

// Function prototypes for rsa_ctx lifecycle management
mp_err rsa_init_ctx(rsa_ctx *ctx);
void rsa_clear_ctx(rsa_ctx *ctx);

// User's functions
int rsa_generate_keypair(rsa_ctx *ctx, int keysize);
int rsa_encrypt_file(rsa_ctx *ctx, const char *infile, const char *outfile);
int rsa_decrypt_file(rsa_ctx *ctx, const char *infile, const char *outfile);

#endif // RSA_H