#ifndef RSA_H
#define RSA_H

#include "tommath.h"

#define NUM_SMALL_PRIMES 1024
#define RSA_KEY_FILE_LINE_MAX_LEN 4096

typedef struct
{
    mp_int p, q;
    mp_int n;
    mp_int e;
    mp_int d;
    mp_int dp;
    mp_int dq;
    mp_int qinv;
} rsa_ctx;

mp_err rsa_init_ctx(rsa_ctx *ctx);
void rsa_clear_ctx(rsa_ctx *ctx);

int rsa_generate_keypair(rsa_ctx *ctx, int keysize);
int rsa_encrypt_file(rsa_ctx *ctx, const char *infile, const char *outfile);
int rsa_decrypt_file(rsa_ctx *ctx, const char *infile, const char *outfile);

int rsa_save_public_key_to_file(rsa_ctx *ctx, const char *pubkey_file);
int rsa_load_public_key_from_file(rsa_ctx *ctx, const char *pubkey_file);
int rsa_save_private_key_to_file(rsa_ctx *ctx, const char *privkey_file);
int rsa_load_private_key_from_file(rsa_ctx *ctx, const char *privkey_file);

#endif // RSA_H