#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stdio.h>
#include <stddef.h>

typedef uint32_t uint;

#define BLOCK_SIZE 8

size_t add_padding(uint8_t **buf, size_t len);
size_t check_remove_padding(const uint8_t *buf, size_t len);
void cbc_encrypt(void (*encrypt_func)(const void *, uint *, uint *), const void *context, const uint8_t *iv, uint8_t *data, size_t len);
void cbc_decrypt(void (*decrypt_func)(const void *, uint *, uint *), const void *context, const uint8_t *iv, uint8_t *data, size_t len);
void generate_iv(uint8_t *iv);
void tea_encrypt_wrapper(const void *key, uint *L, uint *R);
void tea_decrypt_wrapper(const void *key, uint *L, uint *R);
void blowfish_encrypt_wrapper(const void *ctx, uint *L, uint *R);
void blowfish_decrypt_wrapper(const void *ctx, uint *L, uint *R);

#endif // UTILS_H
