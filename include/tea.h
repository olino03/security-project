#ifndef TEA_H
#define TEA_H

#include <stdint.h>
#include <stddef.h> 

typedef uint32_t uint;

void tea_encrypt(uint *v, const uint *k);
void tea_decrypt(uint *v, const uint *k);
void tea_prepare_key(uint *key_out, const uint8_t *key_in, size_t key_len);

#endif // TEA_H
