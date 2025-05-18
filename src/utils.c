#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "utils.h"
#include "blowfish.h"
#include "tea.h"

size_t add_padding(uint8_t **buf, size_t len)
{
    size_t remainder = len % BLOCK_SIZE;
    size_t pad_len = (remainder == 0) ? BLOCK_SIZE : (BLOCK_SIZE - remainder);
    size_t padded_total_len = len + pad_len;
    uint8_t pad_byte = (uint8_t)pad_len;

    uint8_t *new_buf = realloc(*buf, padded_total_len);
    if (!new_buf)
    {
        return 0;
    }
    *buf = new_buf;

    for (size_t i = len; i < padded_total_len; i++)
    {
        (*buf)[i] = pad_byte;
    }

    return padded_total_len;
}

size_t check_remove_padding(const uint8_t *buf, size_t len)
{
    if (len == 0 || len % BLOCK_SIZE != 0)
    {
        return len;
    }

    uint8_t pad_len = buf[len - 1];

    if (pad_len == 0 || pad_len > BLOCK_SIZE)
    {
        return len;
    }

    for (size_t i = len - pad_len; i < len; i++)
    {
        if (buf[i] != pad_len)
        {
            return len;
        }
    }

    return len - pad_len;
}

void cbc_encrypt(void (*encrypt_func)(const void *, uint *, uint *), const void *context, const uint8_t *iv, uint8_t *data, size_t len)
{
    if (len == 0 || len % BLOCK_SIZE != 0)
    {
        fprintf(stderr, "Error: Data length (%zu) must be a multiple of %d for CBC encryption.\n", len, BLOCK_SIZE);
        return;
    }

    uint8_t prev_cipher_block[BLOCK_SIZE];
    memcpy(prev_cipher_block, iv, BLOCK_SIZE);

    for (size_t i = 0; i < len; i += BLOCK_SIZE)
    {
        uint8_t *current_block = data + i;

        for (int j = 0; j < BLOCK_SIZE; j++)
        {
            current_block[j] ^= prev_cipher_block[j];
        }

        encrypt_func(context, (uint *)current_block, (uint *)(current_block + 4));

        memcpy(prev_cipher_block, current_block, BLOCK_SIZE);
    }
}

void cbc_decrypt(void (*decrypt_func)(const void *, uint *, uint *), const void *context, const uint8_t *iv, uint8_t *data, size_t len)
{
    if (len == 0 || len % BLOCK_SIZE != 0)
    {
        fprintf(stderr, "Error: Data length (%zu) must be a multiple of %d for CBC decryption.\n", len, BLOCK_SIZE);
        return;
    }

    uint8_t prev_cipher_block[BLOCK_SIZE];
    uint8_t current_cipher_block[BLOCK_SIZE];
    memcpy(prev_cipher_block, iv, BLOCK_SIZE);

    for (size_t i = 0; i < len; i += BLOCK_SIZE)
    {
        uint8_t *current_block = data + i;

        memcpy(current_cipher_block, current_block, BLOCK_SIZE);

        decrypt_func(context, (uint *)current_block, (uint *)(current_block + 4));

        for (int j = 0; j < BLOCK_SIZE; j++)
        {
            current_block[j] ^= prev_cipher_block[j];
        }

        memcpy(prev_cipher_block, current_cipher_block, BLOCK_SIZE);
    }
}

void generate_iv(uint8_t *iv)
{
    for (int i = 0; i < BLOCK_SIZE; i++)
    {
        iv[i] = rand() % 256;
    }
}

void tea_encrypt_wrapper(const void *key, uint *L, uint *R)
{
    uint block[2] = {*L, *R};
    tea_encrypt(block, (const uint *)key);
    *L = block[0];
    *R = block[1];
}

void tea_decrypt_wrapper(const void *key, uint *L, uint *R)
{
    uint block[2] = {*L, *R};
    tea_decrypt(block, (const uint *)key);
    *L = block[0];
    *R = block[1];
}

void blowfish_encrypt_wrapper(const void *ctx, uint *L, uint *R)
{
    blowfish_encrypt((const blowfish_ctx *)ctx, L, R);
}

void blowfish_decrypt_wrapper(const void *ctx, uint *L, uint *R)
{
    blowfish_decrypt((const blowfish_ctx *)ctx, L, R);
}
