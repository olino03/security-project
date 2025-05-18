#include <stdlib.h>   // For malloc, realloc, free, rand, srand
#include <string.h>   // For memcpy, memcmp
#include <time.h>

#include "utils.h"
#include "blowfish.h" // For blowfish_ctx type
#include "tea.h"      // For tea function prototypes
     // For time()

// PKCS#7 Padding ====================================================

// Adds padding to ensure the length is a multiple of BLOCK_SIZE (8 bytes)
size_t add_padding(uint8_t **buf, size_t len) {
    size_t remainder = len % BLOCK_SIZE;
    size_t pad_len = (remainder == 0) ? BLOCK_SIZE : (BLOCK_SIZE - remainder); // Add a full block if already aligned
    size_t padded_total_len = len + pad_len;
    uint8_t pad_byte = (uint8_t)pad_len; // The value of the padding byte is the length of the padding

    uint8_t *new_buf = realloc(*buf, padded_total_len);
    if (!new_buf) {
        // Allocation failed
        return 0; // Indicate error
    }
    *buf = new_buf; // Update the original pointer

    // Fill the padding bytes
    for (size_t i = len; i < padded_total_len; i++) {
        (*buf)[i] = pad_byte;
    }

    return padded_total_len;
}

// Checks for valid PKCS#7 padding and returns the original length
size_t check_remove_padding(const uint8_t *buf, size_t len) {
    if (len == 0 || len % BLOCK_SIZE != 0) {
        // Invalid length for padded data
        return len; // Return original length, indicating padding error or no padding
    }

    uint8_t pad_len = buf[len - 1]; // Get the last byte, which indicates padding length

    // Check if padding length is valid (1 to BLOCK_SIZE)
    if (pad_len == 0 || pad_len > BLOCK_SIZE) {
        return len; // Invalid padding value
    }

    // Verify that all padding bytes have the correct value
    for (size_t i = len - pad_len; i < len; i++) {
        if (buf[i] != pad_len) {
            return len; // Padding bytes are inconsistent
        }
    }

    // Padding is valid, return the length without padding
    return len - pad_len;
}


// CBC Mode Implementation ===========================================

void cbc_encrypt(void (*encrypt_func)(const void*, uint*, uint*), const void *context, const uint8_t *iv, uint8_t *data, size_t len) {
    if (len == 0 || len % BLOCK_SIZE != 0) {
        // Data length must be a multiple of block size for CBC
        fprintf(stderr, "Error: Data length (%zu) must be a multiple of %d for CBC encryption.\n", len, BLOCK_SIZE);
        return; // Or handle error appropriately
    }

    uint8_t prev_cipher_block[BLOCK_SIZE];
    memcpy(prev_cipher_block, iv, BLOCK_SIZE); // Start with the IV

    for (size_t i = 0; i < len; i += BLOCK_SIZE) {
        uint8_t *current_block = data + i;

        // 1. XOR plaintext block with the previous ciphertext block (or IV for the first block)
        for (int j = 0; j < BLOCK_SIZE; j++) {
            current_block[j] ^= prev_cipher_block[j];
        }

        // 2. Encrypt the result
        //    We pass pointers to the two 32-bit halves of the block
        encrypt_func(context, (uint*)current_block, (uint*)(current_block + 4));

        // 3. The output of encryption is the current ciphertext block,
        //    which becomes the 'previous' block for the next iteration.
        memcpy(prev_cipher_block, current_block, BLOCK_SIZE);
    }
}

void cbc_decrypt(void (*decrypt_func)(const void*, uint*, uint*), const void *context, const uint8_t *iv, uint8_t *data, size_t len) {
     if (len == 0 || len % BLOCK_SIZE != 0) {
        // Data length must be a multiple of block size for CBC
        fprintf(stderr, "Error: Data length (%zu) must be a multiple of %d for CBC decryption.\n", len, BLOCK_SIZE);
        return; // Or handle error appropriately
    }

    uint8_t prev_cipher_block[BLOCK_SIZE];
    uint8_t current_cipher_block[BLOCK_SIZE];
    memcpy(prev_cipher_block, iv, BLOCK_SIZE); // Start with the IV

    for (size_t i = 0; i < len; i += BLOCK_SIZE) {
        uint8_t *current_block = data + i;

        // 1. Store the current ciphertext block *before* decryption
        memcpy(current_cipher_block, current_block, BLOCK_SIZE);

        // 2. Decrypt the current ciphertext block
        //    We pass pointers to the two 32-bit halves of the block
        decrypt_func(context, (uint*)current_block, (uint*)(current_block + 4));

        // 3. XOR the result with the previous ciphertext block (or IV for the first block)
        for (int j = 0; j < BLOCK_SIZE; j++) {
            current_block[j] ^= prev_cipher_block[j];
        }

        // 4. Update the 'previous' ciphertext block for the next iteration
        memcpy(prev_cipher_block, current_cipher_block, BLOCK_SIZE);
    }
}


// IV Generation =====================================================

// NOTE: This uses rand() which is NOT cryptographically secure.
// For real applications, use a proper CSPRNG (Cryptographically Secure Pseudo-Random Number Generator)
// available from your operating system (e.g., /dev/urandom on Linux, CryptGenRandom on Windows).
void generate_iv(uint8_t *iv) {
    // Seed the pseudo-random generator (only needs to be done once ideally)
    // Placing it here means it might get re-seeded often if called rapidly,
    // which isn't ideal but simple for this example.

    for (int i = 0; i < BLOCK_SIZE; i++) {
        iv[i] = rand() % 256; // Generate pseudo-random bytes
    }
}

// Wrapper Functions ================================================
// These allow Blowfish and TEA functions to be used with the generic CBC functions

void tea_encrypt_wrapper(const void *key, uint *L, uint *R) {
    uint block[2] = {*L, *R};
    tea_encrypt(block, (const uint*)key);
    *L = block[0];
    *R = block[1];
}

void tea_decrypt_wrapper(const void *key, uint *L, uint *R) {
    uint block[2] = {*L, *R};
    tea_decrypt(block, (const uint*)key);
    *L = block[0];
    *R = block[1];
}

void blowfish_encrypt_wrapper(const void *ctx, uint *L, uint *R) {
    blowfish_encrypt((const blowfish_ctx*)ctx, L, R);
}

void blowfish_decrypt_wrapper(const void *ctx, uint *L, uint *R) {
    blowfish_decrypt((const blowfish_ctx*)ctx, L, R);
}

