#include "constants.h"
#include "rsa.h"
#include <stdio.h>
#include <stdlib.h>

const uint prime_list[1024] = {
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283, 1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399, 1409, 1423, 1427, 1429, 1433, 1439, 1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511, 1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609, 1613, 1619, 1621, 1627, 1637, 1657, 1663, 1667, 1669, 1693, 1697, 1699, 1709, 1721, 1723, 1733, 1741, 1747, 1753, 1759, 1777, 1783, 1787, 1789, 1801, 1811, 1823, 1831, 1847, 1861, 1867, 1871, 1873, 1877, 1879, 1889, 1901, 1907, 1913, 1931, 1933, 1949, 1951, 1973, 1979, 1987, 1993, 1997, 1999, 2003, 2011, 2017, 2027, 2029, 2039, 2053, 2063, 2069, 2081, 2083, 2087, 2089, 2099, 2111, 2113, 2129, 2131, 2137, 2141, 2143, 2153, 2161, 2179, 2203, 2207, 2213, 2221, 2237, 2239, 2243, 2251, 2267, 2269, 2273, 2281, 2287, 2293, 2297, 2309, 2311, 2333, 2339, 2341, 2347, 2351, 2357, 2371, 2377, 2381, 2383, 2389, 2393, 2399, 2411, 2417, 2423, 2437, 2441, 2447, 2459, 2467, 2473, 2477, 2503, 2521, 2531, 2539, 2543, 2549, 2551, 2557, 2579, 2591, 2593, 2609, 2617, 2621, 2633, 2647, 2657, 2659, 2663, 2671, 2677, 2683, 2687, 2689, 2693, 2699, 2707, 2711, 2713, 2719, 2729, 2731, 2741, 2749, 2753, 2767, 2777, 2789, 2791, 2797, 2801, 2803, 2819, 2833, 2837, 2843, 2851, 2857, 2861, 2879, 2887, 2897, 2903, 2909, 2917, 2927, 2939, 2953, 2957, 2963, 2969, 2971, 2999, 3001, 3011, 3019, 3023, 3037, 3041, 3049, 3061, 3067, 3079, 3083, 3089, 3109, 3119, 3121, 3137, 3163, 3167, 3169, 3181, 3187, 3191, 3203, 3209, 3217, 3221, 3229, 3251, 3253, 3257, 3259, 3271, 3299, 3301, 3307, 3313, 3319, 3323, 3329, 3331, 3343, 3347, 3359, 3361, 3371, 3373, 3389, 3391, 3407, 3413, 3433, 3449, 3457, 3461, 3463, 3467, 3469, 3491, 3499, 3511, 3517, 3527, 3529, 3533, 3539, 3541, 3547, 3557, 3559, 3571, 3581, 3583, 3593, 3607, 3613, 3617, 3623, 3631, 3637, 3643, 3659, 3671, 3673, 3677, 3691, 3697, 3701, 3709, 3719, 3727, 3733, 3739, 3761, 3767, 3769, 3779, 3793, 3797, 3803, 3821, 3823, 3833, 3847, 3851, 3853, 3863, 3877, 3881, 3889, 3907, 3911, 3917, 3919, 3923, 3929, 3931, 3943, 3947, 3967, 3989, 4001, 4003, 4007, 4013, 4019, 4021, 4027, 4049, 4051, 4057, 4073, 4079, 4091, 4093, 4099, 4111, 4127, 4129, 4133, 4139, 4153, 4157, 4159, 4177, 4201, 4211, 4217, 4219, 4229, 4231, 4241, 4243, 4253, 4259, 4261, 4271, 4273, 4283, 4289, 4297, 4327, 4337, 4339, 4349, 4357, 4363, 4373, 4391, 4397, 4409, 4421, 4423, 4441, 4447, 4451, 4457, 4463, 4481, 4483, 4493, 4507, 4513, 4517, 4519, 4523, 4547, 4549, 4561, 4567, 4583, 4591, 4597, 4603, 4621, 4637, 4639, 4643, 4649, 4651, 4657, 4663, 4673, 4679, 4691, 4703, 4721, 4723, 4729, 4733, 4751, 4759, 4783, 4787, 4789, 4793, 4799, 4801, 4813, 4817, 4831, 4861, 4871, 4877, 4889, 4903, 4909, 4919, 4931, 4933, 4937, 4943, 4951, 4957, 4967, 4969, 4973, 4987, 4993, 4999, 5003, 5009, 5011, 5021, 5023, 5039, 5051, 5059, 5077, 5081, 5087, 5099, 5101, 5107, 5113, 5119, 5147, 5153, 5167, 5171, 5179, 5189, 5197, 5209, 5227, 5231, 5233, 5237, 5261, 5273, 5279, 5281, 5297, 5303, 5309, 5323, 5333, 5347, 5351, 5381, 5387, 5393, 5399, 5407, 5413, 5417, 5419, 5431, 5437, 5441, 5443, 5449, 5471, 5477, 5479, 5483, 5501, 5503, 5507, 5519, 5521, 5527, 5531, 5557, 5563, 5569, 5573, 5581, 5591, 5623, 5639, 5641, 5647, 5651, 5653, 5657, 5659, 5669, 5683, 5689, 5693, 5701, 5711, 5717, 5737, 5741, 5743, 5749, 5779, 5783, 5791, 5801, 5807, 5813, 5821, 5827, 5839, 5843, 5849, 5851, 5857, 5861, 5867, 5869, 5879, 5881, 5897, 5903, 5923, 5927, 5939, 5953, 5981, 5987, 6007, 6011, 6029, 6037, 6043, 6047, 6053, 6067, 6073, 6079, 6089, 6091, 6101, 6113, 6121, 6131, 6133, 6143, 6151, 6163, 6173, 6197, 6199, 6203, 6211, 6217, 6221, 6229, 6247, 6257, 6263, 6269, 6271, 6277, 6287, 6299, 6301, 6311, 6317, 6323, 6329, 6337, 6343, 6353, 6359, 6361, 6367, 6373, 6379, 6389, 6397, 6421, 6427, 6449, 6451, 6469, 6473, 6481, 6491, 6521, 6529, 6547, 6551, 6553, 6563, 6569, 6571, 6577, 6581, 6599, 6607, 6619, 6637, 6653, 6659, 6661, 6673, 6679, 6689, 6691, 6701, 6703, 6709, 6719, 6733, 6737, 6761, 6763, 6779, 6781, 6791, 6793, 6803, 6823, 6827, 6829, 6833, 6841, 6857, 6863, 6869, 6871, 6883, 6899, 6907, 6911, 6917, 6947, 6949, 6959, 6961, 6967, 6971, 6977, 6983, 6991, 6997, 7001, 7013, 7019, 7027, 7039, 7043, 7057, 7069, 7079, 7103, 7109, 7121, 7127, 7129, 7151, 7159, 7177, 7187, 7193, 7207, 7211, 7213, 7219, 7229, 7237, 7243, 7247, 7253, 7283, 7297, 7307, 7309, 7321, 7331, 7333, 7349, 7351, 7369, 7393, 7411, 7417, 7433, 7451, 7457, 7459, 7477, 7481, 7487, 7489, 7499, 7507, 7517, 7523, 7529, 7537, 7541, 7547, 7549, 7559, 7561, 7573, 7577, 7583, 7589, 7591, 7603, 7607, 7621, 7639, 7643, 7649, 7669, 7673, 7681, 7687, 7691, 7699, 7703, 7717, 7723, 7727, 7741, 7753, 7757, 7759, 7789, 7793, 7817, 7823, 7829, 7841, 7853, 7867, 7873, 7877, 7879, 7883, 7901, 7907, 7919, 7927, 7933, 7937, 7949, 7951, 7963, 7993, 8009, 8011, 8017, 8039, 8053, 8059, 8069, 8081, 8087, 8089, 8093, 8101, 8111, 8117, 8123, 8147, 8161
};

mp_err rsa_init_ctx(rsa_ctx *ctx) {
    return mp_init_multi(&ctx->p, &ctx->q, &ctx->n, &ctx->e, &ctx->d, 
                  &ctx->dp, &ctx->dq, &ctx->qinv, NULL);
}

void rsa_clear_ctx(rsa_ctx *ctx) {
    mp_clear_multi(&ctx->p, &ctx->q, &ctx->n, &ctx->e, &ctx->d,
                   &ctx->dp, &ctx->dq, &ctx->qinv, NULL);
}

static void get_random_bytes_placeholder(unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buf[i] = rand() % 256; 
    }
}


static int set_prime_candidate(mp_int *num, int bits) {
    int err;
    // Calculate number of bytes needed for the specified number of bits
    int num_bytes = (bits + 7) / 8;
    unsigned char *buf = malloc(num_bytes);
    if (buf == NULL) {
        return MP_MEM; // Memory allocation error
    }

    // 1. Obtain random bytes from a CSPRNG
    get_random_bytes_placeholder(buf, num_bytes); // CRITICAL: Replace with a real CSPRNG

    // Convert the byte string to an mp_int
    if ((err = mp_from_ubin(num, buf, num_bytes)) != MP_OKAY) {
        free(buf);
        return err;
    }
    free(buf);

    if (num_bytes * 8 > bits) {
        mp_int temp_modulus;
        if ((err = mp_init(&temp_modulus)) != MP_OKAY) return err;
        if ((err = mp_2expt(&temp_modulus, bits)) != MP_OKAY) { // temp_modulus = 2^bits
            mp_clear(&temp_modulus);
            return err;
        }
        if ((err = mp_mod(num, &temp_modulus, num)) != MP_OKAY) { // num = num mod 2^bits
            mp_clear(&temp_modulus);
            return err;
        }
        mp_clear(&temp_modulus);
    }
    
    if (bits > 0) { // Check to prevent issues if bits is 0 or negative (though unlikely here)
        mp_int msb_val;
        if ((err = mp_init(&msb_val)) != MP_OKAY) return err;
        if ((err = mp_2expt(&msb_val, bits - 1)) != MP_OKAY) { // msb_val = 2^(bits-1)
            mp_clear(&msb_val);
            return err;
        }
        if ((err = mp_or(num, &msb_val, num)) != MP_OKAY) { // num = num | msb_val
            mp_clear(&msb_val);
            return err;
        }
        mp_clear(&msb_val);
    }

    if (mp_iseven(num)) {
       if ((err = mp_add_d(num, 1UL, num)) != MP_OKAY) return err; // Add 1 if even
    }

    return MP_OKAY;
}


// Generates one prime number and stores it in result_prime.
static int rsa_generate_one_prime(mp_int *result_prime, int bits, 
                                  const unsigned int *local_prime_list, int prime_list_size) {
    mp_int candidate, remainder;
    mp_int small_primes_mp[NUM_SMALL_PRIMES]; // Adapt size if NUM_SMALL_PRIMES is very large and stack is an issue
    int err = MP_OKAY;
    int is_prime = 0;
    int initialized_small_primes = 0;

    // Initialize mp_int array for small primes
    for (initialized_small_primes = 0; initialized_small_primes < prime_list_size; initialized_small_primes++) {
        if ((err = mp_init(&small_primes_mp[initialized_small_primes])) != MP_OKAY) {
            goto cleanup_small_primes_partial;
        }
        mp_set_ul(&small_primes_mp[initialized_small_primes], local_prime_list[initialized_small_primes]);
    }

    if ((err = mp_init(&candidate)) != MP_OKAY) goto cleanup_small_primes_full;
    if ((err = mp_init(&remainder)) != MP_OKAY) {
        mp_clear(&candidate);
        goto cleanup_small_primes_full;
    }

    do {
        // Generate a prime candidate
        if ((err = set_prime_candidate(&candidate, bits)) != MP_OKAY) {
            goto cleanup_candidate_remainder;
        }
        
        // Trial division by small primes
        int divisible_by_small_prime = 0;
        for (int i = 0; i < prime_list_size; i++) {
            if ((err = mp_div(&candidate, &small_primes_mp[i], NULL, &remainder)) != MP_OKAY) {
                goto cleanup_candidate_remainder;
            }
            if (mp_iszero(&remainder)) {
                divisible_by_small_prime = 1;
                break;
            }
        }

        if (divisible_by_small_prime) {
            continue; // Try a new candidate
        }

        if ((err = mp_prime_is_prime(&candidate, 5, &is_prime)) != MP_OKAY) {
            goto cleanup_candidate_remainder;
        }
    } while (!is_prime);

    if (err == MP_OKAY) { // If loop exited because is_prime is true and no errors
        err = mp_copy(&candidate, result_prime);
    }

cleanup_candidate_remainder:
    mp_clear(&candidate);
    mp_clear(&remainder);
cleanup_small_primes_full: 
cleanup_small_primes_partial: // Label for when only some small_primes_mp are initialized
    for (int i = 0; i < initialized_small_primes; i++) {
        mp_clear(&small_primes_mp[i]);
    }
    return err;
}


int rsa_generate_keypair(rsa_ctx *ctx, int keysize) {
    int err;
    mp_int phi, p_minus_1, q_minus_1; // p and q are in ctx->p, ctx->q

    int prime_bits = keysize / 2;

    if ((err = rsa_generate_one_prime(&ctx->p, prime_bits, prime_list, NUM_SMALL_PRIMES)) != MP_OKAY) {
        return err;
    }

    do {
        if ((err = rsa_generate_one_prime(&ctx->q, prime_bits, prime_list, NUM_SMALL_PRIMES)) != MP_OKAY) {
            return err;
        }
    } while (mp_cmp(&ctx->p, &ctx->q) == MP_EQ); // Repeat if p == q

    if ((err = mp_mul(&ctx->p, &ctx->q, &ctx->n)) != MP_OKAY) {
        return err;
    }

    if ((err = mp_init_multi(&phi, &p_minus_1, &q_minus_1, NULL)) != MP_OKAY) {
        return err; // Error initializing temps
    }
    
    if ((err = mp_sub_d(&ctx->p, 1, &p_minus_1)) != MP_OKAY) goto cleanup_phi;
    if ((err = mp_sub_d(&ctx->q, 1, &q_minus_1)) != MP_OKAY) goto cleanup_phi;
    if ((err = mp_mul(&p_minus_1, &q_minus_1, &phi)) != MP_OKAY) goto cleanup_phi;

    mp_set_ul(&ctx->e, 65537);

    if ((err = mp_invmod(&ctx->e, &phi, &ctx->d)) != MP_OKAY) {
        goto cleanup_phi;
    }

    if ((err = mp_mod(&ctx->d, &p_minus_1, &ctx->dp)) != MP_OKAY) goto cleanup_phi;
    if ((err = mp_mod(&ctx->d, &q_minus_1, &ctx->dq)) != MP_OKAY) goto cleanup_phi;
    if ((err = mp_invmod(&ctx->q, &ctx->p, &ctx->qinv)) != MP_OKAY) goto cleanup_phi;

cleanup_phi:
    mp_clear_multi(&phi, &p_minus_1, &q_minus_1, NULL);
    return err; // Return the latest error code, or MP_OKAY if successful
}

int rsa_encrypt_file(rsa_ctx *ctx, const char *infile_name, const char *outfile_name) {
    FILE *fin = fopen(infile_name, "rb");
    if (!fin) {
        perror("Error opening input file for encryption");
        return MP_ERR; // Indicate generic error, or use a custom code
    }
    FILE *fout = fopen(outfile_name, "wb");
    if (!fout) {
        perror("Error opening output file for encryption");
        fclose(fin);
        return MP_ERR;
    }

    int modulus_bytes = mp_unsigned_bin_size(&ctx->n);
    int block_size = modulus_bytes - 11; 
    if (block_size <= 0) { // Modulus too small for PKCS#1 v1.5 padding
        fprintf(stderr, "RSA modulus too small for PKCS#1 v1.5 padding.\n");
        fclose(fin);
        fclose(fout);
        return MP_VAL; // Invalid parameter or value error
    }

    unsigned char *data_block_buf = malloc(block_size);
    if (!data_block_buf) {
        fclose(fin);
        fclose(fout);
        return MP_MEM;
    }

    mp_int plain, cipher;
    int err = MP_OKAY;

    if ((err = mp_init_multi(&plain, &cipher, NULL)) != MP_OKAY) {
        free(data_block_buf);
        fclose(fin);
        fclose(fout);
        return err;
    }

    size_t bytes_read;
    while ((bytes_read = fread(data_block_buf, 1, block_size, fin)) > 0) {

        if ((err = mp_read_unsigned_bin(&plain, data_block_buf, bytes_read)) != MP_OKAY) break;
        if ((err = mp_exptmod(&plain, &ctx->e, &ctx->n, &cipher)) != MP_OKAY) break;

        int cipher_size = mp_unsigned_bin_size(&cipher);
        unsigned char *cipher_bytes = malloc(cipher_size);
        if (!cipher_bytes) { err = MP_MEM; break; }

        if ((err = mp_to_unsigned_bin(&cipher, cipher_bytes)) != MP_OKAY) { // Use mp_to_unsigned_bin_n for fixed size buffer
            free(cipher_bytes);
            break;
        }
        
        // Write size of ciphertext block, then ciphertext block
        if (fwrite(&cipher_size, sizeof(int), 1, fout) != 1) { err = MP_ERR; free(cipher_bytes); break; }
        if (fwrite(cipher_bytes, 1, cipher_size, fout) != cipher_size) { err = MP_ERR; free(cipher_bytes); break; }
        free(cipher_bytes);
    }
    if (ferror(fin)) { // Check for read errors
        err = MP_ERR; 
    }


    free(data_block_buf);
    mp_clear_multi(&plain, &cipher, NULL);
    fclose(fin);
    fclose(fout);
    return err;
}

int rsa_decrypt_file(rsa_ctx *ctx, const char *infile_name, const char *outfile_name) {
    FILE *fin = fopen(infile_name, "rb");
    if (!fin) {
        perror("Error opening input file for decryption");
        return MP_ERR;
    }
    FILE *fout = fopen(outfile_name, "wb");
    if (!fout) {
        perror("Error opening output file for decryption");
        fclose(fin);
        return MP_ERR;
    }

    mp_int cipher, plain;
    mp_int m1, m2, h; // For CRT
    int err = MP_OKAY;

    if ((err = mp_init_multi(&cipher, &plain, &m1, &m2, &h, NULL)) != MP_OKAY) {
        fclose(fin);
        fclose(fout);
        return err;
    }

    int cipher_block_size;
    while (fread(&cipher_block_size, sizeof(int), 1, fin) == 1) {
        if (cipher_block_size <= 0 || cipher_block_size > mp_unsigned_bin_size(&ctx->n) + 4 /*some margin*/) {
             // Basic sanity check for block size
            err = MP_VAL; 
            break;
        }
        unsigned char *cipher_bytes_buf = malloc(cipher_block_size);
        if (!cipher_bytes_buf) { err = MP_MEM; break; }

        if (fread(cipher_bytes_buf, 1, cipher_block_size, fin) != cipher_block_size) {
            free(cipher_bytes_buf);
            err = MP_ERR; // Read error or unexpected EOF
            break;
        }
        
        if ((err = mp_read_unsigned_bin(&cipher, cipher_bytes_buf, cipher_block_size)) != MP_OKAY) {
            free(cipher_bytes_buf);
            break;
        }
        free(cipher_bytes_buf);

        if ((err = mp_exptmod(&cipher, &ctx->dp, &ctx->p, &m1)) != MP_OKAY) break;
        if ((err = mp_exptmod(&cipher, &ctx->dq, &ctx->q, &m2)) != MP_OKAY) break;

        mp_sub(&m1, &m2, &h); // h = m1 - m2
        if ((err = mp_mulmod(&h, &ctx->qinv, &ctx->p, &h)) != MP_OKAY) break;
        
        if ((err = mp_mul(&h, &ctx->q, &h)) != MP_OKAY) break;
        if ((err = mp_add(&h, &m2, &plain)) != MP_OKAY) break;

        int plain_size = mp_unsigned_bin_size(&plain);
        unsigned char *plain_bytes_buf = malloc(plain_size);
        if (!plain_bytes_buf) { err = MP_MEM; break; }

        if ((err = mp_to_unsigned_bin(&plain, plain_bytes_buf)) != MP_OKAY) {
            free(plain_bytes_buf);
            break;
        }
        if (fwrite(plain_bytes_buf, 1, plain_size, fout) != plain_size) {
            err = MP_ERR; free(plain_bytes_buf); break;
        }
        free(plain_bytes_buf);
    }
    if (ferror(fin) && err == MP_OKAY) { // Check for read errors if no other LTM error occurred
         err = MP_ERR;
    }

    mp_clear_multi(&cipher, &plain, &m1, &m2, &h, NULL);
    fclose(fin);
    fclose(fout);
    return err;
}
