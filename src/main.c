#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>     // For seeding rand()
#include <unistd.h>   // For getopt() - POSIX standard for option parsing
#include <errno.h>    // For perror()
#include <getopt.h>   // For getopt_long, if preferred, but getopt is used here

#include "rsa.h"      // For RSA functionalities
#include "blowfish.h"
#include "tea.h"
#include "utils.h"    // Assumed to contain symmetric cipher helpers

// Define modes
typedef enum { MODE_ENCRYPT, MODE_DECRYPT, MODE_KEYGEN, MODE_NONE } op_mode;
typedef enum { ALGO_BLOWFISH, ALGO_TEA, ALGO_RSA, ALGO_NONE } algorithm_type;

// Function pointer types for symmetric cipher operations (unchanged)
typedef void (*init_func_t)(void*, const uint8_t*, size_t);
typedef void (*crypt_func_t)(const void*, uint*, uint*);


// --- RSA Key I/O Stubs (These need to be implemented in rsa.c or similar) ---

/**
 * @brief Loads an RSA public key from a file into the rsa_ctx.
 * @param ctx Pointer to the rsa_ctx structure.
 * @param pubkey_file Path to the public key file.
 * @return MP_OKAY on success, an error code otherwise.
 * @note The file format needs to be defined and implemented.
 * Typically stores modulus (n) and public exponent (e).
 */
static int rsa_load_public_key_from_file(rsa_ctx *ctx, const char *pubkey_file) {
    // STUB: Implementation needed.
    // Example: Open pubkey_file, read n and e, and load them into ctx->n and ctx->e.
    // Ensure mp_int variables are initialized if not already.
    fprintf(stdout, "INFO: Stub rsa_load_public_key_from_file called for %s. Needs implementation.\n", pubkey_file);
    // For testing, you might hardcode or set minimal values if ctx is already init'd
    // mp_set_ul(&ctx->e, 65537UL); // Example, n would also be needed
    if (!pubkey_file) return MP_ERR; // Basic check
    return MP_OKAY; // Placeholder success
}

/**
 * @brief Loads an RSA private key from a file into the rsa_ctx.
 * @param ctx Pointer to the rsa_ctx structure.
 * @param privkey_file Path to the private key file.
 * @return MP_OKAY on success, an error code otherwise.
 * @note The file format needs to be defined and implemented.
 * Typically stores modulus (n), private exponent (d), and optionally CRT params.
 */
static int rsa_load_private_key_from_file(rsa_ctx *ctx, const char *privkey_file) {
    // STUB: Implementation needed.
    // Example: Open privkey_file, read necessary components (n, d, p, q, dp, dq, qinv)
    // and load them into the rsa_ctx.
    fprintf(stdout, "INFO: Stub rsa_load_private_key_from_file called for %s. Needs implementation.\n", privkey_file);
    if (!privkey_file) return MP_ERR; // Basic check
    return MP_OKAY; // Placeholder success
}

/**
 * @brief Saves an RSA public key from rsa_ctx to a file.
 * @param ctx Pointer to the rsa_ctx structure containing the key.
 * @param pubkey_file Path to save the public key file.
 * @return MP_OKAY on success, an error code otherwise.
 * @note The file format needs to be defined and implemented. Saves n and e.
 */
static int rsa_save_public_key_to_file(rsa_ctx *ctx, const char *pubkey_file) {
    // STUB: Implementation needed.
    // Example: Open pubkey_file, get n and e from ctx, convert to a storable format, and write.
    fprintf(stdout, "INFO: Stub rsa_save_public_key_to_file called for %s. Needs implementation.\n", pubkey_file);
    // FILE* f = fopen(pubkey_file, "wb"); if (!f) return MP_ERR;
    // ... logic to write mp_int n, e ...
    // fclose(f);
    if (!ctx || !pubkey_file) return MP_ERR;
    return MP_OKAY; // Placeholder success
}

/**
 * @brief Saves an RSA private key from rsa_ctx to a file.
 * @param ctx Pointer to the rsa_ctx structure containing the key.
 * @param privkey_file Path to save the private key file.
 * @return MP_OKAY on success, an error code otherwise.
 * @note The file format needs to be defined and implemented. Saves n, d, p, q, dp, dq, qinv.
 */
static int rsa_save_private_key_to_file(rsa_ctx *ctx, const char *privkey_file) {
    // STUB: Implementation needed.
    // Example: Open privkey_file, get components from ctx, convert and write.
    fprintf(stdout, "INFO: Stub rsa_save_private_key_to_file called for %s. Needs implementation.\n", privkey_file);
    if (!ctx || !privkey_file) return MP_ERR;
    return MP_OKAY; // Placeholder success
}


// --- Helper Functions ---

void print_usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s <-e|-d|-g <keysize>> -a <algorithm> [options]\n\n", prog_name);
    fprintf(stderr, "Modes & Algorithms:\n");
    fprintf(stderr, "  -e             Encrypt mode (requires -a, -i, -o)\n");
    fprintf(stderr, "  -d             Decrypt mode (requires -a, -i, -o)\n");
    fprintf(stderr, "  -g <keysize>   RSA Key Generation mode (e.g., 2048). Requires -N <name_base>.\n");
    fprintf(stderr, "                 Algorithm (-a) should be 'rsa' or not specified for keygen.\n\n");
    fprintf(stderr, "  -a <algorithm> Specify algorithm: 'blowfish', 'tea', or 'rsa'.\n\n");
    fprintf(stderr, "Common Options:\n");
    fprintf(stderr, "  -i <infile>    Input file path.\n");
    fprintf(stderr, "  -o <outfile>   Output file path.\n");
    fprintf(stderr, "  -h             Show this help message.\n\n");
    fprintf(stderr, "Symmetric Algorithm Options (blowfish, tea):\n");
    fprintf(stderr, "  -k <key>       Encryption/Decryption key string.\n\n");
    fprintf(stderr, "RSA Algorithm Options:\n");
    fprintf(stderr, "  For -e (encrypt): -P <public_key_file>\n");
    fprintf(stderr, "  For -d (decrypt): -S <private_key_file>\n");
    fprintf(stderr, "  For -g (keygen):  -N <key_name_base> (e.g., 'mykey' -> 'mykey.pub', 'mykey.priv')\n");
}

// --- RSA Key Generation ---
int handle_rsa_key_generation(const char *key_name_base, int keysize) {
    rsa_ctx ctx;
    int err;
    char pub_file_name[256];
    char priv_file_name[256];

    snprintf(pub_file_name, sizeof(pub_file_name), "%s.pub", key_name_base);
    snprintf(priv_file_name, sizeof(priv_file_name), "%s.priv", key_name_base);

    printf("Initializing RSA context for key generation...\n");
    if ((err = rsa_init_ctx(&ctx)) != MP_OKAY) {
        fprintf(stderr, "Error: RSA context initialization failed: %s\n", mp_error_to_string(err));
        return -1;
    }

    printf("Generating %d-bit RSA keypair (base name: %s). This may take a while...\n", keysize, key_name_base);
    if ((err = rsa_generate_keypair(&ctx, keysize)) != MP_OKAY) {
        fprintf(stderr, "Error: RSA keypair generation failed: %s\n", mp_error_to_string(err));
        rsa_clear_ctx(&ctx);
        return -1;
    }
    printf("RSA keypair generated successfully.\n");

    printf("Saving public key to %s...\n", pub_file_name);
    if ((err = rsa_save_public_key_to_file(&ctx, pub_file_name)) != MP_OKAY) {
        fprintf(stderr, "Error: Failed to save RSA public key: %s\n", mp_error_to_string(err));
        // Continue to save private key if public key saving failed, but report error.
    }

    printf("Saving private key to %s...\n", priv_file_name);
    if ((err = rsa_save_private_key_to_file(&ctx, priv_file_name)) != MP_OKAY) {
        fprintf(stderr, "Error: Failed to save RSA private key: %s\n", mp_error_to_string(err));
    }

    rsa_clear_ctx(&ctx);
    printf("RSA key generation process finished.\n");
    return (err == MP_OKAY) ? 0 : -1; // Return success if last operation was okay, otherwise error
}


// --- File Processing ---
int process_file(op_mode mode, algorithm_type algo, 
                 const char *key_str,      // For symmetric algos
                 const char *pubkey_file,  // For RSA encryption
                 const char *privkey_file, // For RSA decryption
                 const char *infile, const char *outfile) {
    FILE *fin = NULL;
    FILE *fout = NULL;
    uint8_t *buffer = NULL; // For symmetric ciphers
    long file_size = 0;
    size_t data_len = 0; 
    size_t buffer_len = 0;
    int result = -1; 

    // --- Algorithm Specific Setup ---
    blowfish_ctx bf_ctx_sym; // Renamed to avoid conflict if rsa_ctx is named ctx
    uint tea_key[4]; 
    void *cipher_context_sym = NULL; 
    crypt_func_t encrypt_block_sym = NULL;
    crypt_func_t decrypt_block_sym = NULL;

    rsa_ctx rsa_ctx_obj; // RSA context
    int rsa_err;

    switch (algo) {
        case ALGO_BLOWFISH:
            if (!key_str) { fprintf(stderr, "Error: Key string (-k) required for Blowfish.\n"); goto cleanup; }
            blowfish_init(&bf_ctx_sym, (const uint8_t*)key_str, strlen(key_str));
            cipher_context_sym = &bf_ctx_sym;
            encrypt_block_sym = blowfish_encrypt_wrapper;
            decrypt_block_sym = blowfish_decrypt_wrapper;
            printf("Using Blowfish algorithm.\n");
            break;
        case ALGO_TEA:
            if (!key_str) { fprintf(stderr, "Error: Key string (-k) required for TEA.\n"); goto cleanup; }
            tea_prepare_key(tea_key, (const uint8_t*)key_str, strlen(key_str));
            cipher_context_sym = tea_key; 
            encrypt_block_sym = tea_encrypt_wrapper;
            decrypt_block_sym = tea_decrypt_wrapper;
            printf("Using TEA algorithm.\n");
            break;
        case ALGO_RSA:
            printf("Using RSA algorithm.\n");
            if ((rsa_err = rsa_init_ctx(&rsa_ctx_obj)) != MP_OKAY) {
                fprintf(stderr, "Error: RSA context initialization failed: %s\n", mp_error_to_string(rsa_err));
                goto cleanup;
            }
            if (mode == MODE_ENCRYPT) {
                if (!pubkey_file) { fprintf(stderr, "Error: Public key file (-P) required for RSA encryption.\n"); rsa_clear_ctx(&rsa_ctx_obj); goto cleanup; }
                if ((rsa_err = rsa_load_public_key_from_file(&rsa_ctx_obj, pubkey_file)) != MP_OKAY) {
                    fprintf(stderr, "Error: Failed to load RSA public key from %s: %s\n", pubkey_file, mp_error_to_string(rsa_err));
                    rsa_clear_ctx(&rsa_ctx_obj);
                    goto cleanup;
                }
            } else if (mode == MODE_DECRYPT) {
                if (!privkey_file) { fprintf(stderr, "Error: Private key file (-S) required for RSA decryption.\n"); rsa_clear_ctx(&rsa_ctx_obj); goto cleanup; }
                 if ((rsa_err = rsa_load_private_key_from_file(&rsa_ctx_obj, privkey_file)) != MP_OKAY) {
                    fprintf(stderr, "Error: Failed to load RSA private key from %s: %s\n", privkey_file, mp_error_to_string(rsa_err));
                    rsa_clear_ctx(&rsa_ctx_obj);
                    goto cleanup;
                }
            }
            // RSA processing happens below, not using the symmetric cipher file reading loop
            break;
        default:
            fprintf(stderr, "Error: Invalid algorithm selected for processing.\n");
            goto cleanup;
    }

    if (algo == ALGO_RSA) {
        // RSA file processing is handled by rsa_encrypt_file / rsa_decrypt_file directly
        if (mode == MODE_ENCRYPT) {
            printf("Encrypting %s to %s using RSA...\n", infile, outfile);
            rsa_err = rsa_encrypt_file(&rsa_ctx_obj, infile, outfile);
            if (rsa_err != MP_OKAY) {
                fprintf(stderr, "Error: RSA encryption failed: %s\n", mp_error_to_string(rsa_err));
            } else {
                printf("RSA encryption successful.\n");
                result = 0;
            }
        } else if (mode == MODE_DECRYPT) {
            printf("Decrypting %s to %s using RSA...\n", infile, outfile);
            rsa_err = rsa_decrypt_file(&rsa_ctx_obj, infile, outfile);
            if (rsa_err != MP_OKAY) {
                fprintf(stderr, "Error: RSA decryption failed: %s\n", mp_error_to_string(rsa_err));
            } else {
                printf("RSA decryption successful.\n");
                result = 0;
            }
        }
        rsa_clear_ctx(&rsa_ctx_obj); // Clear RSA context after use
        goto cleanup_no_files; // Skip symmetric file I/O and buffer free
    }


    // --- Open Files (for symmetric ciphers) ---
    fin = fopen(infile, "rb");
    if (!fin) {
        perror("Error opening input file");
        goto cleanup;
    }

    fout = fopen(outfile, "wb");
    if (!fout) {
        perror("Error opening output file");
        goto cleanup;
    }

    // --- Read Input File (for symmetric ciphers) ---
    fseek(fin, 0, SEEK_END);
    file_size = ftell(fin);
    if (file_size < 0) {
         perror("Error getting input file size");
         goto cleanup;
    }
    fseek(fin, 0, SEEK_SET);

    if (mode == MODE_ENCRYPT) {
        buffer = malloc(file_size); // Read entire plaintext
        if (!buffer) { perror("Error allocating memory for input buffer"); goto cleanup; }
        if (fread(buffer, 1, file_size, fin) != (size_t)file_size) {
            fprintf(stderr, "Error reading input file.\n"); goto cleanup;
        }
        data_len = file_size;
        buffer_len = data_len;

        // --- Padding (Symmetric Encryption) ---
        buffer_len = add_padding(&buffer, data_len); // buffer might be realloc'd
        if (buffer_len == 0) { fprintf(stderr, "Error adding padding.\n"); goto cleanup; }
        printf("Original size: %zu bytes, Padded size: %zu bytes\n", data_len, buffer_len);

        uint8_t iv[BLOCK_SIZE];
        generate_iv(iv); 
        if (fwrite(iv, 1, BLOCK_SIZE, fout) != BLOCK_SIZE) {
            perror("Error writing IV to output file"); goto cleanup;
        }
        printf("Generated and wrote IV.\n");

        cbc_encrypt(encrypt_block_sym, cipher_context_sym, iv, buffer, buffer_len);
        printf("Symmetric encryption complete.\n");

        if (fwrite(buffer, 1, buffer_len, fout) != buffer_len) {
            perror("Error writing encrypted data"); goto cleanup;
        }

    } else { // MODE_DECRYPT (Symmetric)
        if (file_size < BLOCK_SIZE) {
            fprintf(stderr, "Error: Input file too small for IV (symmetric decryption).\n"); goto cleanup;
        }

        uint8_t iv[BLOCK_SIZE];
        if (fread(iv, 1, BLOCK_SIZE, fin) != BLOCK_SIZE) {
            fprintf(stderr, "Error reading IV from input file.\n"); goto cleanup;
        }
        printf("Read IV from file.\n");

        buffer_len = file_size - BLOCK_SIZE;
        if (buffer_len == 0 && algo != ALGO_NONE) { // ALGO_NONE check is defensive
             printf("No encrypted data found after IV (symmetric decryption).\n");
             result = 0; 
             goto cleanup;
        }
        if (buffer_len % BLOCK_SIZE != 0 && algo != ALGO_NONE) {
             fprintf(stderr, "Warning: Encrypted data size (%zu) not multiple of block size (%d).\n", buffer_len, BLOCK_SIZE);
        }
        
        buffer = malloc(buffer_len);
        if (!buffer) { perror("Error allocating memory for input buffer"); goto cleanup; }
        if (fread(buffer, 1, buffer_len, fin) != buffer_len) {
            fprintf(stderr, "Error reading encrypted data.\n"); goto cleanup;
        }

        cbc_decrypt(decrypt_block_sym, cipher_context_sym, iv, buffer, buffer_len);
        printf("Symmetric decryption complete.\n");

        data_len = check_remove_padding(buffer, buffer_len);
        if (data_len == buffer_len && buffer_len > 0) {
             printf("Warning: Invalid padding or no padding found (symmetric decryption).\n");
        } else {
             printf("Padding removed. Original size: %zu bytes\n", data_len);
        }

        if (fwrite(buffer, 1, data_len, fout) != data_len) {
            perror("Error writing decrypted data"); goto cleanup;
        }
    }

    result = 0; // Success for symmetric path

cleanup:
    if (fin) fclose(fin);
    if (fout) fclose(fout);
    if (buffer) free(buffer); // Buffer is only for symmetric ciphers here
cleanup_no_files: // Jump here if RSA handled files itself or on early RSA errors
    return result;
}


// --- Main Function ---
int main(int argc, char *argv[]) {
    op_mode mode = MODE_NONE;
    algorithm_type algo = ALGO_NONE;
    char *key_str = NULL;     // For symmetric algos
    char *infile = NULL;
    char *outfile = NULL;
    char *rsa_pubkey_file = NULL;
    char *rsa_privkey_file = NULL;
    char *rsa_key_name_base = NULL;
    int rsa_keysize = 0;
    int opt;

    // Seed the pseudo-random number generator once
    srand(time(NULL));

    // getopt option string: add g:N:P:S:
    // g takes an argument (keysize)
    // N takes an argument (key name base)
    // P takes an argument (public key file)
    // S takes an argument (private key file)
    while ((opt = getopt(argc, argv, "edg:a:k:i:o:hN:P:S:")) != -1) {
        switch (opt) {
            case 'e':
                if (mode != MODE_NONE && mode != MODE_KEYGEN) { // Allow -e with -g if algo is rsa for some reason, though -g is primary
                    fprintf(stderr, "Error: Mode already specified.\n"); print_usage(argv[0]); return 1;
                }
                mode = MODE_ENCRYPT;
                break;
            case 'd':
                if (mode != MODE_NONE && mode != MODE_KEYGEN) {
                    fprintf(stderr, "Error: Mode already specified.\n"); print_usage(argv[0]); return 1;
                }
                mode = MODE_DECRYPT;
                break;
            case 'g':
                if (mode != MODE_NONE) {
                    fprintf(stderr, "Error: Mode already specified. Key generation (-g) is a distinct mode.\n"); print_usage(argv[0]); return 1;
                }
                mode = MODE_KEYGEN;
                rsa_keysize = atoi(optarg);
                if (rsa_keysize == 0 && strcmp(optarg, "0") != 0) { // atoi returns 0 on error or for "0"
                    fprintf(stderr, "Error: Invalid keysize '%s' for -g.\n", optarg); print_usage(argv[0]); return 1;
                }
                break;
            case 'a':
                if (strcmp(optarg, "blowfish") == 0) algo = ALGO_BLOWFISH;
                else if (strcmp(optarg, "tea") == 0) algo = ALGO_TEA;
                else if (strcmp(optarg, "rsa") == 0) algo = ALGO_RSA;
                else {
                    fprintf(stderr, "Error: Invalid algorithm '%s'.\n", optarg); print_usage(argv[0]); return 1;
                }
                break;
            case 'k': key_str = optarg; break;
            case 'i': infile = optarg; break;
            case 'o': outfile = optarg; break;
            case 'N': rsa_key_name_base = optarg; break;
            case 'P': rsa_pubkey_file = optarg; break;
            case 'S': rsa_privkey_file = optarg; break;
            case 'h': print_usage(argv[0]); return 0;
            case '?': print_usage(argv[0]); return 1;
            default: abort();
        }
    }

    // --- Validate arguments based on mode ---
    if (mode == MODE_KEYGEN) {
        if (rsa_keysize < 512) { // Basic check, rsa_generate_keypair might have stricter limits
            fprintf(stderr, "Error: Keysize for RSA generation (-g) must be at least 512 bits.\n"); print_usage(argv[0]); return 1;
        }
        if (!rsa_key_name_base) {
            fprintf(stderr, "Error: Key name base (-N) required for RSA key generation.\n"); print_usage(argv[0]); return 1;
        }
        // Optionally, ensure algo is RSA or not set for keygen
        if (algo != ALGO_NONE && algo != ALGO_RSA) {
             fprintf(stderr, "Warning: Algorithm (-a %s) specified with RSA key generation (-g) is ignored.\n", argv[optind-1]); // optind might be tricky here
        }
        algo = ALGO_RSA; // Implicitly RSA for keygen
    } else if (mode == MODE_ENCRYPT || mode == MODE_DECRYPT) {
        if (algo == ALGO_NONE) {
            fprintf(stderr, "Error: Algorithm (-a) must be specified for encryption/decryption.\n"); print_usage(argv[0]); return 1;
        }
        if (!infile || !outfile) {
            fprintf(stderr, "Error: Input (-i) and output (-o) files must be specified.\n"); print_usage(argv[0]); return 1;
        }
        if (algo == ALGO_RSA) {
            if (mode == MODE_ENCRYPT && !rsa_pubkey_file) {
                fprintf(stderr, "Error: RSA public key file (-P) required for encryption.\n"); print_usage(argv[0]); return 1;
            }
            if (mode == MODE_DECRYPT && !rsa_privkey_file) {
                fprintf(stderr, "Error: RSA private key file (-S) required for decryption.\n"); print_usage(argv[0]); return 1;
            }
        } else { // Symmetric algos
            if (!key_str) {
                fprintf(stderr, "Error: Key string (-k) required for %s.\n", (algo == ALGO_BLOWFISH ? "Blowfish" : "TEA"));
                print_usage(argv[0]); return 1;
            }
        }
    } else { // MODE_NONE
        fprintf(stderr, "Error: Operation mode (-e, -d, or -g) must be specified.\n");
        print_usage(argv[0]);
        return 1;
    }

    // Check for non-option arguments
    if (optind < argc) {
        fprintf(stderr, "Error: Unexpected arguments found: ");
        while (optind < argc) fprintf(stderr, "%s ", argv[optind++]);
        fprintf(stderr, "\n"); print_usage(argv[0]); return 1;
    }

    // --- Execute Operation ---
    int operation_result = -1;
    if (mode == MODE_KEYGEN) {
        operation_result = handle_rsa_key_generation(rsa_key_name_base, rsa_keysize);
    } else { // ENCRYPT or DECRYPT
        operation_result = process_file(mode, algo, key_str, rsa_pubkey_file, rsa_privkey_file, infile, outfile);
    }

    if (operation_result != 0) {
        fprintf(stderr, "Operation failed.\n");
        return 1; 
    }

    printf("Operation completed successfully.\n");
    return 0; 
}
