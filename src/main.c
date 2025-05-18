#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>

#include "rsa.h"
#include "blowfish.h"
#include "tea.h"
#include "utils.h"

typedef enum
{
    MODE_ENCRYPT,
    MODE_DECRYPT,
    MODE_KEYGEN,
    MODE_NONE
} op_mode;
typedef enum
{
    ALGO_BLOWFISH,
    ALGO_TEA,
    ALGO_RSA,
    ALGO_NONE
} algorithm_type;

typedef void (*init_func_t)(void *, const uint8_t *, size_t);
typedef void (*crypt_func_t)(const void *, uint *, uint *);

#define RSA_KEY_FILE_LINE_MAX_LEN 4096

static int write_mp_int_to_file_hex(FILE *f, const char *label, mp_int *val)
{
    int err;
    int size;
    char *buffer;

    if (!f || !label || !val)
    {
        return MP_VAL;
    }

    if ((err = mp_radix_size(val, 16, &size)) != MP_OKAY)
    {
        fprintf(stderr, "Error: mp_radix_size failed for %s: %s\n", label, mp_error_to_string(err));
        return err;
    }

    buffer = malloc(size);
    if (!buffer)
    {
        fprintf(stderr, "Error: Memory allocation failed for %s hex string.\n", label);
        return MP_MEM;
    }

    if ((err = mp_toradix(val, buffer, 16)) != MP_OKAY)
    {
        fprintf(stderr, "Error: mp_toradix failed for %s: %s\n", label, mp_error_to_string(err));
        free(buffer);
        return err;
    }

    if (fprintf(f, "%s: %s\n", label, buffer) < 0)
    {
        perror("Error writing mp_int to file");
        free(buffer);
        return MP_ERR;
    }

    free(buffer);
    return MP_OKAY;
}

void print_usage(const char *prog_name)
{
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

int handle_rsa_key_generation(const char *key_name_base, int keysize)
{
    rsa_ctx ctx;
    int err;
    char pub_file_name[256];
    char priv_file_name[256];

    snprintf(pub_file_name, sizeof(pub_file_name), "%s.pub", key_name_base);
    snprintf(priv_file_name, sizeof(priv_file_name), "%s.priv", key_name_base);

    printf("Initializing RSA context for key generation...\n");
    if ((err = rsa_init_ctx(&ctx)) != MP_OKAY)
    {
        fprintf(stderr, "Error: RSA context initialization failed: %s\n", mp_error_to_string(err));
        return -1;
    }

    printf("Generating %d-bit RSA keypair (base name: %s). This may take a while...\n", keysize, key_name_base);
    if ((err = rsa_generate_keypair(&ctx, keysize)) != MP_OKAY)
    {
        fprintf(stderr, "Error: RSA keypair generation failed: %s\n", mp_error_to_string(err));
        rsa_clear_ctx(&ctx);
        return -1;
    }
    printf("RSA keypair generated successfully.\n");

    printf("Saving public key to %s...\n", pub_file_name);
    if ((err = rsa_save_public_key_to_file(&ctx, pub_file_name)) != MP_OKAY)
    {
        fprintf(stderr, "Error: Failed to save RSA public key: %s\n", mp_error_to_string(err));
    }

    printf("Saving private key to %s...\n", priv_file_name);
    if ((err = rsa_save_private_key_to_file(&ctx, priv_file_name)) != MP_OKAY)
    {
        fprintf(stderr, "Error: Failed to save RSA private key: %s\n", mp_error_to_string(err));
    }

    rsa_clear_ctx(&ctx);
    printf("RSA key generation process finished.\n");
    return (err == MP_OKAY) ? 0 : -1;
}

int process_file(op_mode mode, algorithm_type algo,
                 const char *key_str,
                 const char *pubkey_file,
                 const char *privkey_file,
                 const char *infile, const char *outfile)
{
    FILE *fin = NULL;
    FILE *fout = NULL;
    uint8_t *buffer = NULL;
    long file_size = 0;
    size_t data_len = 0;
    size_t buffer_len = 0;
    int result = -1;

    blowfish_ctx bf_ctx_sym;
    uint tea_key[4];
    void *cipher_context_sym = NULL;
    crypt_func_t encrypt_block_sym = NULL;
    crypt_func_t decrypt_block_sym = NULL;

    rsa_ctx rsa_ctx_obj;
    int rsa_err;

    switch (algo)
    {
    case ALGO_BLOWFISH:
        if (!key_str)
        {
            fprintf(stderr, "Error: Key string (-k) required for Blowfish.\n");
            goto cleanup;
        }
        blowfish_init(&bf_ctx_sym, (const uint8_t *)key_str, strlen(key_str));
        cipher_context_sym = &bf_ctx_sym;
        encrypt_block_sym = blowfish_encrypt_wrapper;
        decrypt_block_sym = blowfish_decrypt_wrapper;
        printf("Using Blowfish algorithm.\n");
        break;
    case ALGO_TEA:
        if (!key_str)
        {
            fprintf(stderr, "Error: Key string (-k) required for TEA.\n");
            goto cleanup;
        }
        tea_prepare_key(tea_key, (const uint8_t *)key_str, strlen(key_str));
        cipher_context_sym = tea_key;
        encrypt_block_sym = tea_encrypt_wrapper;
        decrypt_block_sym = tea_decrypt_wrapper;
        printf("Using TEA algorithm.\n");
        break;
    case ALGO_RSA:
        printf("Using RSA algorithm.\n");
        if ((rsa_err = rsa_init_ctx(&rsa_ctx_obj)) != MP_OKAY)
        {
            fprintf(stderr, "Error: RSA context initialization failed: %s\n", mp_error_to_string(rsa_err));
            return -1;
        }
        if (mode == MODE_ENCRYPT)
        {
            if (!pubkey_file)
            {
                fprintf(stderr, "Error: Public key file (-P) required for RSA encryption.\n");
                rsa_clear_ctx(&rsa_ctx_obj);
                return -1;
            }
            if ((rsa_err = rsa_load_public_key_from_file(&rsa_ctx_obj, pubkey_file)) != MP_OKAY)
            {
                fprintf(stderr, "Error: Failed to load RSA public key from %s: %s\n", pubkey_file, mp_error_to_string(rsa_err));
                rsa_clear_ctx(&rsa_ctx_obj);
                return -1;
            }
        }
        else if (mode == MODE_DECRYPT)
        {
            if (!privkey_file)
            {
                fprintf(stderr, "Error: Private key file (-S) required for RSA decryption.\n");
                rsa_clear_ctx(&rsa_ctx_obj);
                return -1;
            }
            if ((rsa_err = rsa_load_private_key_from_file(&rsa_ctx_obj, privkey_file)) != MP_OKAY)
            {
                fprintf(stderr, "Error: Failed to load RSA private key from %s: %s\n", privkey_file, mp_error_to_string(rsa_err));
                rsa_clear_ctx(&rsa_ctx_obj);
                return -1;
            }
        }
        break;
    default:
        fprintf(stderr, "Error: Invalid algorithm selected for processing.\n");
        goto cleanup;
    }

    if (algo == ALGO_RSA)
    {
        rsa_clear_ctx(&rsa_ctx_obj);
        return (rsa_err == MP_OKAY) ? 0 : -1;
    }

    fin = fopen(infile, "rb");
    if (!fin)
    {
        perror("Error opening input file");
        goto cleanup;
    }

    fout = fopen(outfile, "wb");
    if (!fout)
    {
        perror("Error opening output file");
        goto cleanup;
    }

    fseek(fin, 0, SEEK_END);
    file_size = ftell(fin);
    if (file_size < 0)
    {
        perror("Error getting input file size");
        goto cleanup;
    }
    fseek(fin, 0, SEEK_SET);

    if (mode == MODE_ENCRYPT)
    {
        buffer = malloc(file_size);
        if (!buffer)
        {
            perror("Error allocating memory for input buffer");
            goto cleanup;
        }
        if (fread(buffer, 1, file_size, fin) != (size_t)file_size)
        {
            fprintf(stderr, "Error reading input file.\n");
            goto cleanup;
        }
        data_len = file_size;
        buffer_len = data_len;

        buffer_len = add_padding(&buffer, data_len);
        if (buffer_len == 0)
        {
            fprintf(stderr, "Error adding padding.\n");
            goto cleanup;
        }
        printf("Original size: %zu bytes, Padded size: %zu bytes\n", data_len, buffer_len);

        uint8_t iv[BLOCK_SIZE];
        generate_iv(iv);
        if (fwrite(iv, 1, BLOCK_SIZE, fout) != BLOCK_SIZE)
        {
            perror("Error writing IV to output file");
            goto cleanup;
        }
        printf("Generated and wrote IV.\n");

        cbc_encrypt(encrypt_block_sym, cipher_context_sym, iv, buffer, buffer_len);
        printf("Symmetric encryption complete.\n");

        if (fwrite(buffer, 1, buffer_len, fout) != buffer_len)
        {
            perror("Error writing encrypted data");
            goto cleanup;
        }
    }
    else
    {
        if (file_size < BLOCK_SIZE)
        {
            fprintf(stderr, "Error: Input file too small for IV (symmetric decryption).\n");
            goto cleanup;
        }

        uint8_t iv[BLOCK_SIZE];
        if (fread(iv, 1, BLOCK_SIZE, fin) != BLOCK_SIZE)
        {
            fprintf(stderr, "Error reading IV from input file.\n");
            goto cleanup;
        }
        printf("Read IV from file.\n");

        buffer_len = file_size - BLOCK_SIZE;
        if (buffer_len == 0 && algo != ALGO_NONE)
        {
            printf("No encrypted data found after IV (symmetric decryption).\n");
            result = 0;
            goto cleanup;
        }
        if (buffer_len % BLOCK_SIZE != 0 && algo != ALGO_NONE)
        {
            fprintf(stderr, "Warning: Encrypted data size (%zu) not multiple of block size (%d).\n", buffer_len, BLOCK_SIZE);
        }

        buffer = malloc(buffer_len);
        if (!buffer)
        {
            perror("Error allocating memory for input buffer");
            goto cleanup;
        }
        if (fread(buffer, 1, buffer_len, fin) != buffer_len)
        {
            fprintf(stderr, "Error reading encrypted data.\n");
            goto cleanup;
        }

        cbc_decrypt(decrypt_block_sym, cipher_context_sym, iv, buffer, buffer_len);
        printf("Symmetric decryption complete.\n");

        data_len = check_remove_padding(buffer, buffer_len);
        if (data_len == buffer_len && buffer_len > 0)
        {
            printf("Warning: Invalid padding or no padding found (symmetric decryption).\n");
        }
        else
        {
            printf("Padding removed. Original size: %zu bytes\n", data_len);
        }

        if (fwrite(buffer, 1, data_len, fout) != data_len)
        {
            perror("Error writing decrypted data");
            goto cleanup;
        }
    }

    result = 0;

cleanup:
    if (fin)
        fclose(fin);
    if (fout)
        fclose(fout);
    if (buffer)
        free(buffer);
cleanup_no_files:
    return result;
}

int main(int argc, char *argv[])
{
    op_mode mode = MODE_NONE;
    algorithm_type algo = ALGO_NONE;
    char *key_str = NULL;
    char *infile = NULL;
    char *outfile = NULL;
    char *rsa_pubkey_file = NULL;
    char *rsa_privkey_file = NULL;
    char *rsa_key_name_base = NULL;
    int rsa_keysize = 0;
    int opt;

    srand(time(NULL));

    while ((opt = getopt(argc, argv, "edg:a:k:i:o:hN:P:S:")) != -1)
    {
        switch (opt)
        {
        case 'e':
            if (mode != MODE_NONE && mode != MODE_KEYGEN)
            {
                fprintf(stderr, "Error: Mode already specified.\n");
                print_usage(argv[0]);
                return 1;
            }
            mode = MODE_ENCRYPT;
            break;
        case 'd':
            if (mode != MODE_NONE && mode != MODE_KEYGEN)
            {
                fprintf(stderr, "Error: Mode already specified.\n");
                print_usage(argv[0]);
                return 1;
            }
            mode = MODE_DECRYPT;
            break;
        case 'g':
            if (mode != MODE_NONE)
            {
                fprintf(stderr, "Error: Mode already specified. Key generation (-g) is a distinct mode.\n");
                print_usage(argv[0]);
                return 1;
            }
            mode = MODE_KEYGEN;
            rsa_keysize = atoi(optarg);
            if (rsa_keysize == 0 && strcmp(optarg, "0") != 0)
            {
                fprintf(stderr, "Error: Invalid keysize '%s' for -g.\n", optarg);
                print_usage(argv[0]);
                return 1;
            }
            break;
        case 'a':
            if (strcmp(optarg, "blowfish") == 0)
                algo = ALGO_BLOWFISH;
            else if (strcmp(optarg, "tea") == 0)
                algo = ALGO_TEA;
            else if (strcmp(optarg, "rsa") == 0)
                algo = ALGO_RSA;
            else
            {
                fprintf(stderr, "Error: Invalid algorithm '%s'.\n", optarg);
                print_usage(argv[0]);
                return 1;
            }
            break;
        case 'k':
            key_str = optarg;
            break;
        case 'i':
            infile = optarg;
            break;
        case 'o':
            outfile = optarg;
            break;
        case 'N':
            rsa_key_name_base = optarg;
            break;
        case 'P':
            rsa_pubkey_file = optarg;
            break;
        case 'S':
            rsa_privkey_file = optarg;
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        case '?':
            print_usage(argv[0]);
            return 1;
        default:
            abort();
        }
    }

    if (mode == MODE_KEYGEN)
    {
        if (rsa_keysize < 512)
        {
            fprintf(stderr, "Error: Keysize for RSA generation (-g) must be at least 512 bits.\n");
            print_usage(argv[0]);
            return 1;
        }
        if (!rsa_key_name_base)
        {
            fprintf(stderr, "Error: Key name base (-N) required for RSA key generation.\n");
            print_usage(argv[0]);
            return 1;
        }
        if (algo != ALGO_NONE && algo != ALGO_RSA)
        {
            fprintf(stderr, "Warning: Algorithm (-a %s) specified with RSA key generation (-g) is ignored.\n", argv[optind - 1]);
        }
        algo = ALGO_RSA;
    }
    else if (mode == MODE_ENCRYPT || mode == MODE_DECRYPT)
    {
        if (algo == ALGO_NONE)
        {
            fprintf(stderr, "Error: Algorithm (-a) must be specified for encryption/decryption.\n");
            print_usage(argv[0]);
            return 1;
        }
        if (!infile || !outfile)
        {
            fprintf(stderr, "Error: Input (-i) and output (-o) files must be specified.\n");
            print_usage(argv[0]);
            return 1;
        }
        if (algo == ALGO_RSA)
        {
            if (mode == MODE_ENCRYPT && !rsa_pubkey_file)
            {
                fprintf(stderr, "Error: RSA public key file (-P) required for encryption.\n");
                print_usage(argv[0]);
                return 1;
            }
            if (mode == MODE_DECRYPT && !rsa_privkey_file)
            {
                fprintf(stderr, "Error: RSA private key file (-S) required for decryption.\n");
                print_usage(argv[0]);
                return 1;
            }
        }
        else
        {
            if (!key_str)
            {
                fprintf(stderr, "Error: Key string (-k) required for %s.\n", (algo == ALGO_BLOWFISH ? "Blowfish" : "TEA"));
                print_usage(argv[0]);
                return 1;
            }
        }
    }
    else
    {
        fprintf(stderr, "Error: Operation mode (-e, -d, or -g) must be specified.\n");
        print_usage(argv[0]);
        return 1;
    }

    if (optind < argc)
    {
        fprintf(stderr, "Error: Unexpected arguments found: ");
        while (optind < argc)
            fprintf(stderr, "%s ", argv[optind++]);
        fprintf(stderr, "\n");
        print_usage(argv[0]);
        return 1;
    }

    int operation_result = -1;
    if (mode == MODE_KEYGEN)
    {
        operation_result = handle_rsa_key_generation(rsa_key_name_base, rsa_keysize);
    }
    else
    {
        operation_result = process_file(mode, algo, key_str, rsa_pubkey_file, rsa_privkey_file, infile, outfile);
    }

    if (operation_result != 0)
    {
        fprintf(stderr, "Operation failed.\n");
        return 1;
    }

    printf("Operation completed successfully.\n");
    return 0;
}
