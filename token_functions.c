/*
 * token_functions.c – Ed25519-signed captcha token generation & validation.
 */

#include "token_functions.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdatomic.h>

/* ========================================================================== */
/* GLOBAL STATE                                                                */
/* ========================================================================== */

EVP_PKEY *g_ed25519_privkey = NULL;
EVP_PKEY *g_ed25519_pubkey  = NULL;


/* ========================================================================== */
/* BASE64URL HELPERS                                                           */
/* ========================================================================== */

static const char B64URL_CHARS[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static int8_t b64url_dec_table[256];

void init_b64url_dec(void) {
    memset(b64url_dec_table, -1, sizeof(b64url_dec_table));
    for (int i = 0; i < 64; i++)
        b64url_dec_table[(unsigned char)B64URL_CHARS[i]] = (int8_t)i;
}

void b64url_encode(char *dst, const uint8_t *src, size_t src_len) {
    size_t i = 0, j = 0;
    for (; i + 3 <= src_len; i += 3) {
        dst[j++] = B64URL_CHARS[ src[i]   >> 2];
        dst[j++] = B64URL_CHARS[((src[i]   & 0x03) << 4) | (src[i+1] >> 4)];
        dst[j++] = B64URL_CHARS[((src[i+1] & 0x0F) << 2) | (src[i+2] >> 6)];
        dst[j++] = B64URL_CHARS[  src[i+2] & 0x3F];
    }
    if (src_len - i == 1) {
        dst[j++] = B64URL_CHARS[ src[i] >> 2];
        dst[j++] = B64URL_CHARS[(src[i] & 0x03) << 4];
    } else if (src_len - i == 2) {
        dst[j++] = B64URL_CHARS[ src[i]   >> 2];
        dst[j++] = B64URL_CHARS[((src[i]   & 0x03) << 4) | (src[i+1] >> 4)];
        dst[j++] = B64URL_CHARS[ (src[i+1] & 0x0F) << 2];
    }
    dst[j] = '\0';
}

/* Returns number of decoded bytes, or -1 on invalid input. */
int b64url_decode(uint8_t *dst, const char *src, size_t src_len) {
    size_t i = 0, j = 0;
    for (; i + 4 <= src_len; i += 4) {
        int8_t a = b64url_dec_table[(unsigned char)src[i]];
        int8_t b = b64url_dec_table[(unsigned char)src[i+1]];
        int8_t c = b64url_dec_table[(unsigned char)src[i+2]];
        int8_t d = b64url_dec_table[(unsigned char)src[i+3]];
        if (a < 0 || b < 0 || c < 0 || d < 0) return -1;
        dst[j++] = (uint8_t)((a << 2) | (b >> 4));
        dst[j++] = (uint8_t)((b << 4) | (c >> 2));
        dst[j++] = (uint8_t)((c << 6) |  d);
    }
    size_t rem = src_len - i;
    if (rem == 2) {
        int8_t a = b64url_dec_table[(unsigned char)src[i]];
        int8_t b = b64url_dec_table[(unsigned char)src[i+1]];
        if (a < 0 || b < 0) return -1;
        dst[j++] = (uint8_t)((a << 2) | (b >> 4));
    } else if (rem == 3) {
        int8_t a = b64url_dec_table[(unsigned char)src[i]];
        int8_t b = b64url_dec_table[(unsigned char)src[i+1]];
        int8_t c = b64url_dec_table[(unsigned char)src[i+2]];
        if (a < 0 || b < 0 || c < 0) return -1;
        dst[j++] = (uint8_t)((a << 2) | (b >> 4));
        dst[j++] = (uint8_t)((b << 4) | (c >> 2));
    } else if (rem == 1) {
        return -1; /* 1 leftover character is always invalid in base64 */
    }
    return (int)j;
}

/* ========================================================================== */
/* token_init                                                                  */
/* ========================================================================== */

bool token_init(void) {
    init_b64url_dec();

    FILE *f = fopen(TOKEN_PRIVATE_KEY_PATH, "r");
    if (!f) {
        fprintf(stderr, "token_functions: failed to open private key %s\n",
                TOKEN_PRIVATE_KEY_PATH);
        return false;
    }

    g_ed25519_privkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);

    if (!g_ed25519_privkey) {
        fprintf(stderr, "token_functions: PEM_read_PrivateKey failed\n");
        ERR_print_errors_fp(stderr);
        return false;
    }

    if (EVP_PKEY_id(g_ed25519_privkey) != EVP_PKEY_ED25519) {
        fprintf(stderr, "token_functions: key is not Ed25519\n");
        EVP_PKEY_free(g_ed25519_privkey);
        g_ed25519_privkey = NULL;
        return false;
    }

    /*
     * Extract the raw 32-byte public key from the private key and store a
     * public-key-only EVP_PKEY for the verification path.
     * This is both safer (no privkey exposure during verify) and faster
     * (OpenSSL can use the optimised verify code path).
     */
    uint8_t raw_pub[32];
    size_t  raw_pub_len = sizeof(raw_pub);
    if (EVP_PKEY_get_raw_public_key(g_ed25519_privkey,
                                    raw_pub, &raw_pub_len) != 1) {
        fprintf(stderr, "token_functions: EVP_PKEY_get_raw_public_key failed\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(g_ed25519_privkey);
        g_ed25519_privkey = NULL;
        return false;
    }

    g_ed25519_pubkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
                                                    raw_pub, raw_pub_len);
    if (!g_ed25519_pubkey) {
        fprintf(stderr, "token_functions: EVP_PKEY_new_raw_public_key failed\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(g_ed25519_privkey);
        g_ed25519_privkey = NULL;
        return false;
    }

    fprintf(stderr, "token_functions: Ed25519 key loaded successfully\n");
    return true;
}

void token_cleanup(void) {
    if (g_ed25519_privkey) { EVP_PKEY_free(g_ed25519_privkey); g_ed25519_privkey = NULL; }
    if (g_ed25519_pubkey)  { EVP_PKEY_free(g_ed25519_pubkey);  g_ed25519_pubkey  = NULL; }
}

/* ========================================================================== */
/* sign_final_token  (OpenSSL EVP)                                            */
/* ========================================================================== */

bool sign_final_token(unsigned char *sig_out, size_t *sig_len,
                      const char *message) {
    if (!g_ed25519_privkey) {
        fprintf(stderr, "token_functions: sign_final_token: no private key\n");
        return false;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return false;

    bool ok = false;
    if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, g_ed25519_privkey) == 1) {
        *sig_len = ED25519_SIG_BYTES;
        ok = (EVP_DigestSign(ctx, sig_out, sig_len,
                             (const unsigned char *)message,
                             strlen(message)) == 1);
    }
    if (!ok) ERR_print_errors_fp(stderr);
    EVP_MD_CTX_free(ctx);
    return ok;
}

/* ========================================================================== */
/* verify_token_signature                                                     */
/* ========================================================================== */

bool verify_token_signature(const char *message,
                             const unsigned char *sig, size_t sig_len) {
    if (!g_ed25519_pubkey) {
        fprintf(stderr, "token_functions: verify_token_signature: no public key\n");
        return false;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return false;

    bool ok = false;
    if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, g_ed25519_pubkey) == 1) {
        ok = (EVP_DigestVerify(ctx, sig, sig_len,
                               (const unsigned char *)message,
                               strlen(message)) == 1);
    }
    /*
     * Do NOT print OpenSSL errors here on verify fail – it is not an error,
     * just an invalid token supplied by the client.
     */
    EVP_MD_CTX_free(ctx);
    return ok;
}

/* ========================================================================== */
/* generate_final_token                                                        */
/* ========================================================================== */

bool generate_final_token(bool is_simp, char *output_token, size_t output_size,
                          const char *ja4_str, const char *user_ip,
                          const char *ja4_o ) {

    if (!ja4_str || !user_ip || !ja4_o) {
        fprintf(stderr, "token_functions: generate_final_token: null arg\n");
        return false;
    }
    char difficulty[8];
    if(is_simp){
        strcpy(difficulty, "SIMP");
    }
    else{
        strcpy(difficulty, "COMP");
    }

    /* ---- Build plaintext: difficulty|unix_timestamp|ip|ja4|ja4o ---- */
    char timestamp[20];
    snprintf(timestamp, sizeof(timestamp), "%ld", (long)time(NULL));

    char plaintext[512];
    snprintf(plaintext, sizeof(plaintext), "%s|%s|%s|%s|%s",
             difficulty, timestamp, user_ip, ja4_str, ja4_o);

    /* ---- Sign the plaintext ---- */
    unsigned char sig_raw[ED25519_SIG_BYTES];
    size_t sig_len = ED25519_SIG_BYTES;
    if (!sign_final_token(sig_raw, &sig_len, plaintext)) {
        fprintf(stderr, "token_functions: sign_final_token failed\n");
        return false;
    }

    /* ---- Base64url-encode the raw signature ---- */
    char sig_b64[ED25519_SIG_B64_LEN + 1];
    b64url_encode(sig_b64, sig_raw, sig_len);

    /* ---- Assemble the full token ---- */
    int written = snprintf(output_token, output_size,
                           "%s||%s", plaintext, sig_b64);
    if (written < 0 || (size_t)written >= output_size) {
        fprintf(stderr, "token_functions: output token truncated\n");
        return false;
    }
    return true;
}

/* ========================================================================== */
/* validate_token                                                              */
/* ========================================================================== */

bool validate_token(char *token,
                    const char *user_ip,
                    const char *user_ja4,
                    const char *user_ja4_o) {
    if (!token || !user_ip || !user_ja4 || !user_ja4_o) {
        return false;
    }

    /* ---- Split on "||" ---- */
    char *split_point = strstr(token, TOKEN_SEP);
    if (!split_point) {
        return false;
    }
    *split_point     = '\0';           /* NUL-terminate the plaintext part     */
    const char *plaintext = token;
    const char *sig_b64   = split_point + 2; /* skip "||" */

    /* ---- Decode and verify the signature ---- */
    uint8_t sig_raw[ED25519_SIG_BYTES];
    int sig_len = b64url_decode(sig_raw, sig_b64, strlen(sig_b64));
    if (sig_len != ED25519_SIG_BYTES) {
        return false;
    }

    if (!verify_token_signature(plaintext, sig_raw, (size_t)sig_len)) {
        return false;
    }

    /* ---- Parse plaintext: difficulty|timestamp|ip|ja4|ja4o ---- */
    char token_timestamp[20];
    char difficulty[16];
    char token_user_ip[64];
    char token_ja4[64];
    char token_ja4_o[64];

    if (sscanf(plaintext, "%15[^|]|%19[^|]|%63[^|]|%63[^|]|%63s",
               difficulty, token_timestamp,
               token_user_ip, token_ja4, token_ja4_o) != 5) {
        return false;
    }

    if (strcmp(token_ja4, user_ja4_o) != 0) {
        return false;
    }

    /* ---- Check token age ---- */
    time_t received_ts     = (time_t)atoll(token_timestamp);
    double elapsed_seconds = difftime(time(NULL), received_ts);
    if (elapsed_seconds > 60.0 * MAX_MINUTES) {
        return false;
    }

    /* ---- Check IP ---- */
    if (strcmp(user_ip, token_user_ip) != 0) {
        return false;
    }

    /* ---- Check JA4 fingerprint ---- */
    if (strcmp(user_ja4, token_ja4) != 0) {
        return false;
    }

    return true;
}

/* ========================================================================== */
/* ANTI MAX-REPLAY TOKEN (Count-Min Sketch double-buffer)                      */
/* ========================================================================== */

#define TOK_DEPTH       4
#define TOK_WIDTH       4096

static atomic_uint  g_tok[2][TOK_DEPTH][TOK_WIDTH];
static atomic_int   g_tok_slot = 0;


static uint32_t tok_hash(const char *key, int seed) {
    uint32_t h = 2166136261u ^ (uint32_t)seed;
    for (; *key; key++) h = (h ^ (unsigned char)*key) * 16777619u;
    return h & (TOK_WIDTH - 1);
}

static uint32_t add_count_token(const char *key) {
    int slot = atomic_load(&g_tok_slot);
    uint32_t min = UINT32_MAX;
    for (int d = 0; d < TOK_DEPTH; d++) {
        uint32_t idx = tok_hash(key, d);
        uint32_t v = atomic_fetch_add(&g_tok[slot][d][idx], 1) + 1;
        if (v < min) min = v;
    }
    return min;
}

uint32_t validate_add_count_token(const char *key) {
    char *split_p = strstr(key, TOKEN_SEP);
    if (!split_p) {
        return UINT32_MAX;
    }
    *split_p     = '\0';           /* NUL-terminate the plaintext part     */
    const char *plaint = key;
    const char *sig64   = split_p + 2; /* skip "||" */

    /* ---- Decode and verify the signature ---- */
    uint8_t sig_raw[ED25519_SIG_BYTES];
    int sig_len = b64url_decode(sig_raw, sig64, strlen(sig64));
    if (sig_len != ED25519_SIG_BYTES) {
        return UINT32_MAX;
    }

    if (!verify_token_signature(plaint, sig_raw, (size_t)sig_len)) {
        return UINT32_MAX;
    }

    char token_time[20];
    if (sscanf(plaint, "%*[^|]|%19[^|]", token_time) != 1) {
        return UINT32_MAX;
    }

    time_t received_ts     = (time_t)atoll(token_time);
    double elapsed_seconds = difftime(time(NULL), received_ts);
    if (elapsed_seconds > 60.0 * MAX_MINUTES) {
        return UINT32_MAX;
    }

    return add_count_token(key);
}


void tok_reset(void) {
    int current = atomic_load(&g_tok_slot);
    int next    = 1 - current;

    /* Zero out the inactive slot first */
    memset((void*)g_tok[next], 0, sizeof(g_tok[next]));
    /* Then atomically flip to it */
    atomic_store(&g_tok_slot, next);
}
