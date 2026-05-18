/*
 * token_functions.h – Public API for Ed25519-signed captcha tokens.
 */

#ifndef TOKEN_FUNCTIONS_H
#define TOKEN_FUNCTIONS_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <openssl/evp.h>
#include <h2o.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================== */
/* CONFIGURATION                                                               */
/* ========================================================================== */

#ifndef TOKEN_PRIVATE_KEY_PATH
#define TOKEN_PRIVATE_KEY_PATH "certs/ed25519_private.pem"
#endif

/** Maximum token reuse count before a new captcha challenge is required. */
#define MAX_COUNT          100

/** Token lifetime in minutes. */
#define MAX_MINUTES        30

/** Separator between the plaintext and base64url-encoded signature. */
#define TOKEN_SEP          "||"

/** Ed25519 raw signature size in bytes (always 64). */
#define ED25519_SIG_BYTES  64

/**
 * Base64url-encoded length of an Ed25519 signature (no padding).
 * ceil(64 * 4 / 3) = 86 characters.
 */
#define ED25519_SIG_B64_LEN  86

/** Safe upper bound for a complete token string (plaintext + "||" + sig_b64). */
#define TOKEN_MAX_LEN      512

#define TOK_RESET_SEC   3600


extern EVP_PKEY *g_ed25519_privkey;
extern EVP_PKEY *g_ed25519_pubkey;


bool token_init(void);


void token_cleanup(void);


bool generate_final_token(bool is_simp,
                          char       *output_token,
                          size_t      output_size,
                          const char *ja4_str,
                          const char *user_ip,
                          const char *ja4_o);


bool validate_token(char       *token,
                    const char *user_ip,
                    const char *user_ja4,
                    const char *user_ja4_o);


bool sign_final_token(unsigned char *sig_out,
                      size_t        *sig_len,
                      const char    *message);


bool verify_token_signature(const char    *message,
                             const unsigned char *sig,
                             size_t         sig_len);

void init_b64url_dec(void);

void b64url_encode(char *dst, const uint8_t *src, size_t src_len);


int b64url_decode(uint8_t *dst, const char *src, size_t src_len);

uint32_t validate_add_count_token(const char *key);

void tok_reset(void);

#ifdef __cplusplus
}
#endif

#endif /* TOKEN_FUNCTIONS_H */
