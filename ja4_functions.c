#include "ja4_functions.h"
#include <openssl/ssl.h>
#include <openssl/sha.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static int ja4_ex_data_idx = -1;

typedef struct {
    char ja4[128];
    char ja4o[128];
} ja4_data_t;

static inline int is_grease(uint16_t v) {
    return (v & 0x0F0F) == 0x0A0A;
}

/* Hashes an array of uint16_t into a 12-char truncated SHA256 string for JA4 */
static void do_hash(uint16_t *arr, int count, char *out12) {
    if (count == 0) {
        strcpy(out12, "000000000000");
        return;
    }
    char hex[2048] = {0};
    int p = 0;
    for (int i = 0; i < count; i++) {
        p += snprintf(hex + p, sizeof(hex) - p, "%04x%s", arr[i], (i < count - 1) ? "," : "");
    }
    unsigned char md[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)hex, strlen(hex), md);
    for (int i = 0; i < 6; i++) {
        sprintf(out12 + (i * 2), "%02x", md[i]);
    }
}

/* Callback fired by OpenSSL when raw TLS messages arrive */
static void tls_msg_cb(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg) {
    /* We only care about incoming Handshake (22) ClientHello (1) packets */
    if (write_p || content_type != 22 || len < 42) return;
    const uint8_t *p = (const uint8_t *)buf;
    if (p[0] != 1) return;

    /* If we already parsed JA4 for this connection, skip */
    if (SSL_get_ex_data(ssl, ja4_ex_data_idx) != NULL) return;

    size_t pos = 4; // Skip Handshake Type & Length
    pos += 2;       // Version
    pos += 32;      // Random

    if (pos >= len) return;
    uint8_t sid_len = p[pos++];
    pos += sid_len; // Session ID

    if (pos + 2 > len) return;
    uint16_t ciphers_len = (p[pos] << 8) | p[pos+1];
    pos += 2;

    if (pos + ciphers_len > len) return;
    const uint8_t *ciphers_ptr = p + pos;
    pos += ciphers_len;

    if (pos >= len) return;
    uint8_t comp_len = p[pos++];
    pos += comp_len; // Compression Methods

    uint16_t ext_len = 0;
    const uint8_t *ext_ptr = NULL;
    if (pos + 2 <= len) {
        ext_len = (p[pos] << 8) | p[pos+1];
        pos += 2;
        if (pos + ext_len <= len) ext_ptr = p + pos;
    }

    int is_tls13 = 0, has_sni = 0;
    char alpn[3] = "00";

    uint16_t ciphers[256];
    int cipher_count = 0;
    for (int i = 0; i < ciphers_len; i += 2) {
        uint16_t c = (ciphers_ptr[i] << 8) | ciphers_ptr[i+1];
        if (!is_grease(c) && cipher_count < 256) {
            ciphers[cipher_count++] = c;
        }
    }

    uint16_t exts[256];
    int ext_count = 0;

    if (ext_ptr) {
        size_t epos = 0;
        while (epos + 4 <= ext_len) {
            uint16_t etype = (ext_ptr[epos] << 8) | ext_ptr[epos+1];
            uint16_t elen = (ext_ptr[epos+2] << 8) | ext_ptr[epos+3];
            epos += 4;

            if (epos + elen > ext_len) break;

            if (!is_grease(etype)) {
                if (ext_count < 256) exts[ext_count++] = etype;

                if (etype == 0) has_sni = 1;
                else if (etype == 16 && elen > 3) { // ALPN
                    uint8_t list_len = (ext_ptr[epos] << 8) | ext_ptr[epos+1];
                    if (list_len > 0 && epos + 2 + list_len <= epos + elen) {
                        uint8_t falpn_len = ext_ptr[epos+2];
                        if (falpn_len > 0 && epos + 3 + falpn_len <= epos + elen) {
                            alpn[0] = ext_ptr[epos+3];                     // First char
                            alpn[1] = ext_ptr[epos+3+falpn_len-1];         // Last char
                        }
                    }
                }
                else if (etype == 43) is_tls13 = 1; // supported_versions (indicates TLS 1.3)
            }
            epos += elen;
        }
    }

    // Create sorted variants for JA4 (JA4 sorts; JA4o uses original order)
    uint16_t sorted_ciphers[256], sorted_exts[256];
    memcpy(sorted_ciphers, ciphers, cipher_count * sizeof(uint16_t));
    memcpy(sorted_exts, exts, ext_count * sizeof(uint16_t));

    for (int i=0; i<cipher_count-1; i++) {
        for (int j=i+1; j<cipher_count; j++) {
            if (sorted_ciphers[j] < sorted_ciphers[i]) {
                uint16_t t = sorted_ciphers[i]; sorted_ciphers[i] = sorted_ciphers[j]; sorted_ciphers[j] = t;
            }
        }
    }
    for (int i=0; i<ext_count-1; i++) {
        for (int j=i+1; j<ext_count; j++) {
            if (sorted_exts[j] < sorted_exts[i]) {
                uint16_t t = sorted_exts[i]; sorted_exts[i] = sorted_exts[j]; sorted_exts[j] = t;
            }
        }
    }

    /* JA4 Part A: Protocol + Version + SNI + Ciphers Count + Ext Count + ALPN */
    char part_a[32];
    snprintf(part_a, sizeof(part_a), "t%d%c%02d%02d%s",
             is_tls13 ? 13 : 12, has_sni ? 'd' : 'i',
             cipher_count, ext_count, alpn);

    char ja4_b[13], ja4_c[13], ja4o_b[13], ja4o_c[13];
    do_hash(sorted_ciphers, cipher_count, ja4_b);
    do_hash(sorted_exts, ext_count, ja4_c);

    do_hash(ciphers, cipher_count, ja4o_b);
    do_hash(exts, ext_count, ja4o_c);

    /* Store in the SSL context memory pool so handlers can fetch it */
    ja4_data_t *ja4_obj = calloc(1, sizeof(ja4_data_t));
    if (ja4_obj) {
        snprintf(ja4_obj->ja4, sizeof(ja4_obj->ja4), "%s_%s_%s", part_a, ja4_b, ja4_c);
        snprintf(ja4_obj->ja4o, sizeof(ja4_obj->ja4o), "%s_%s_%s", part_a, ja4o_b, ja4o_c);
        SSL_set_ex_data(ssl, ja4_ex_data_idx, ja4_obj);
    }
}

static void ja4_free_cb(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp) {
    if (ptr) free(ptr);
}

void ja4_init_ssl_ctx(SSL_CTX *ctx) {
    if (ja4_ex_data_idx == -1) {
        ja4_ex_data_idx = SSL_get_ex_new_index(0, "ja4_data", NULL, NULL, ja4_free_cb);
    }
    SSL_CTX_set_msg_callback(ctx, tls_msg_cb);
}

bool get_ja4_from_ssl(SSL *ssl, char *ja4_out, char *ja4o_out) {
    if (!ssl || ja4_ex_data_idx == -1) return false;
    ja4_data_t *ja4 = SSL_get_ex_data(ssl, ja4_ex_data_idx);
    if (!ja4) return false;
    if (ja4_out) strcpy(ja4_out, ja4->ja4);
    if (ja4o_out) strcpy(ja4o_out, ja4->ja4o);
    return true;
}
