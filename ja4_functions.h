#ifndef JA4_FUNCTIONS_H
#define JA4_FUNCTIONS_H

#include <openssl/ssl.h>
#include <stdbool.h>

/* Initializes the OpenSSL ClientHello message callback */
void ja4_init_ssl_ctx(SSL_CTX *ctx);

/* Retrieves the computed JA4 and JA4o strings for a given TLS session */
bool get_ja4_from_ssl(SSL *ssl, char *ja4_out, char *ja4o_out);

#endif
