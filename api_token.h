#ifndef API_TOKEN_H
#define API_TOKEN_H

#include <stdint.h>

#define MY_API_TOKEN "00000000000000000000"

#define API_TOKEN_LEN 20


/*
 * Returns 1 if the token is structurally valid and its checksum matches.
 * Returns 0 otherwise.
 * `token` must be a NUL-terminated string of exactly 20 base-62 characters.
 */
int api_token_verify(const char *token);

#endif /* API_TOKEN_H */
