#include "api_token.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>


int api_token_verify(const char *token){
    if (!token) return 0;

    /* Must be exactly 20  characters */
    size_t len = strnlen(token, API_TOKEN_LEN + 1);
    if (len != API_TOKEN_LEN) return 0;

    if(strcmp(MY_API_TOKEN,token) != 0){
        return 0;
    }
    return 1;
}
