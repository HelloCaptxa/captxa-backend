#ifndef RATE_LIMITING_H
#define RATE_LIMITING_H

#include <stdint.h>
#include <stdbool.h>


#define CMS_DEPTH       4
#define CMS_WIDTH       4096
#define CMS_LIMIT       20
#define CMS_LIMIT_COMPLEX 400

#define CMS_RESET_SEC   600

#ifdef __cplusplus
extern "C" {
#endif


uint32_t cms_increment_and_get(const char *key);


inline bool rate_limit_allow(const char *key) {
    return cms_increment_and_get(key) <= CMS_LIMIT;
}


void cms_reset(void);

#ifdef __cplusplus
}
#endif

#endif /* RATE_LIMITING_H */
