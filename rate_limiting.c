/* ========================================================================== */
/* rate_limiting.c — Count-Min Sketch rate limiter (double-buffer)             */
/* ========================================================================== */

#include "rate_limiting.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdatomic.h>

/* Two sketches — double-buffer to avoid resetting while reads happen */
static atomic_uint  g_cms[2][CMS_DEPTH][CMS_WIDTH];
static atomic_int   g_cms_slot = 0;   /* which slot is active (0 or 1) */

static uint32_t cms_hash(const char *key, int seed) {
    uint32_t h = 2166136261u ^ (uint32_t)seed;
    for (; *key; key++) h = (h ^ (unsigned char)*key) * 16777619u;
    return h & (CMS_WIDTH - 1);
}

/* Returns new count for this key. Call once per request. */
uint32_t cms_increment_and_get(const char *key) {
    int slot = atomic_load(&g_cms_slot);
    uint32_t min = UINT32_MAX;
    for (int d = 0; d < CMS_DEPTH; d++) {
        uint32_t idx = cms_hash(key, d);
        uint32_t v = atomic_fetch_add(&g_cms[slot][d][idx], 1) + 1;
        if (v < min) min = v;
    }
    return min;
}

/* Call from a background thread every CMS_RESET_SEC seconds */
void cms_reset(void) {
    int current = atomic_load(&g_cms_slot);
    int next    = 1 - current;

    /* Zero out the inactive slot first */
    memset((void*)g_cms[next], 0, sizeof(g_cms[next]));
    /* Then atomically flip to it */
    atomic_store(&g_cms_slot, next);
}
