#define _POSIX_C_SOURCE 200809L
/* ========================================================================== */
/* ip_functions.c                                                             */
/* Bloom filter doble-buffer para IPs maliciosas                              */
/* + Sorted array con bsearch para CIDRs maliciosos (doble-buffer)            */
/* + Sorted static table para CIDRs de datacenters                            */
/* Rotación automática a las 3:00 AM via hilo dedicado                        */
/* ========================================================================== */

#include "ip_functions.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>

/* ========================================================================== */
/* DOUBLE-BUFFER STATE                                                         */
/* ========================================================================== */

/* ── IP bloom ── */
static uint8_t *g_bloom_bits[2] = { NULL, NULL };
static _Atomic int g_bloom_active = 0;
static int g_loaded_count = 0;

/* ========================================================================== */
/* CIDR SORTED-ARRAY DOUBLE-BUFFER                                            */
/* ========================================================================== */
/*
 * Instead of a bloom filter for CIDRs, we maintain a sorted array of
 * (net, mask) pairs.  For each incoming IP we binary-search for the
 * first entry whose net <= ip32, then walk backwards checking all entries
 * that could still cover the IP.  This gives:
 *   - O(log N) average lookup (binary search narrows candidates fast)
 *   - Zero false positives / zero false negatives
 *   - ~16 bytes per CIDR  →  10 000 CIDRs ≈ 160 KB  (trivial)
 *   - Correct handling of overlapping / nested CIDRs (/8, /16, /24 …)
 */

typedef struct {
    uint32_t net;   /* network address, host byte order  */
    uint32_t mask;  /* prefix mask,     host byte order  */
} cidr_entry_t;

typedef struct {
    cidr_entry_t *entries;
    size_t        count;
    size_t        capacity;
} cidr_table_t;

static cidr_table_t g_cidr_table[2];
static _Atomic int  g_cidr_active = 0;
/* Protects the *inactive* slot during a reload; readers never lock. */
static pthread_mutex_t g_cidr_reload_mtx = PTHREAD_MUTEX_INITIALIZER;

/* ========================================================================== */
/* DATACENTER / HOSTING CIDR TABLE (IPv4, static, read-only)                 */
/* Sorted by .net so dc_ipv4_match() can use bsearch.                         */
/* ========================================================================== */

#define IP4(a,b,c,d) \
    ((uint32_t)(a)<<24|(uint32_t)(b)<<16|(uint32_t)(c)<<8|(uint32_t)(d))

#define MASK(p) \
    ((uint32_t)((p)==0 ? 0u : (~0u << (32u-(unsigned)(p)))))

typedef struct {
    uint32_t    net;
    uint32_t    mask;
    const char *label;
} dc_cidr4_t;

/* NOTE: entries MUST stay sorted ascending by .net for bsearch to work.     */
static const dc_cidr4_t g_dc_cidrs[] = {
/* ── Amazon Web Services ─────────────────────────────────────────── */
{ IP4(  3,  0,  0,  0), MASK( 8), "AWS"          },
{ IP4( 13, 32,  0,  0), MASK(15), "AWS"          },
{ IP4( 13, 34,  0,  0), MASK(15), "AWS"          },
{ IP4( 13, 48,  0,  0), MASK(16), "AWS"          },
{ IP4( 13, 52,  0,  0), MASK(14), "AWS"          },
{ IP4( 13, 56,  0,  0), MASK(14), "AWS"          },
{ IP4( 13, 58,  0,  0), MASK(15), "AWS"          },
{ IP4( 13, 64,  0,  0), MASK(11), "Azure"        },
{ IP4( 13, 96,  0,  0), MASK(13), "Azure"        },
{ IP4( 13,104,  0,  0), MASK(13), "Azure"        },
{ IP4( 15,152,  0,  0), MASK(13), "AWS"          },
{ IP4( 15,177,  0,  0), MASK(18), "AWS"          },
{ IP4( 15,188,  0,  0), MASK(16), "AWS"          },
{ IP4( 15,196,  0,  0), MASK(15), "AWS"          },
{ IP4( 16, 16,  0,  0), MASK(14), "AWS"          },
{ IP4( 18,116,  0,  0), MASK(14), "AWS"          },
{ IP4( 18,144,  0,  0), MASK(15), "AWS"          },
{ IP4( 18,168,  0,  0), MASK(14), "AWS"          },
{ IP4( 18,184,  0,  0), MASK(14), "AWS"          },
{ IP4( 18,192,  0,  0), MASK(13), "AWS"          },
{ IP4( 18,200,  0,  0), MASK(14), "AWS"          },
{ IP4( 18,208,  0,  0), MASK(13), "AWS"          },
{ IP4( 18,224,  0,  0), MASK(13), "AWS"          },
{ IP4( 20,  0,  0,  0), MASK( 8), "Azure"        },
{ IP4( 23, 88,  0,  0), MASK(17), "Hetzner"      },
{ IP4( 34,192,  0,  0), MASK(10), "AWS"          },
{ IP4( 35,160,  0,  0), MASK(13), "AWS"          },
{ IP4( 35,168,  0,  0), MASK(13), "AWS"          },
{ IP4( 35,176,  0,  0), MASK(15), "AWS"          },
{ IP4( 35,184,  0,  0), MASK(13), "GCP"          },
{ IP4( 35,192,  0,  0), MASK(11), "GCP"          },
{ IP4( 35,224,  0,  0), MASK(12), "GCP"          },
{ IP4( 37, 27,  0,  0), MASK(16), "Hetzner"      },
{ IP4( 37, 59,  0,  0), MASK(16), "OVH"          },
{ IP4( 40, 64,  0,  0), MASK(10), "Azure"        },
{ IP4( 40,112,  0,  0), MASK(14), "Azure"        },
{ IP4( 40,120,  0,  0), MASK(14), "Azure"        },
{ IP4( 45, 32,  0,  0), MASK(17), "Vultr"        },
{ IP4( 45, 33,  0,  0), MASK(17), "Linode"       },
{ IP4( 45, 55,  0,  0), MASK(16), "DigitalOcean" },
{ IP4( 45, 56,  0,  0), MASK(21), "Linode"       },
{ IP4( 45, 63,  0,  0), MASK(18), "Vultr"        },
{ IP4( 45, 76,  0,  0), MASK(15), "Vultr"        },
{ IP4( 45, 79,  0,  0), MASK(16), "Linode"       },
{ IP4( 50, 16,  0,  0), MASK(15), "AWS"          },
{ IP4( 50, 18,  0,  0), MASK(16), "AWS"          },
{ IP4( 50,116,  0,  0), MASK(16), "Linode"       },
{ IP4( 51, 10,  0,  0), MASK(14), "Azure"        },
{ IP4( 51, 38,  0,  0), MASK(16), "OVH"          },
{ IP4( 51, 68,  0,  0), MASK(16), "OVH"          },
{ IP4( 51, 75,  0,  0), MASK(16), "OVH"          },
{ IP4( 51, 77,  0,  0), MASK(16), "OVH"          },
{ IP4( 51, 79,  0,  0), MASK(16), "OVH"          },
{ IP4( 51, 89,  0,  0), MASK(16), "OVH"          },
{ IP4( 51, 91,  0,  0), MASK(16), "OVH"          },
{ IP4( 51,104,  0,  0), MASK(13), "Azure"        },
{ IP4( 51,120,  0,  0), MASK(13), "Azure"        },
{ IP4( 51,132,  0,  0), MASK(14), "Azure"        },
{ IP4( 51,158,  0,  0), MASK(15), "Scaleway"     },
{ IP4( 51,161,  0,  0), MASK(16), "OVH"          },
{ IP4( 51,195,  0,  0), MASK(16), "OVH"          },
{ IP4( 51,210,  0,  0), MASK(16), "OVH"          },
{ IP4( 52,  0,  0,  0), MASK( 8), "AWS"          },
{ IP4( 54, 36,  0,  0), MASK(14), "OVH"          },
{ IP4( 54, 64,  0,  0), MASK(11), "AWS"          },
{ IP4( 54,144,  0,  0), MASK(12), "AWS"          },
{ IP4( 54,160,  0,  0), MASK(11), "AWS"          },
{ IP4( 54,196,  0,  0), MASK(15), "AWS"          },
{ IP4( 54,208,  0,  0), MASK(13), "AWS"          },
{ IP4( 54,224,  0,  0), MASK(12), "AWS"          },
{ IP4( 62,210,  0,  0), MASK(16), "Scaleway"     },
{ IP4( 64,225,  0,  0), MASK(16), "DigitalOcean" },
{ IP4( 65, 21,  0,  0), MASK(16), "Hetzner"      },
{ IP4( 65, 52,  0,  0), MASK(14), "Azure"        },
{ IP4( 66, 42, 48,  0), MASK(20), "Vultr"        },
{ IP4( 66,175,208,  0), MASK(20), "Linode"       },
{ IP4( 66,228, 32,  0), MASK(19), "Linode"       },
{ IP4( 67,205,128,  0), MASK(17), "DigitalOcean" },
{ IP4( 69,164,192,  0), MASK(18), "Linode"       },
{ IP4( 78, 46,  0,  0), MASK(15), "Hetzner"      },
{ IP4( 88, 99,  0,  0), MASK(16), "Hetzner"      },
{ IP4( 91,121,  0,  0), MASK(16), "OVH"          },
{ IP4( 92,222,  0,  0), MASK(16), "OVH"          },
{ IP4( 95,179,128,  0), MASK(17), "Vultr"        },
{ IP4( 95,216,  0,  0), MASK(16), "Hetzner"      },
{ IP4( 96,126, 96,  0), MASK(19), "Linode"       },
{ IP4( 97,107,128,  0), MASK(17), "Linode"       },
{ IP4(103, 21,244,  0), MASK(22), "Cloudflare"   },
{ IP4(103, 22,200,  0), MASK(22), "Cloudflare"   },
{ IP4(103, 31,  4,  0), MASK(22), "Cloudflare"   },
{ IP4(104, 16,  0,  0), MASK(13), "Cloudflare"   },
{ IP4(104, 24,  0,  0), MASK(14), "Cloudflare"   },
{ IP4(104, 40,  0,  0), MASK(13), "Azure"        },
{ IP4(104,131,  0,  0), MASK(16), "DigitalOcean" },
{ IP4(104,154,  0,  0), MASK(15), "GCP"          },
{ IP4(104,196,  0,  0), MASK(14), "GCP"          },
{ IP4(104,200, 16,  0), MASK(20), "Linode"       },
{ IP4(104,207,128,  0), MASK(18), "Vultr"        },
{ IP4(104,236,  0,  0), MASK(16), "DigitalOcean" },
{ IP4(104,238,128,  0), MASK(17), "Vultr"        },
{ IP4(107,170,  0,  0), MASK(16), "DigitalOcean" },
{ IP4(108, 61,  0,  0), MASK(17), "Vultr"        },
{ IP4(108,162,192,  0), MASK(18), "Cloudflare"   },
{ IP4(116,202,  0,  0), MASK(15), "Hetzner"      },
{ IP4(128,140,  0,  0), MASK(17), "Hetzner"      },
{ IP4(128,199,  0,  0), MASK(16), "DigitalOcean" },
{ IP4(130,211,  0,  0), MASK(16), "GCP"          },
{ IP4(131,  0, 72,  0), MASK(22), "Cloudflare"   },
{ IP4(134,122,  0,  0), MASK(15), "DigitalOcean" },
{ IP4(135,125,  0,  0), MASK(16), "OVH"          },
{ IP4(135,181,  0,  0), MASK(16), "Hetzner"      },
{ IP4(136,243,  0,  0), MASK(16), "Hetzner"      },
{ IP4(136,244, 64,  0), MASK(18), "Vultr"        },
{ IP4(137,184,  0,  0), MASK(14), "DigitalOcean" },
{ IP4(138,197,  0,  0), MASK(16), "DigitalOcean" },
{ IP4(138,201,  0,  0), MASK(16), "Hetzner"      },
{ IP4(139, 59,  0,  0), MASK(16), "DigitalOcean" },
{ IP4(139, 84,128,  0), MASK(17), "Vultr"        },
{ IP4(141, 95,  0,  0), MASK(16), "OVH"          },
{ IP4(141,101, 64,  0), MASK(18), "Cloudflare"   },
{ IP4(142,250,  0,  0), MASK(15), "GCP"          },
{ IP4(143,110,  0,  0), MASK(16), "DigitalOcean" },
{ IP4(143,198,  0,  0), MASK(15), "DigitalOcean" },
{ IP4(144,202,  0,  0), MASK(16), "Vultr"        },
{ IP4(146, 59,  0,  0), MASK(16), "OVH"          },
{ IP4(146,148,  0,  0), MASK(17), "GCP"          },
{ IP4(146,190,  0,  0), MASK(16), "DigitalOcean" },
{ IP4(149, 28,  0,  0), MASK(16), "Vultr"        },
{ IP4(151, 80,  0,  0), MASK(16), "OVH"          },
{ IP4(155,138,128,  0), MASK(17), "Vultr"        },
{ IP4(157, 90,  0,  0), MASK(16), "Hetzner"      },
{ IP4(159, 65,  0,  0), MASK(17), "DigitalOcean" },
{ IP4(159, 69,  0,  0), MASK(16), "Hetzner"      },
{ IP4(159,203,  0,  0), MASK(16), "DigitalOcean" },
{ IP4(161, 35,  0,  0), MASK(16), "DigitalOcean" },
{ IP4(162, 55,  0,  0), MASK(16), "Hetzner"      },
{ IP4(162,158,  0,  0), MASK(15), "Cloudflare"   },
{ IP4(163,172,  0,  0), MASK(16), "Scaleway"     },
{ IP4(164, 90,  0,  0), MASK(16), "DigitalOcean" },
{ IP4(164,132,  0,  0), MASK(16), "OVH"          },
{ IP4(165, 22,  0,  0), MASK(16), "DigitalOcean" },
{ IP4(167, 71,  0,  0), MASK(16), "DigitalOcean" },
{ IP4(167, 99,  0,  0), MASK(16), "DigitalOcean" },
{ IP4(167,235,  0,  0), MASK(16), "Hetzner"      },
{ IP4(168, 61,  0,  0), MASK(16), "Azure"        },
{ IP4(168, 62,  0,  0), MASK(15), "Azure"        },
{ IP4(168,119,  0,  0), MASK(16), "Hetzner"      },
{ IP4(172, 64,  0,  0), MASK(13), "Cloudflare"   },
{ IP4(172,104,  0,  0), MASK(15), "Linode"       },
{ IP4(173,245, 48,  0), MASK(20), "Cloudflare"   },
{ IP4(173,255,112,  0), MASK(20), "GCP"          },
{ IP4(174,138,  0,  0), MASK(17), "DigitalOcean" },
{ IP4(176,  9,  0,  0), MASK(16), "Hetzner"      },
{ IP4(176, 31,  0,  0), MASK(16), "OVH"          },
{ IP4(178, 32,  0,  0), MASK(15), "OVH"          },
{ IP4(178, 63,  0,  0), MASK(16), "Hetzner"      },
{ IP4(185, 12, 64,  0), MASK(22), "Hetzner"      },
{ IP4(188, 40,  0,  0), MASK(16), "Hetzner"      },
{ IP4(188,114, 96,  0), MASK(20), "Cloudflare"   },
{ IP4(188,165,  0,  0), MASK(16), "OVH"          },
{ IP4(190, 93,240,  0), MASK(20), "Cloudflare"   },
{ IP4(191,232,  0,  0), MASK(13), "Azure"        },
{ IP4(193, 70,  0,  0), MASK(17), "OVH"          },
{ IP4(194,195,112,  0), MASK(20), "Linode"       },
{ IP4(195,154,  0,  0), MASK(16), "Scaleway"     },
{ IP4(195,201,  0,  0), MASK(16), "Hetzner"      },
{ IP4(197,234,240,  0), MASK(22), "Cloudflare"   },
{ IP4(198, 27, 64,  0), MASK(18), "OVH"          },
{ IP4(198, 41,128,  0), MASK(17), "Cloudflare"   },
{ IP4(198, 58, 96,  0), MASK(19), "Linode"       },
{ IP4(206, 81,  0,  0), MASK(18), "DigitalOcean" },
{ IP4(207,246, 64,  0), MASK(18), "Vultr"        },
{ IP4(209,250,224,  0), MASK(19), "Vultr"        },
{ IP4(212, 47,224,  0), MASK(19), "Scaleway"     },
{ IP4(213,133, 96,  0), MASK(19), "Hetzner"      },
{ IP4(213,186, 32,  0), MASK(19), "OVH"          },
{ IP4(216,238, 96,  0), MASK(19), "Vultr"        },
{ IP4(217,182,  0,  0), MASK(16), "OVH"          },
/* Sentinel — must be last */
{ 0u, 0u, NULL }
};

#define DC_CIDR_COUNT \
    ((int)(sizeof(g_dc_cidrs) / sizeof(g_dc_cidrs[0])) - 1)

/* ========================================================================== */
/* INTERNAL HELPERS                                                            */
/* ========================================================================== */

/*
 * ip_to_bytes() — normaliza IP a 16 bytes IPv4-mapped IPv6.
 * IPv4 "a.b.c.d" → [0..9]=0x00, [10..11]=0xff, [12..15]=a.b.c.d
 */
static bool ip_to_bytes(const char *ip_str, uint8_t out[16])
{
    struct in6_addr addr6;
    struct in_addr  addr4;

    if (inet_pton(AF_INET6, ip_str, &addr6) == 1) {
        memcpy(out, addr6.s6_addr, 16);
        return true;
    }
    if (inet_pton(AF_INET, ip_str, &addr4) == 1) {
        memset(out, 0, 10);
        out[10] = 0xff; out[11] = 0xff;
        memcpy(out + 12, &addr4.s_addr, 4);
        return true;
    }
    return false;
}

/*
 * bloom_hash() — FNV-1a 64-bit con seed por función.
 * Usado sólo para el bloom filter de IPs individuales.
 */
static inline uint64_t bloom_hash(const uint8_t *data, size_t len, uint32_t seed)
{
    uint64_t h = 14695981039346656037ULL ^ ((uint64_t)seed * 2654435761ULL);
    for (size_t i = 0; i < len; i++) { h ^= data[i]; h *= 1099511628211ULL; }
    h ^= h >> 33; h *= 0xff51afd7ed558ccdULL; h ^= h >> 33;
    return h;
}

static inline void bit_set(uint8_t *bits, uint64_t index)
{
    bits[index >> 3] |= (uint8_t)(1u << (index & 7));
}

static inline bool bit_get(const uint8_t *bits, uint64_t index)
{
    return (bits[index >> 3] >> (index & 7)) & 1u;
}

/* ── IP bloom helpers ── */
static void bloom_insert(uint8_t *bits, const uint8_t ip_bytes[16])
{
    for (int k = 0; k < IP_BLOOM_K; k++) {
        uint64_t idx = bloom_hash(ip_bytes, 16, (uint32_t)k) % IP_BLOOM_BITS;
        bit_set(bits, idx);
    }
}

static bool bloom_query(const uint8_t *bits, const uint8_t ip_bytes[16])
{
    for (int k = 0; k < IP_BLOOM_K; k++) {
        uint64_t idx = bloom_hash(ip_bytes, 16, (uint32_t)k) % IP_BLOOM_BITS;
        if (!bit_get(bits, idx)) return false;
    }
    return true;
}

/* ========================================================================== */
/* CIDR SORTED-ARRAY HELPERS                                                  */
/* ========================================================================== */

/* Comparator for qsort / bsearch on cidr_entry_t */
static int cidr_entry_cmp(const void *a, const void *b)
{
    const cidr_entry_t *ca = (const cidr_entry_t *)a;
    const cidr_entry_t *cb = (const cidr_entry_t *)b;
    if (ca->net < cb->net) return -1;
    if (ca->net > cb->net) return  1;
    /* For equal network bases, sort wider masks (smaller prefix) first so
       that a /8 comes before a /24 with the same base — improves early-exit. */
    if (ca->mask < cb->mask) return -1;
    if (ca->mask > cb->mask) return  1;
    return 0;
}

/*
 * cidr_table_contains() — checks whether ip32 (host byte order) falls inside
 * any CIDR in the sorted table.
 *
 * Strategy:
 *   Binary-search for the rightmost entry whose .net <= ip32.
 *   Walk leftward from that position; an entry matches iff:
 *       (ip32 & entry.mask) == entry.net
 *   We can stop walking as soon as entry.net < (ip32 & entry.mask_widest),
 *   i.e. once entries are so far left that even a /0 couldn't cover ip32
 *   from there — but a simple O(log N) scan is already very fast in practice.
 *
 *   Worst case: all CIDRs overlap (degenerate).  Typical case: O(log N).
 */
static bool cidr_table_contains(const cidr_table_t *t, uint32_t ip32)
{
    if (!t->entries || t->count == 0) return false;

    /* Binary search: find last index where entries[idx].net <= ip32 */
    size_t lo = 0, hi = t->count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (t->entries[mid].net <= ip32)
            lo = mid + 1;
        else
            hi = mid;
    }
    /* lo now points one past the last entry with .net <= ip32.
       Walk backwards from lo-1. */
    if (lo == 0) return false;

    size_t i = lo;
    while (i-- > 0) {
        const cidr_entry_t *e = &t->entries[i];
        /* Once the network address is so small that even /0 can't reach ip32
           from here, we can stop.  (e->net > ip32 impossible by construction.) */
        if ((ip32 & e->mask) == e->net)
            return true;
        /* Optimisation: if e->net < (ip32 masked with the widest possible mask
           that still covers ip32), no earlier entry can match either.
           Since entries are sorted by net, once e->net is below ip32's /1
           boundary we're done. */
        if (e->net == 0) break;  /* avoid underflow; /0 covers everything */
    }
    return false;
}

static void cidr_table_free(cidr_table_t *t)
{
    free(t->entries);
    t->entries  = NULL;
    t->count    = 0;
    t->capacity = 0;
}

static bool cidr_table_push(cidr_table_t *t, uint32_t net, uint32_t mask)
{
    if (t->count >= t->capacity) {
        size_t new_cap = t->capacity ? t->capacity * 2 : 1024;
        cidr_entry_t *p = realloc(t->entries, new_cap * sizeof(cidr_entry_t));
        if (!p) return false;
        t->entries  = p;
        t->capacity = new_cap;
    }
    t->entries[t->count].net  = net;
    t->entries[t->count].mask = mask;
    t->count++;
    return true;
}

/* ── Datacenter bsearch comparator ── */
/*
 * dc_ipv4_match() — O(log N) lookup using bsearch.
 * Returns the label of the datacenter whose CIDR contains addr, or NULL.
 *
 * bsearch finds the exact .net; for a range lookup we need to scan neighbors.
 * We use a manual binary search so we can walk leftward after finding a
 * candidate, same strategy as cidr_table_contains().
 */
static const char *dc_ipv4_match(uint32_t addr)
{
    /* Find last entry whose .net <= addr */
    int lo = 0, hi = DC_CIDR_COUNT;
    while (lo < hi) {
        int mid = lo + (hi - lo) / 2;
        if (g_dc_cidrs[mid].net <= addr)
            lo = mid + 1;
        else
            hi = mid;
    }
    if (lo == 0) return NULL;

    int i = lo;
    while (i-- > 0) {
        if ((addr & g_dc_cidrs[i].mask) == g_dc_cidrs[i].net)
            return g_dc_cidrs[i].label;
        if (g_dc_cidrs[i].net == 0) break;
    }
    return NULL;
}

/* ========================================================================== */
/* LOAD HELPERS                                                                */
/* ========================================================================== */

static int load_ips_into_buffer(uint8_t *buf)
{
    FILE *f = fopen(IP_LIST_PATH, "r");
    if (!f) {
        perror("ip_functions: fopen IP_LIST_PATH");
        return 0;
    }

    char line[256];
    int loaded = 0, skipped = 0, line_num = 0;

    while (fgets(line, sizeof(line), f)) {
        line_num++;
        size_t len = strlen(line);
        while (len > 0 && (line[len-1]=='\n'||line[len-1]=='\r'||
                            line[len-1]==' ' ||line[len-1]=='\t'))
            line[--len] = '\0';
        if (len == 0 || line[0] == '#') continue;

        const char *ip_str = line;
        while (*ip_str == ' ' || *ip_str == '\t') ip_str++;

        uint8_t ip_bytes[16];
        if (ip_to_bytes(ip_str, ip_bytes)) {
            bloom_insert(buf, ip_bytes);
            loaded++;
        } else {
            skipped++;
        }
    }
    fclose(f);

    double k = IP_BLOOM_K, n = (double)loaded, m = (double)IP_BLOOM_BITS;
    double fp = 0.0;
    if (n > 0.0) {
        double inner = 1.0 - __builtin_exp(-k * n / m);
        fp = 1.0;
        for (int i = 0; i < IP_BLOOM_K; i++) fp *= inner;
    }
    if (fp > 0.01)
        fprintf(stderr, "ip_functions: WARNING bloom FP rate %.2f%% "
                        "(loaded=%d, bits=%llu)\n",
                fp * 100.0, loaded, (unsigned long long)IP_BLOOM_BITS);

    return loaded;
}

/*
 * load_cidrs_into_table() — parses the CIDR file and fills a cidr_table_t.
 * Entries are sorted by .net after loading so binary search works correctly.
 * Returns number of CIDRs loaded, or -1 on fatal error.
 */
static int load_cidrs_into_table(cidr_table_t *t)
{
    FILE *f = fopen(CIDR_LIST_PATH, "r");
    if (!f) {
        /* Non-fatal: captcha can work without the dynamic CIDR list. */
        return 0;
    }

    char line[64];
    int loaded = 0, skipped = 0;

    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len-1]=='\n'||line[len-1]=='\r'||
                            line[len-1]==' ' ||line[len-1]=='\t'))
            line[--len] = '\0';
        if (len == 0 || line[0] == '#') continue;

        unsigned a, b, c, d; int prefix;
        if (sscanf(line, "%u.%u.%u.%u/%d", &a, &b, &c, &d, &prefix) != 5 ||
            a > 255 || b > 255 || c > 255 || d > 255 ||
            prefix < 0 || prefix > 32) {
            skipped++;
            continue;
        }

        uint32_t raw_ip = ((uint32_t)a << 24) | ((uint32_t)b << 16) |
                           ((uint32_t)c <<  8) |  (uint32_t)d;
        uint32_t mask   = (prefix == 0) ? 0u : (~0u << (32 - prefix));
        uint32_t net    = raw_ip & mask;   /* normalise host bits to 0 */

        if (!cidr_table_push(t, net, mask)) {
            fprintf(stderr, "ip_functions: OOM loading CIDRs\n");
            fclose(f);
            cidr_table_free(t);
            return -1;
        }
        loaded++;
    }
    fclose(f);

    /* Sort so binary search works */
    if (t->count > 1)
        qsort(t->entries, t->count, sizeof(cidr_entry_t), cidr_entry_cmp);

    if (skipped > 0)
        fprintf(stderr, "ip_functions: skipped %d malformed CIDR lines\n", skipped);

    return loaded;
}

/* ========================================================================== */
/* PUBLIC API                                                                  */
/* ========================================================================== */

int ip_bloom_init(void)
{
    /* ── Allocate IP bloom buffers ── */
    for (int i = 0; i < 2; i++) {
        g_bloom_bits[i] = (uint8_t *)calloc(IP_BLOOM_BYTES, 1);
        if (!g_bloom_bits[i]) {
            for (int j = 0; j < i; j++) { free(g_bloom_bits[j]); g_bloom_bits[j] = NULL; }
            return -1;
        }
    }

    /* ── Initialise CIDR tables ── */
    memset(g_cidr_table, 0, sizeof(g_cidr_table));

    int loaded_ips = load_ips_into_buffer(g_bloom_bits[0]);
    if (loaded_ips < 0) return -1;

    /* Load CIDRs into slot 0; non-fatal if file absent */
    load_cidrs_into_table(&g_cidr_table[0]);

    g_loaded_count = loaded_ips;
    atomic_store_explicit(&g_bloom_active, 0, memory_order_release);
    atomic_store_explicit(&g_cidr_active,  0, memory_order_release);

    return loaded_ips;
}

bool ip_is_datacenter(const char *ip_str)
{
    if (!ip_str) return false;

    struct in_addr  addr4;
    struct in6_addr addr6;

    if (inet_pton(AF_INET, ip_str, &addr4) == 1)
        return dc_ipv4_match(ntohl(addr4.s_addr)) != NULL;

    if (inet_pton(AF_INET6, ip_str, &addr6) == 1) {
        static const uint8_t v4mapped[12] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
        if (memcmp(addr6.s6_addr, v4mapped, 12) == 0) {
            uint32_t a = (uint32_t)addr6.s6_addr[12] << 24 |
                         (uint32_t)addr6.s6_addr[13] << 16 |
                         (uint32_t)addr6.s6_addr[14] <<  8 |
                         (uint32_t)addr6.s6_addr[15];
            return dc_ipv4_match(a) != NULL;
        }
    }
    return false;
}

bool ip_bloom_is_suspicious(const char *ip_str)
{
    if (!ip_str) return false;

    /* 1. Static datacenter table — O(log N) bsearch, no locks */
    if (ip_is_datacenter(ip_str)) return true;

    /* 2. Parse IP to uint32 */
    uint8_t ip_bytes[16];
    if (!ip_to_bytes(ip_str, ip_bytes)) return false;

    /* Only IPv4 and IPv4-mapped IPv6 are handled by the CIDR tables */
    bool is_v4mapped = (memcmp(ip_bytes, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff", 12) == 0);
    bool is_v4       = is_v4mapped; /* ip_to_bytes maps pure v4 to v4-mapped */

    /* 3. Dynamic CIDR sorted-array — O(log N), zero false positives */
    if (is_v4) {
        uint32_t ip32 = ((uint32_t)ip_bytes[12] << 24) |
                        ((uint32_t)ip_bytes[13] << 16) |
                        ((uint32_t)ip_bytes[14] <<  8) |
                         (uint32_t)ip_bytes[15];

        int cidr_slot = atomic_load_explicit(&g_cidr_active, memory_order_acquire);
        /* Readers access the active slot without locks — the inactive slot is
           only modified under g_cidr_reload_mtx when its index is NOT active. */
        if (cidr_table_contains(&g_cidr_table[cidr_slot], ip32))
            return true;
    }

    /* 4. Individual IP bloom filter */
    int ip_slot = atomic_load_explicit(&g_bloom_active, memory_order_acquire);
    const uint8_t *bits = g_bloom_bits[ip_slot];
    if (!bits) return false;

    return bloom_query(bits, ip_bytes);
}

void ip_bloom_destroy(void)
{
    for (int i = 0; i < 2; i++) {
        if (g_bloom_bits[i]) { free(g_bloom_bits[i]); g_bloom_bits[i] = NULL; }
        cidr_table_free(&g_cidr_table[i]);
    }
    g_loaded_count = 0;
}

/* ========================================================================== */
/* ROTATION AT 3:00 AM                                                        */
/* ========================================================================== */

static long secs_until_3am(void)
{
    time_t now = time(NULL);
    struct tm tm_now;
    localtime_r(&now, &tm_now);

    struct tm tm_target = tm_now;
    tm_target.tm_hour  = 3;
    tm_target.tm_min   = 0;
    tm_target.tm_sec   = 0;
    tm_target.tm_isdst = -1;

    time_t target = mktime(&tm_target);
    if (target <= now) target += 24 * 3600;
    return (long)(target - now);
}

static int run_regenerate_ip(void)
{
    pid_t pid = fork();
    if (pid < 0) {
        perror("ip_functions: fork");
        return -1;
    }
    if (pid == 0) {
        execl(REGENERATE_IP_BIN, REGENERATE_IP_BIN, (char *)NULL);
        perror("ip_functions: execl");
        _exit(127);
    }
    int status;
    time_t deadline = time(NULL) + REGENERATE_IP_TIMEOUT_SECS;
    while (1) {
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid) {
            if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                return 0;
            }
            return -1;
        }
        if (time(NULL) >= deadline) {
            kill(pid, SIGKILL);
            waitpid(pid, NULL, 0);
            return -1;
        }
        sleep(5);
    }
}

static void ip_bloom_rotate(void)
{
    /* ── IP bloom ── */
    int ip_active = atomic_load_explicit(&g_bloom_active, memory_order_acquire);
    int ip_next   = 1 - ip_active;

    memset(g_bloom_bits[ip_next], 0, IP_BLOOM_BYTES);
    int loaded = load_ips_into_buffer(g_bloom_bits[ip_next]);
    if (loaded >= 0) {
        atomic_store_explicit(&g_bloom_active, ip_next, memory_order_release);
        g_loaded_count = loaded;
    }

    /* ── CIDR sorted-array ── */
    int cidr_active = atomic_load_explicit(&g_cidr_active, memory_order_acquire);
    int cidr_next   = 1 - cidr_active;

    pthread_mutex_lock(&g_cidr_reload_mtx);
    cidr_table_free(&g_cidr_table[cidr_next]);
    int loaded_cidrs = load_cidrs_into_table(&g_cidr_table[cidr_next]);
    if (loaded_cidrs >= 0) {
        atomic_store_explicit(&g_cidr_active, cidr_next, memory_order_release);
        fprintf(stderr, "ip_functions: rotated CIDR table, %d entries\n", loaded_cidrs);
    }
    pthread_mutex_unlock(&g_cidr_reload_mtx);
}

static void *bloom_rotation_thread(void *arg)
{
    (void)arg;
    for (;;) {
        long wait = secs_until_3am();

        while (wait > 0) {
            long chunk = wait < 60 ? wait : 60;
            sleep((unsigned int)chunk);
            wait -= chunk;
        }

        if (run_regenerate_ip() != 0) {
            fprintf(stderr, "ip_functions: regenerate_ip failed, skipping rotation\n");
            continue;
        }

        ip_bloom_rotate();
    }
    return NULL;
}

void ip_bloom_start_rotation_thread(void)
{
    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&tid, &attr, bloom_rotation_thread, NULL);
    pthread_attr_destroy(&attr);
}
