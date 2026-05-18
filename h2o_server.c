/* =============================================================================
 * h2o_server.c  —  H2O/libuv CAPTCHA server  (libuv backend, NOT evloop)
 *
 * Sections:
 *   1. Includes & compile-time constants
 *   2. Server state & worker struct  ← DEFINED BEFORE any function that uses it
 *   3. Challenge-token crypto  (server-local ChaCha20-Poly1305)
 *   4. Utility helpers  (IP, headers, hex, base64, JSON)
 *   5. HTTP endpoint handlers
 *      5a. POST /challenge/simp
 *      5b. POST /solve/simp
 *      5c. GET  /challenge/complex
 *      5d. POST /solve/complex
 *      5e. GET  /api/stats
 *   6. TCP listener (libuv)
 *   7. Worker threads & main
 * ============================================================================= */

/* --------------------------------------------------------------------------- */
/* 1. Includes & compile-time constants                                        */
/* --------------------------------------------------------------------------- */

#include "captcha_core.h"
#include "ip_functions.h"
#include "token_functions.h"
#include "rate_limiting.h"
#include "send_udp.h"
#include "ja4_functions.h"
#include "api_token.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <math.h>

#include <h2o.h>
#include <h2o/http1.h>
#include <h2o/http2.h>
#include <h2o/socket.h>
struct st_h2o_socket_ssl_t {
    SSL_CTX *ssl_ctx;
    SSL     *ossl;
    /* remaining fields intentionally omitted */
};

static inline SSL *h2o_socket_get_ssl(h2o_socket_t *sock)
{
    if (sock == NULL || sock->ssl == NULL)
        return NULL;
    return sock->ssl->ossl;
}

#include <h2o/file.h>

#include <uv.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>


#ifdef __linux__
#  include <sched.h>
#endif

/* PoW difficulty (can override at compile time) */
#ifndef POW_DIFFICULTY_SIMPLE
#define POW_DIFFICULTY_SIMPLE   18
#endif
#ifndef POW_DIFFICULTY_COMPLEX
#define POW_DIFFICULTY_COMPLEX 19
#endif


/* Challenge TTL (seconds) */
#ifndef CHALLENGE_MAX_AGE_SECS
#define CHALLENGE_MAX_AGE_SECS  180
#endif

/* Puzzle answer tolerance in pixels */
#ifndef PUZZLE_TOLERANCE
#  define PUZZLE_TOLERANCE 7
#endif

/* Max bot score before rejection */
#ifndef BOT_SCORE_MAX
#  define BOT_SCORE_MAX       0.5f
#endif
#ifndef BOT_SCORE_MAX_SIMP
#  define BOT_SCORE_MAX_SIMP  0.30f
#endif

/* Server port and worker count */
#ifndef SERVER_PORT
#  define SERVER_PORT      443
#endif
#ifndef WORKER_THREADS
#  define WORKER_THREADS   8
#endif
#ifndef WORKER_CORE_START
#  define WORKER_CORE_START 0
#endif

/* TLS certificate paths */
#ifndef TLS_CERT_FILE
#  define TLS_CERT_FILE  "/etc/letsencrypt/live/captxa.com/fullchain.pem"
#endif
#ifndef TLS_KEY_FILE
#  define TLS_KEY_FILE   "/etc/letsencrypt/live/captxa.com/privkey.pem"
#endif

static volatile sig_atomic_t reload_ssl_requested = 0;


//SSL *h2o_socket_get_ssl(h2o_socket_t *sock);

/* Challenge-token AEAD key length & nonce length */
#define CHAL_KEY_LEN    32
#define CHAL_NONCE_LEN  12
#define MAX_VAL 4294967295

const char *LOGS_SERVER_IP = "159.195.38.167";
int LOGS_SERVER_PORT = 5000;

/* JSON response string constants */
#define ERR_BOT_DETECTOR  "{\"valid\":false,\"error\":\"environment_inconsistency\"}"
#define ERR_INTEGRITY     "{\"valid\":false,\"error\":\"integrity_filters\"}"
#define ERR_BURSTINESS    "{\"valid\":false,\"error\":\"burstiness_failed\"}"
#define ERR_ENTROPY       "{\"valid\":false,\"error\":\"sample_entropy_failed\"}"
#define ERR_FEATURES      "{\"valid\":false,\"error\":\"final_features_failed\"}"
#define ERR_VELOCITY      "{\"valid\":false,\"error\":\"velocity_check_failed\"}"
#define ERR_FITTS         "{\"valid\":false,\"error\":\"fitts_law_failed\"}"
#define ERR_BOT_SCORE     "{\"valid\":false,\"error\":\"bot_score_exceeded\"}"
#define ERR_TRAJ_SHORT    "{\"valid\":false,\"error\":\"trajectory_too_short\"}"
#define ERR_TOKEN_BAD     "{\"valid\":false,\"error\":\"invalid_token\"}"
#define ERR_TOKEN_EXP     "{\"valid\":false,\"error\":\"token_expired\"}"
#define ERR_IP_MISMATCH   "{\"valid\":false,\"error\":\"ip_mismatch\"}"
#define ERR_JA4_MISMATCH  "{\"valid\":false,\"error\":\"ja4_mismatch\"}"
#define ERR_POW_FAIL      "{\"valid\":false,\"error\":\"pow_failed\"}"
#define ERR_PUZZLE_WRONG  "{\"valid\":false,\"error\":\"puzzle_wrong\"}"
#define ERR_DO_COMPLEX    "{\"valid\":false,\"error\":\"Do_complex_captcha\"}"
#define ERR_WRONG_TYPE    "{\"valid\":false,\"error\":\"wrong_token_type\"}"
#define SUCCESS_START  "{\"valid\":true,\"score\":"
#define SUCCESS_MOB_T  ",\"mobile\":true}"
#define SUCCESS_MOB_F  ",\"mobile\":false}"

/* After your #include "token_functions.h" line, add: */
#define b64url_encoded_len(n)  ((n)/3*4 + ((n)%3 ? (n)%3+1 : 0))


/* SEND403 convenience macro */
#define SEND403(req, msg) \
    send_json_response((req), 403, (msg), sizeof(msg) - 1)


#define SOLVE_FAIL(req_, err_, dom_, ip_,comp_) do {  \
    udp_report_event((dom_), (ip_), 0,(comp_));         \
    SEND403((req_), (err_));                    \
    return 0;                                   \
} while (0)

/* Responds to OPTIONS preflight and returns 0 to stop handler chain.
 * If method is not OPTIONS, does nothing (falls through). */
#define HANDLE_PREFLIGHT(req)                                                   \
    if (h2o_memis((req)->method.base, (req)->method.len, H2O_STRLIT("OPTIONS"))) { \
        (req)->res.status = 204;                                                \
        (req)->res.reason = "No Content";                                       \
        add_cors_headers(req);                                                  \
        h2o_send_inline((req), NULL, 0);                                        \
        return 0;                                                               \
}

/* --------------------------------------------------------------------------- */
/* 2. Server state & worker struct  (MUST be defined before req_worker_id)     */
/* --------------------------------------------------------------------------- */

/* Ephemeral symmetric key — generated once at startup */
static unsigned char g_challenge_key[CHAL_KEY_LEN];

static h2o_globalconf_t  config;
static volatile sig_atomic_t shutdown_requested = 0;
static SSL_CTX *g_ssl_ctx = NULL;

/* Per-thread challenge cipher contexts — lazy-init, never freed (worker lifetime) */
static __thread EVP_CIPHER_CTX *tls_chal_encrypt_ctx = NULL;
static __thread EVP_CIPHER_CTX *tls_chal_decrypt_ctx = NULL;


/* One per OS thread */
struct st_worker_t {
    pthread_t        tid;
    h2o_context_t    ctx;
    h2o_accept_ctx_t accept_ctx;
    uv_loop_t       *loop;
    int              worker_id;
};

/* --------------------------------------------------------------------------- */
/* 2b. UDP telemetry batch                                                      */
/* --------------------------------------------------------------------------- */

#define UDP_BATCH_MAX  15
#define UDP_FLUSH_MS   (5ULL * 60ULL * 1000ULL)   /* 5 minutes */

typedef struct {
    char   domain[128];
    char   ip[64];
    int    passed;         /* 1 = pass, 0 = fail */
    int comp; /*0 simple, 1 complex */
    time_t timestamp;
} udp_event_t;

static udp_event_t     g_udp_batch[UDP_BATCH_MAX];
static int             g_udp_batch_count = 0;
static pthread_mutex_t g_udp_mutex = PTHREAD_MUTEX_INITIALIZER;
/* --------------------------------------------------------------------------- */
/* 2c. Shared JA4 fingerprint extraction helper                                 */
/* --------------------------------------------------------------------------- */


static inline void force_new_tls_handshake(h2o_req_t *req);
static void extract_ja4_fingerprints(h2o_req_t *req,
                                       char ja4[128], char ja4o[128],
                                       char short_ja4[64], char short_ja4o[64])
{
    h2o_socket_t *sock = req->conn->callbacks->get_socket(req->conn);
    SSL *ssl = h2o_socket_get_ssl(sock);
    if (ssl) {
        get_ja4_from_ssl(ssl, ja4, ja4o);
    }

    char *last_underscore_ja4 = strrchr(ja4, '_');
    size_t lenja4 = last_underscore_ja4 - ja4;
    strncpy(short_ja4, ja4, lenja4);
    short_ja4[lenja4] = '\0';

    char *last_underscore_ja4o = strrchr(ja4o, '_');
    size_t lenja4o = last_underscore_ja4o - ja4o;
    strncpy(short_ja4o, ja4o, lenja4o);
    short_ja4o[lenja4o] = '\0';

    force_new_tls_handshake(req);
}


/*
 * Atomically snapshot & reset the batch, then send outside the lock.
 * Safe to call from any thread or timer: a concurrent call getting count=0
 * simply does nothing.
 */
static void flush_udp_batch(void) {
    udp_event_t snapshot[UDP_BATCH_MAX];
    int count = 0;

    pthread_mutex_lock(&g_udp_mutex);
    count = g_udp_batch_count;
    if (count > 0) {
        memcpy(snapshot, g_udp_batch, sizeof(udp_event_t) * (size_t)count);
        g_udp_batch_count = 0;
    }
    pthread_mutex_unlock(&g_udp_mutex);

    if (count == 0) return;

    /* Build one newline-delimited bulk payload — single sendto() call */
    char bulk[UDP_BATCH_MAX * 320];
    int  offset = 0;

    for (int i = 0; i < count; i++) {
        int n = snprintf(bulk + offset, sizeof(bulk) - offset,
                         "%s,%s,%d,%d,%ld\n",
                         snapshot[i].domain,
                         snapshot[i].ip,
                         snapshot[i].passed,
                         snapshot[i].comp,
                         (long)snapshot[i].timestamp);

        /* Guard: if remaining buffer is too small, flush what we have
           and start a new packet — prevents MTU fragmentation          */
        if (offset + n >= 1400) {
            bulk[offset] = '\0';
            udpSend(bulk);
            offset = 0;
            i--;    /* retry this event in the new packet */
            continue;
        }
        offset += n;
    }

    if (offset > 0) {
        bulk[offset] = '\0';
        udpSend(bulk);
    }


}

/*
 * Enqueue one solve outcome (domain, ip, pass=1/fail=0).
 * If the batch just reached UDP_BATCH_MAX, flush immediately on the
 * calling thread (no timer needed, avoids head-of-line blocking).
 */
static void udp_report_event(const char *domain, const char *ip, int passed,int comp) {
    bool do_flush = false;

    pthread_mutex_lock(&g_udp_mutex);
    if (g_udp_batch_count < UDP_BATCH_MAX) {
        udp_event_t *ev = &g_udp_batch[g_udp_batch_count++];
        strncpy(ev->domain, domain ? domain : "unknown", sizeof(ev->domain) - 1);
        ev->domain[sizeof(ev->domain) - 1] = '\0';
        strncpy(ev->ip,    ip     ? ip     : "unknown", sizeof(ev->ip)    - 1);
        ev->ip[sizeof(ev->ip) - 1] = '\0';
        ev->passed    = passed;
        ev->comp = comp;
        ev->timestamp = time(NULL);
        do_flush = (g_udp_batch_count >= UDP_BATCH_MAX);
    }
    pthread_mutex_unlock(&g_udp_mutex);

    if (do_flush)
        flush_udp_batch();
}

/* libuv timer callback — runs on worker-0's loop every 5 minutes */
static void udp_flush_timer_cb(uv_timer_t *handle) {
    (void)handle;
    flush_udp_batch();
}

/* --------------------------------------------------------------------------- */
/* 3. Challenge-token crypto  (ChaCha20-Poly1305, ephemeral key)               */
/* --------------------------------------------------------------------------- */

/*
 * Wire format (raw bytes, before base64url):
 *   12 B nonce || ciphertext || 16 B Poly1305 tag
 *
 * Plaintext formats:
 *   Simple:  "SIMP|ip|ja4|unix_ts|pow_hex32"
 *   Complex: "COMP|ip|ja4|unix_ts|pow_hex32|sol_x|sol_y"
 */

static size_t chal_encrypt(const char *plaintext, size_t ptlen,
                            unsigned char *out, size_t outsize) {
    if (outsize < ptlen + 28) return 0;

    unsigned char *nonce = out;
    unsigned char *ct    = out + CHAL_NONCE_LEN;
    unsigned char *tag   = out + CHAL_NONCE_LEN + ptlen;

    if (RAND_bytes(nonce, CHAL_NONCE_LEN) != 1) return 0;

    /* Lazy-init: allocated once per OS thread, reused on every subsequent call */
    if (!tls_chal_encrypt_ctx) {
        tls_chal_encrypt_ctx = EVP_CIPHER_CTX_new();
        if (!tls_chal_encrypt_ctx) return 0;
    }

    int ok = 0, len = 0;
    /* EVP_EncryptInit_ex with a non-NULL cipher fully reinitialises the context,
     * so any state from a previous (possibly failed) call is safely overwritten. */
    if (EVP_EncryptInit_ex(tls_chal_encrypt_ctx, EVP_chacha20_poly1305(),
                           NULL, g_challenge_key, nonce) != 1) goto done;
    if (EVP_EncryptUpdate(tls_chal_encrypt_ctx, ct, &len,
                          (const unsigned char *)plaintext, (int)ptlen) != 1) goto done;
    if (EVP_EncryptFinal_ex(tls_chal_encrypt_ctx, ct + len, &len) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(tls_chal_encrypt_ctx, EVP_CTRL_AEAD_GET_TAG,
                             16, tag) != 1) goto done;
    ok = 1;
done:
    /* No EVP_CIPHER_CTX_free — context stays alive for the next request */
    return ok ? (CHAL_NONCE_LEN + ptlen + 16) : 0;
}

static bool chal_decrypt(const unsigned char *in, size_t inlen,
                          char *out, size_t outsize) {
    if (inlen < 29) return false;

    const unsigned char *nonce = in;
    const unsigned char *ct    = in + CHAL_NONCE_LEN;
    size_t               ctlen = inlen - CHAL_NONCE_LEN - 16;
    const unsigned char *tag   = in + CHAL_NONCE_LEN + ctlen;

    if (outsize < ctlen + 1) return false;

    /* Lazy-init: allocated once per OS thread, reused on every subsequent call */
    if (!tls_chal_decrypt_ctx) {
        tls_chal_decrypt_ctx = EVP_CIPHER_CTX_new();
        if (!tls_chal_decrypt_ctx) return false;
    }

    int ok = 0, len = 0;
    /* EVP_DecryptInit_ex with a non-NULL cipher fully reinitialises the context. */
    if (EVP_DecryptInit_ex(tls_chal_decrypt_ctx, EVP_chacha20_poly1305(),
                           NULL, g_challenge_key, nonce) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(tls_chal_decrypt_ctx, EVP_CTRL_AEAD_SET_TAG,
                             16, (void *)tag) != 1) goto done;
    if (EVP_DecryptUpdate(tls_chal_decrypt_ctx, (unsigned char *)out, &len,
                          ct, (int)ctlen) != 1) goto done;
    if (EVP_DecryptFinal_ex(tls_chal_decrypt_ctx,
                             (unsigned char *)out + len, &len) != 1) goto done;
    out[ctlen] = '\0';
    ok = 1;
done:
    /* No EVP_CIPHER_CTX_free — context stays alive for the next request */
    return ok;
}


/* --------------------------------------------------------------------------- */
/* 4. Utility helpers                                                           */
/* --------------------------------------------------------------------------- */

/* --- Client IP (direct peer only — matches original working version) ------- */
static void get_client_ip(h2o_req_t *req, char out[64]) {
    out[0] = '\0';
    struct sockaddr_storage ss;
    socklen_t slen = sizeof(ss);
    int fd = h2o_socket_get_fd(req->conn->callbacks->get_socket(req->conn));
    if (getpeername(fd, (struct sockaddr *)&ss, &slen) != 0) return;
    if (ss.ss_family == AF_INET)
        inet_ntop(AF_INET,  &((struct sockaddr_in  *)&ss)->sin_addr,  out, 64);
    else if (ss.ss_family == AF_INET6)
        inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&ss)->sin6_addr, out, 64);
}

/* --- Header lookup --------------------------------------------------------- */
static bool get_request_header(h2o_req_t *req, const char *name, size_t nlen,
                                 char *out, size_t max) {
    for (size_t i = 0; i < req->headers.size; i++) {
        h2o_header_t *h = &req->headers.entries[i];
        if (h2o_lcstris(h->name->base, h->name->len, name, nlen)) {
            size_t cp = h->value.len < max - 1 ? h->value.len : max - 1;
            memcpy(out, h->value.base, cp);
            out[cp] = '\0';
            return true;
        }
    }
    out[0] = '\0';
    return false;
}

/* --- Hex encode ------------------------------------------------------------ */
static void bytes_to_hex(char *dst, const unsigned char *src, size_t n) {
    static const char hc[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        dst[i*2]   = hc[src[i] >> 4];
        dst[i*2+1] = hc[src[i] & 0x0f];
    }
    dst[n*2] = '\0';
}

/* --- Standard base64 (for puzzle JPEG → JSON transport) ------------------- */
static const char B64STD[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static size_t b64std_encode(char *dst, const unsigned char *src, size_t n) {
    size_t i = 0, j = 0;
    for (; i + 2 < n; i += 3) {
        dst[j++] = B64STD[(src[i]   >> 2) & 0x3f];
        dst[j++] = B64STD[((src[i]   << 4) | (src[i+1] >> 4)) & 0x3f];
        dst[j++] = B64STD[((src[i+1] << 2) | (src[i+2] >> 6)) & 0x3f];
        dst[j++] = B64STD[src[i+2] & 0x3f];
    }
    if (n - i == 1) {
        dst[j++] = B64STD[(src[i] >> 2) & 0x3f];
        dst[j++] = B64STD[(src[i] << 4) & 0x3f];
        dst[j++] = '='; dst[j++] = '=';
    } else if (n - i == 2) {
        dst[j++] = B64STD[(src[i]   >> 2) & 0x3f];
        dst[j++] = B64STD[((src[i]   << 4) | (src[i+1] >> 4)) & 0x3f];
        dst[j++] = B64STD[(src[i+1] << 2) & 0x3f];
        dst[j++] = '=';
    }
    dst[j] = '\0';
    return j;
}


/* --- Single-pass zero-alloc JSON field extractor --------------------------- */
static inline const char *find_json_field(const char *json, size_t len,
                                           const char *key, size_t klen) {
    const char *end = json + len;
    const char *p   = json;
    while (p < end - (klen + 3)) {
        if (*p == '"' && memcmp(p + 1, key, klen) == 0 &&
            p[klen + 1] == '"' && p[klen + 2] == ':')
            return p + klen + 3;
        p++;
    }
    return NULL;
}

static inline size_t extract_json_string(const char *vp, char *out, size_t max) {
    while (*vp == ' ') vp++;
    if (*vp != '"') return 0;
    vp++;
    size_t n = 0;
    while (*vp && *vp != '"' && n < max - 1) out[n++] = *vp++;
    out[n] = '\0';
    return n;
}

static inline long extract_json_int(const char *vp) {
    while (*vp == ' ') vp++;
    return strtol(vp, NULL, 10);
}

static inline bool extract_json_bool(const char *vp) {
    while (*vp && *vp == ' ') vp++;
    return (vp[0] == 't'); /* "true" starts with 't'; anything else is false */
}


static inline unsigned long long extract_json_uint64(const char *vp) {
    while (*vp == ' ') vp++;
    return strtoull(vp, NULL, 10);
}

/* --- Browser metrics bundle ----------------------------------------------- */
typedef struct {
    char webgl_renderer[256];
    char timezone[128];
    int  hardware_concurrency;
    int  innerwidth, innerheight;
    int  outerwidth, outerheight;
    int  device_memory;
    bool webdriver;
    bool chromewebdrivermissing;
    bool error_stack_tripwire;
} browser_metrics_t;

static void extract_browser_metrics(const char *json, size_t jlen,
                                      browser_metrics_t *m) {
    const char *v;
#define STRF(k, kl, dst) \
    if ((v = find_json_field(json, jlen, k, kl))) extract_json_string(v, dst, sizeof(dst)); \
    else dst[0] = '\0';
#define INTF(k, kl, dst) \
    dst = (v = find_json_field(json, jlen, k, kl)) ? (int)extract_json_int(v) : 0;
#define BOOLF(k, kl, dst) \
    dst = (v = find_json_field(json, jlen, k, kl)) ? extract_json_bool(v) : false;

    STRF("webglrenderer", 13, m->webgl_renderer)
    STRF("timezone",    8, m->timezone)
    INTF("hardwareconcurrency", 19, m->hardware_concurrency)
    INTF("innerw",  6, m->innerwidth)
    INTF("innerh", 6, m->innerheight)
    INTF("availw",  6, m->outerwidth)
    INTF("availh", 6, m->outerheight)
    INTF("devicememory",12, m->device_memory)
    BOOLF("webdriver", 9, m->webdriver)
    BOOLF("ischromeruntimemissing", 22, m->chromewebdrivermissing)
    BOOLF("errorstacktripwire", 18, m->error_stack_tripwire)
#undef STRF
#undef INTF
#undef BOOLF
}


/* --- Trajectory parser: [[x,y,t], ...] ------------------------------------ */
static size_t parse_trajectory_fast(const char *json, size_t jlen,
                                      trajectory_point_t *out, size_t max_pts) {
    const char *p = find_json_field(json, jlen, "trajectory", 10);
    if (!p) return 0;
    while (*p && *p != '[') p++;
    if (!*p) return 0;
    p++;

    size_t n = 0;
    while (*p && *p != ']' && n < max_pts) {
        while (*p == ' ' || *p == ',') p++;
        if (*p != '[') break;
        p++;
        char *ep;
        out[n].x            = strtof(p, &ep); p = ep;
        if (*p == ',') p++;
        out[n].y            = strtof(p, &ep); p = ep;
        if (*p == ',') p++;
        out[n].timestamp_ms = (uint32_t)strtoul(p, &ep, 10); p = ep;
        n++;
        while (*p && *p != ']') p++;
        if (*p == ']') p++;
    }
    return n;
}

/* --- PoW challenge builder from raw hex bytes stored in token -------------- */
static inline void make_pow_challenge(pow_challenge_t *out,
                                       const unsigned char raw[32],
                                       uint32_t difficulty) {
    memcpy(out->challenge, raw, 32);
    out->target_leading_zeros = difficulty;
    out->timestamp_created    = 0;
}
/* -----------------------------------------------------------------------
 * add_cors_headers — emit all CORS headers needed for open cross-origin
 * access.  Called by send_json_response AND by the OPTIONS preflight path.
 * --------------------------------------------------------------------- */
static inline void add_cors_headers(h2o_req_t *req) {
    h2o_add_header_by_str(&req->pool, &req->res.headers,
                           H2O_STRLIT("access-control-allow-origin"), 0, NULL,
                           H2O_STRLIT("*"));
    h2o_add_header_by_str(&req->pool, &req->res.headers,
                           H2O_STRLIT("access-control-allow-methods"), 0, NULL,
                           H2O_STRLIT("POST, GET, OPTIONS"));
    h2o_add_header_by_str(&req->pool, &req->res.headers,
                           H2O_STRLIT("access-control-allow-headers"), 0, NULL,
                           H2O_STRLIT("content-type, x-captcha-token"));
    h2o_add_header_by_str(&req->pool, &req->res.headers,
                           H2O_STRLIT("access-control-expose-headers"), 0, NULL,
                           H2O_STRLIT("x-captcha-token"));
    h2o_add_header_by_str(&req->pool, &req->res.headers,
                           H2O_STRLIT("access-control-max-age"), 0, NULL,
                           H2O_STRLIT("86400"));  /* browsers cache preflight 24h */
}
/* --- JSON response sender -------------------------------------------------- */
static inline void send_json_response(h2o_req_t *req, int status,
                                       const char *json, size_t jsonlen) {
    req->res.status = status;
    req->res.reason = (status == 200) ? "OK"
                    : (status == 429) ? "Too Many Requests"
                    :                   "Forbidden";
    h2o_add_header(&req->pool, &req->res.headers,
                   H2O_TOKEN_CONTENT_TYPE, NULL,
                   H2O_STRLIT("application/json"));
    add_cors_headers(req);  /* ✅ All CORS headers in one call */
    h2o_send_inline(req, json, jsonlen);
}
/*
static inline void send_json_response(h2o_req_t *req, int status,
                                       const char *json, size_t jsonlen) {
    req->res.status = status;
    req->res.reason = (status == 200) ? "OK" : "Forbidden";
    h2o_add_header(&req->pool, &req->res.headers,
                   H2O_TOKEN_CONTENT_TYPE, NULL,
                   H2O_STRLIT("application/json"));
    h2o_add_header_by_str(&req->pool, &req->res.headers,
                           H2O_STRLIT("access-control-expose-headers"), 0, NULL,
                           H2O_STRLIT("x-captcha-token"));
    h2o_send_inline(req, json, jsonlen);
}
*/
/* Attach signed pass token as response header */
static inline void attach_pass_token(h2o_req_t *req,
                                      const char *tok, size_t tlen) {
    char *hv = h2o_mem_alloc_pool(&req->pool, tlen + 1);
    memcpy(hv, tok, tlen + 1);
    h2o_add_header_by_str(&req->pool, &req->res.headers,
                           H2O_STRLIT("x-captcha-token"), 0, NULL,
                           hv, tlen);
}

/* --- Worker-id from request context --------------------------------------- */
/* struct st_worker_t is defined in section 2, before this function. */
static inline int req_worker_id(h2o_req_t *req) {
    struct st_worker_t *w = H2O_STRUCT_FROM_MEMBER(
        struct st_worker_t, ctx, req->conn->ctx);
    return w->worker_id;
}

/* --- Trajectory analysis pipeline (shared by both solve endpoints) --------- */
/* Returns bot_score >= 0 on success, -1.0f on hard rejection.
 * On rejection, *fail_json points to an error-response literal. */
static float run_trajectory_analysis(const trajectory_point_t *traj,
                                       size_t count, bool istouchpad,
                                       const char **fail_json, bool issimple) {
    uint32_t time_diff[MAX_TRAJECTORY_POINTS];
    float    dist_diff[MAX_TRAJECTORY_POINTS];
    float    t_avg = 0.0f, p1 = 0.0f, p2 = 0.0f, p3 = 0.0f;
    float    bot_score = 0.0f;

    if (!validate_integrity_filters(traj, count, istouchpad,
                                     time_diff, dist_diff,
                                     &t_avg, &p1, &p2, &p3, issimple)) {

        *fail_json = ERR_INTEGRITY; return -1.0f;
    }
    if (!calculate_correct_burstiness(traj, count, istouchpad,
                                      time_diff, dist_diff,
                                      &t_avg, &p1, &p2, &p3, &bot_score)) {

        *fail_json = ERR_BURSTINESS;
        return -1.0f;
    }

    float scalar_speed[MAX_TRAJECTORY_POINTS];
    float acceleration[MAX_TRAJECTORY_POINTS];

    if (!calculate_sample_entropy_jerk(traj, count, istouchpad,
                                        time_diff, dist_diff,
                                        scalar_speed, acceleration,
                                        &bot_score)) {

        *fail_json = ERR_ENTROPY; return -1.0f;
    }

    if (!f4_final_features(traj, count, istouchpad,
                            time_diff, dist_diff,
                            scalar_speed, acceleration,&bot_score)) {

        *fail_json = ERR_FEATURES; return -1.0f;
    }
    if (!validate_trajectory_fitts(traj, count, &bot_score)) {

        *fail_json = ERR_FITTS; return -1.0f;
    }
    if (!is_human_velocity_cv(dist_diff, time_diff, count, &bot_score)) {

        *fail_json = ERR_VELOCITY; return -1.0f;
    }

    return bot_score;
}

/*
 * Reads the Origin header and returns the registered domain
 * (e.g. "https://sub.example.com:443" → "example.com").
 * Falls back to "unknown" if Origin is absent or malformed.
 */
static void extract_registered_domain(h2o_req_t *req, char *out, size_t max)
{
    char raw[256] = {0};

    // 1. Intentar Origin primero (todos los browsers menos iOS en algunos casos)
    if (!get_request_header(req, "origin", 6, raw, sizeof(raw)) || raw[0] == '\0') {
        // 2. Fallback: Referer (iOS Safari lo envía siempre)
        get_request_header(req, "referer", 7, raw, sizeof(raw));
    }

    if (raw[0] == '\0') goto unknown;

    // Saltar el scheme: "https://" o "http://"
    char *p = raw;
    char *sep = strstr(raw, "://");
    if (sep) p = sep + 3;

    // Cortar en el primer '/' o '?' (Referer puede tener path)
    p[strcspn(p, "/?#")] = '\0';

    // Cortar el puerto si hay ":"
    char *colon = strchr(p, ':');
    if (colon) *colon = '\0';

    if (p[0] == '\0') goto unknown;

    // Extraer el registered domain (los dos últimos labels: example.com)
    char *last = strrchr(p, '.');
    if (!last) goto unknown;

    char *prev = NULL;
    for (int i = (int)(last - p) - 1; i >= 0; i--) {
        if (p[i] == '.') { prev = p + i; break; }
    }

    p = prev ? prev + 1 : p;
    strncpy(out, p, max - 1);
    out[max - 1] = '\0';
    return;

    unknown:
        strncpy(out, "unknown", max - 1);
        out[max - 1] = '\0';
}

static inline void force_new_tls_handshake(h2o_req_t *req)
{
    if (req->version >= 0x200) {

    } else {
        h2o_add_header(&req->pool, &req->res.headers,
                       H2O_TOKEN_CONNECTION, NULL, H2O_STRLIT("close"));
    }
}

/* --------------------------------------------------------------------------- */
/* 5a. POST /challenge/simp                                                    */
/*                                                                             */
/* Request body (JSON):                                                        */
/*   { "userAgent":"...", "hardwareConcurrency":8, "innerWidth":1920,         */
/*     "innerHeight":1080, "outerWidth":1920, "outerHeight":1080,             */
/*     "webglRenderer":"...", "timezone":"...", "deviceMemory":8 }            */
/* Request header: X-JA4                                                      */
/*                                                                             */
/* 200: { "challenge_token":"...", "pow_challenge":"hex32",                   */
/*        "pow_difficulty":16 }                                               */
/* 403: { "valid":false, "error":"Do_complex_captcha" }                       */
/* --------------------------------------------------------------------------- */

static int handle_challenge_simp(h2o_handler_t *self, h2o_req_t *req) {
    (void)self;
    HANDLE_PREFLIGHT(req);
    if (!h2o_memis(req->method.base, req->method.len, H2O_STRLIT("POST")))
        return -1;

    h2o_iovec_t body = req->entity;
    if (body.len == 0 || body.len > 8192) {
        send_json_response(req, 400, H2O_STRLIT("{\"valid\":false,\"error\":\"bad_request\"}"));
        return 0;
    }

    char beg_user_ip[64];
    get_client_ip(req, beg_user_ip);
    const char *user_ip = beg_user_ip;
    if (strncmp(user_ip, "::ffff:", 7) == 0) {
        user_ip += 7;
    }


    if(ip_bloom_is_suspicious(user_ip)){

        SEND403(req, ERR_DO_COMPLEX);
        return 0;
    }

    char ja4[128] = "unknown";
    char ja4o[128] = "unknown";
    char short_ja4[64];
    char short_ja4o[64];

    extract_ja4_fingerprints(req, ja4, ja4o, short_ja4, short_ja4o);

    char domain_start[128];
    extract_registered_domain(req, domain_start, sizeof(domain_start));

    char user_agent[256] = {0};
    get_request_header(req, "user-agent", 10, user_agent, sizeof(user_agent));

    char rl_key[512];
    snprintf(rl_key, sizeof(rl_key), "%s|%s|%s|%s", user_ip, short_ja4, short_ja4o, domain_start);

    // Check + increment atomically num requests
    if (cms_increment_and_get(rl_key) > CMS_LIMIT) {

        SEND403(req, ERR_DO_COMPLEX);
        return 0;
    }

    char client_browser[32];

    /* Browser fingerprint pre-check */
    static __thread browser_metrics_t bm;
    extract_browser_metrics(body.base, body.len, &bm);

    get_client_browser(user_agent,client_browser);


    //Check ja4 matches UA
    if(!ja4_matches_ua(client_browser,ja4)){

        SEND403(req, ERR_DO_COMPLEX);
        return 0;
    }

    bool isphone = check_is_touchpad(user_agent);

    if (captcha_bot_detector(user_agent, bm.hardware_concurrency,
                              bm.innerwidth, bm.innerheight,
                              bm.outerwidth, bm.outerheight,
                              bm.webgl_renderer, &isphone,
                              bm.device_memory, bm.timezone, user_ip,bm.webdriver,
                              bm.chromewebdrivermissing, bm.error_stack_tripwire)) {

        SEND403(req, ERR_DO_COMPLEX);
        return 0;
    }

    /* PoW challenge */
    unsigned char pow_raw[16];
    if (RAND_bytes(pow_raw, sizeof(pow_raw)) != 1) {
        h2o_send_error_503(req, "Service Unavailable", "Entropy error", 0);
        return 0;
    }
    char pow_hex[33];
    bytes_to_hex(pow_hex, pow_raw, sizeof(pow_raw));

    /* Build plaintext: SIMP|ip|ja4|ts|pow_hex */
    char plaintext[512];
    int  ptlen = snprintf(plaintext, sizeof(plaintext),
                          "SIMP|%s|%s|%s|%ld|%s",
                          user_ip, short_ja4, short_ja4o, (long)time(NULL), pow_hex);
    if (ptlen <= 0 || ptlen >= (int)sizeof(plaintext)) {
        h2o_send_error_500(req, "Server Error", "Token build error", 0);
        return 0;
    }

    unsigned char cipher[600];
    size_t cipher_len = chal_encrypt(plaintext, (size_t)ptlen,
                                      cipher, sizeof(cipher));
    if (!cipher_len) {
        h2o_send_error_500(req, "Server Error", "Encryption error", 0);
        return 0;
    }

    char tok_b64[900];
    b64url_encode(tok_b64, cipher, cipher_len);
    tok_b64[b64url_encoded_len(cipher_len)] = '\0';

    char *resp = h2o_mem_alloc_pool(&req->pool, 1024);
    int   rlen = snprintf(resp, 1024,
                          "{\"challenge_token\":\"%s\","
                          "\"pow_challenge\":\"%s\","
                          "\"pow_difficulty\":%d}",
                          tok_b64, pow_hex, POW_DIFFICULTY_SIMPLE);
    send_json_response(req, 200, resp, (size_t)rlen);

    return 0;
}

/* --------------------------------------------------------------------------- */
/* 5b. POST /solve/simp                                                        */
/*                                                                             */
/* Request body (JSON):                                                        */
/*   { "challenge_token":"base64url", "pow_solution":12345678,                */
/*     "trajectory":[{"x":100,"y":200,"t":1000}, ...] }                      */
/* Request header: X-JA4                                                      */
/*                                                                             */
/* 200: { "valid":true, "score":0.08, "mobile":false }                        */
/*      header X-Captcha-Token: <Ed25519-signed pass token>                   */
/* 403: { "valid":false, "error":"..." }                                      */
/* --------------------------------------------------------------------------- */
static int handle_solve_simp(h2o_handler_t *self, h2o_req_t *req) {
    (void)self;
    HANDLE_PREFLIGHT(req);
    if (!h2o_memis(req->method.base, req->method.len, H2O_STRLIT("POST")))
        return -1;

    h2o_iovec_t body = req->entity;
    if (body.len == 0 || body.len > 131072) {
        send_json_response(req, 400, H2O_STRLIT("{\"valid\":false,\"error\":\"bad_request\"}"));
        return 0;
    }

    const char *data = body.base;
    size_t dlen = body.len;

    char beg_user_ip[64];
    get_client_ip(req, beg_user_ip);
    const char *user_ip = beg_user_ip;
    if (strncmp(user_ip, "::ffff:", 7) == 0) {
        user_ip += 7;
    }


    if(ip_bloom_is_suspicious(user_ip)){

        SEND403(req, ERR_DO_COMPLEX);
        return 0;
    }

    /* ── UDP telemetry: resolve domain once for all exit paths ── */
    char domain[128];
    extract_registered_domain(req, domain, sizeof(domain));

    char ja4[128] = "unknown";
    char ja4o[128] = "unknown";
    char short_ja4[64];
    char short_ja4o[64];

    extract_ja4_fingerprints(req, ja4, ja4o, short_ja4, short_ja4o);

    static __thread char tok_b64[900];
    static __thread uint64_t pow_sol;
    const char *v;

    v = find_json_field(data, dlen, "challenge_token", 15);
    if (!v || !extract_json_string(v, tok_b64, sizeof(tok_b64)))
        goto bad_request;
    v = find_json_field(data, dlen, "pow_solution", 12);
    if (!v) goto bad_request;
    pow_sol = extract_json_uint64(v);

    unsigned char cipher[700];
    int cipher_len = b64url_decode(cipher, tok_b64, strlen(tok_b64));
    if (cipher_len <= 0) { SOLVE_FAIL(req, ERR_TOKEN_BAD, domain, user_ip,0); }

    char plaintext[512];
    if (!chal_decrypt(cipher, (size_t)cipher_len, plaintext, sizeof(plaintext))) {

        SOLVE_FAIL(req, ERR_TOKEN_BAD, domain, user_ip,0);
    }

    if (bloom_check_and_add(cipher, (size_t)cipher_len)) {

        SOLVE_FAIL(req, ERR_TOKEN_BAD, domain, user_ip,0);
    }

    char tok_type[8], tok_ip[64], tok_ja4[64], tok_ja4o[64], tok_pow[33];
    long tok_ts;
    if (sscanf(plaintext, "%7[^|]|%63[^|]|%63[^|]|%63[^|]|%ld|%32[^|]",
               tok_type, tok_ip, tok_ja4, tok_ja4o, &tok_ts, tok_pow) != 6)
        { SOLVE_FAIL(req, ERR_TOKEN_BAD, domain, user_ip,0); }

    if (strcmp(tok_type, "SIMP") != 0) { SOLVE_FAIL(req, ERR_WRONG_TYPE, domain, user_ip,0); }

    double age = difftime(time(NULL), (time_t)tok_ts);
    if (age > CHALLENGE_MAX_AGE_SECS || age < 0.0) { SOLVE_FAIL(req, ERR_TOKEN_EXP,   domain, user_ip,0); }

    if (strcmp(user_ip,    tok_ip  ) != 0) { SOLVE_FAIL(req, ERR_IP_MISMATCH,  domain, user_ip,0); }
    if (strcmp(short_ja4,   tok_ja4 ) != 0) { SOLVE_FAIL(req, ERR_JA4_MISMATCH, domain, user_ip,0); }

    if (strcmp(short_ja4o, tok_ja4o) != 0) {
        if (req->version < 0x200) {
            // HTTP/1: strict enforcement, JA4o is reliable
            SOLVE_FAIL(req, ERR_JA4_MISMATCH, domain, user_ip,0);
        } else {
            // HTTP/2: JA4o can drift due to session multiplexing — log but don't block
            // JA4 (cipher/version fingerprint) is still fully enforced below

        }
    }

    unsigned char pow_raw[32] = {0};
    size_t tokpow_len = strlen(tok_pow);
    for (size_t hi = 0; hi * 2 < tokpow_len && hi < 16; hi++) {
        unsigned int bval = 0;
        sscanf(tok_pow + hi * 2, "%02x", &bval);
        pow_raw[hi] = (unsigned char)bval;
    }
    pow_challenge_t pc;
    make_pow_challenge(&pc, pow_raw, POW_DIFFICULTY_SIMPLE);
    if (!verify_pow(&pc, pow_sol)) { SOLVE_FAIL(req, ERR_POW_FAIL, domain, user_ip,0); }


    char pass_token[512];
    if (!generate_final_token(true,pass_token, sizeof(pass_token), short_ja4, user_ip, short_ja4o)) {
        h2o_send_error_500(req, "Server Error", "Token sign failed", 0);
        return 0;
    }
    attach_pass_token(req, pass_token, strlen(pass_token));

    udp_report_event(domain, user_ip, 1, 0);

    send_json_response(req, 200, "true", 4);

    return 0;

    bad_request:
        send_json_response(req, 400, H2O_STRLIT("{\"valid\":false,\"error\":\"bad_request\"}"));
        return 0;
}

/* --------------------------------------------------------------------------- */
/* 5c. GET /challenge/complex                                                  */
/* --------------------------------------------------------------------------- */

static int handle_challenge_complex(h2o_handler_t *self, h2o_req_t *req) {
    (void)self;
    HANDLE_PREFLIGHT(req);
    if (!h2o_memis(req->method.base, req->method.len, H2O_STRLIT("GET")))
        return -1;

    char beg_user_ip[64];
    get_client_ip(req, beg_user_ip);
    const char *user_ip = beg_user_ip;
    if (strncmp(user_ip, "::ffff:", 7) == 0) {
        user_ip += 7;
    }


    char ja4[128] = "unknown";
    char ja4o[128] = "unknown";
    char short_ja4[64];
    char short_ja4o[64];

    extract_ja4_fingerprints(req, ja4, ja4o, short_ja4, short_ja4o);

    char domain_start[128];
    extract_registered_domain(req, domain_start, sizeof(domain_start));


    char user_agent[256] = {0}; // An array of 256 characters
    get_request_header(req, "user-agent", 10, user_agent, sizeof(user_agent));


    char rl_key[512];
    snprintf(rl_key, sizeof(rl_key), "%s|%s|%s|%s", user_ip, short_ja4, short_ja4o, domain_start);

    /* Generate puzzle */
    struct st_worker_t *worker = H2O_STRUCT_FROM_MEMBER(
        struct st_worker_t, ctx, req->conn->ctx);

    puzzle_token_payload_t tok_payload;
    unsigned char          old_enc[256];
    size_t                 old_enc_len = 0;
    puzzle_metadata_t      meta;


    // Check + increment atomically
    if (cms_increment_and_get(rl_key) > CMS_LIMIT_COMPLEX){

        h2o_send_error_503(req, "Service Unavailable",
                           "Puzzle generation failed", 0);
        return 0;
    }

    if (!captcha_get_puzzle(worker->worker_id,
                             &tok_payload, old_enc, &old_enc_len, &meta)) {
        h2o_send_error_503(req, "Service Unavailable",
                           "Puzzle generation failed", 0);
        return 0;
    }

    uint16_t sol_x = meta.solution_x;
    uint16_t sol_y = meta.solution_y;

    /* PoW challenge */
    unsigned char pow_raw[16];
    if (RAND_bytes(pow_raw, sizeof(pow_raw)) != 1) {
        h2o_send_error_503(req, "Service Unavailable", "Entropy error", 0);
        return 0;
    }
    char pow_hex[33];
    bytes_to_hex(pow_hex, pow_raw, sizeof(pow_raw));

    /* Build challenge token: COMP|ip|ja4|ja4o|ts|pow_hex|sol_x|sol_y */
    char plaintext[512];
    int  ptlen = snprintf(plaintext, sizeof(plaintext),
                          "COMP|%s|%s|%s|%ld|%s|%u|%u",
                          user_ip, short_ja4, short_ja4o,(long)time(NULL),
                          pow_hex, (unsigned)sol_x, (unsigned)sol_y);
    if (ptlen <= 0 || ptlen >= (int)sizeof(plaintext)) {
        h2o_send_error_500(req, "Server Error", "Token build error", 0);
        return 0;
    }

    unsigned char cipher[600];
    size_t cipher_len = chal_encrypt(plaintext, (size_t)ptlen,
                                      cipher, sizeof(cipher));
    if (!cipher_len) {
        h2o_send_error_500(req, "Server Error", "Encryption error", 0);
        return 0;
    }

    char tok_b64[900];
    b64url_encode(tok_b64, cipher, cipher_len);
    tok_b64[b64url_encoded_len(cipher_len)] = '\0';

    /* base64-encode puzzle images */
    size_t bg_b64_max = ((meta.background_size + 2) / 3) * 4 + 2;
    size_t pc_b64_max = ((meta.piece_size      + 2) / 3) * 4 + 2;

    char *bg_b64 = h2o_mem_alloc_pool(&req->pool, bg_b64_max);
    char *pc_b64 = h2o_mem_alloc_pool(&req->pool, pc_b64_max);

    b64std_encode(bg_b64, (const unsigned char *)meta.background_png,
                  meta.background_size);
    b64std_encode(pc_b64, (const unsigned char *)meta.piece_png,
                  meta.piece_size);

    /* Assemble JSON */
    size_t resp_max = 256 + strlen(tok_b64) + bg_b64_max + pc_b64_max;
    char  *resp     = h2o_mem_alloc_pool(&req->pool, resp_max);

    int rlen = snprintf(resp, resp_max,
                        "{"
                        "\"challenge_token\":\"%s\","
                        "\"pow_challenge\":\"%s\","
                        "\"pow_difficulty\":%d,"
                        "\"puzzle\":{"
                        "\"background\":\"%s\","
                        "\"piece\":\"%s\","
                        "\"piece_start_x\":0,"
                        "\"width\":%d,"
                        "\"height\":%d,"
                        "\"piece_size\":%d"
                        "}"
                        "}",
                        tok_b64, pow_hex, POW_DIFFICULTY_COMPLEX,
                        bg_b64, pc_b64,
                        BASE_IMAGE_WIDTH, BASE_IMAGE_HEIGHT, PUZZLE_PIECE_SIZE);

    if (rlen <= 0 || (size_t)rlen >= resp_max) {
        h2o_send_error_500(req, "Server Error", "Response build error", 0);
        return 0;
    }

    send_json_response(req, 200, resp, (size_t)rlen);

    return 0;
}

/* --------------------------------------------------------------------------- */
/* 5d. POST /solve/complex                                                     */
/* --------------------------------------------------------------------------- */

static int handle_solve_complex(h2o_handler_t *self, h2o_req_t *req) {
    (void)self;
    HANDLE_PREFLIGHT(req);
    if (!h2o_memis(req->method.base, req->method.len, H2O_STRLIT("POST")))
        return -1;

    h2o_iovec_t body = req->entity;
    if (body.len == 0 || body.len > 131072) {
        send_json_response(req, 400, H2O_STRLIT("{\"valid\":false,\"error\":\"bad_request\"}"));
        return 0;
    }


    const char *data = body.base;
    size_t      dlen = body.len;

    char beg_user_ip[64];
    get_client_ip(req, beg_user_ip);
    const char *user_ip = beg_user_ip;
    if (strncmp(user_ip, "::ffff:", 7) == 0) {
        user_ip += 7;
    }


    char domain[128];
    extract_registered_domain(req, domain, sizeof(domain));


    char ja4[128] = "unknown";
    char ja4o[128] = "unknown";
    char short_ja4[64];
    char short_ja4o[64];

    extract_ja4_fingerprints(req, ja4, ja4o, short_ja4, short_ja4o);

    static __thread char     tok_b64[900];
    static __thread uint64_t pow_sol;
    static __thread int      user_px, user_py;
    const char *v;

    v = find_json_field(data, dlen, "challenge_token", 15);
    if (!v || !extract_json_string(v, tok_b64, sizeof(tok_b64))) goto bad_request;
    v = find_json_field(data, dlen, "pow_solution", 12);
    if (!v) goto bad_request;
    pow_sol = extract_json_uint64(v);
    v = find_json_field(data, dlen, "puzzle_x", 8);
    if (!v) goto bad_request;
    user_px = (int)extract_json_int(v);
    v = find_json_field(data, dlen, "puzzle_y", 8);
    if (!v) goto bad_request;
    user_py = (int)extract_json_int(v);

    /* Decode + decrypt challenge token */
    unsigned char cipher[700];
    int cipher_len = b64url_decode(cipher, tok_b64, strlen(tok_b64));
    if (cipher_len <= 0) { SOLVE_FAIL(req, ERR_TOKEN_BAD,domain,user_ip,1); return 0; }

    char plaintext[512];
    if (!chal_decrypt(cipher, (size_t)cipher_len, plaintext, sizeof(plaintext))) {

        SOLVE_FAIL(req, ERR_TOKEN_BAD,domain,user_ip,1);
        return 0;
    }

    if (bloom_check_and_add(cipher, (size_t)cipher_len)) {

        SOLVE_FAIL(req, ERR_TOKEN_BAD, domain, user_ip,1);
    }

    /* Parse: COMP|ip|ja4|ts|pow_hex|sol_x|sol_y */
    char tok_type[8], tok_ip[64], tok_ja4[64],tok_ja4o[64], tok_pow[33];
    long tok_ts;
    unsigned tok_solx, tok_soly;
    if (sscanf(plaintext, "%7[^|]|%63[^|]|%63[^|]|%63[^|]|%ld|%32[^|]|%u|%u", tok_type, tok_ip, tok_ja4, tok_ja4o, &tok_ts, tok_pow,
               &tok_solx, &tok_soly) != 8) {
        SOLVE_FAIL(req, ERR_TOKEN_BAD,domain,user_ip,1);
        return 0;
    }
    if (strcmp(tok_type, "COMP") != 0) { SOLVE_FAIL(req, ERR_WRONG_TYPE,domain,user_ip,1); return 0; }

    double age = difftime(time(NULL), (time_t)tok_ts);
    if (age > CHALLENGE_MAX_AGE_SECS || age < 0.0) {
        SOLVE_FAIL(req, ERR_TOKEN_EXP,domain,user_ip,1); return 0;
    }
    if (strcmp(user_ip,  tok_ip)  != 0) { SOLVE_FAIL(req, ERR_IP_MISMATCH,domain,user_ip,1);  return 0; }
    if (strcmp(short_ja4, tok_ja4) != 0) { SOLVE_FAIL(req, ERR_JA4_MISMATCH,domain,user_ip,1); return 0; }

    if (strcmp(short_ja4o, tok_ja4o) != 0) {
        if (req->version < 0x200) {
            // HTTP/1: strict enforcement, JA4o is reliable
            SOLVE_FAIL(req, ERR_JA4_MISMATCH,domain,user_ip,1);
        } else {
            // HTTP/2: JA4o can drift due to session multiplexing — log but don't block
            // JA4 (cipher/version fingerprint) is still fully enforced below

        }
    }

    /* PoW */
    unsigned char pow_raw[32] = {0};
    size_t tokpow_len = strlen(tok_pow);
    for (size_t hi = 0; hi * 2 < tokpow_len && hi < 16; hi++) {
        unsigned int bval = 0;
        sscanf(tok_pow + hi * 2, "%02x", &bval);
        pow_raw[hi] = (unsigned char)bval;
    }
    pow_challenge_t pc;
    make_pow_challenge(&pc, pow_raw, POW_DIFFICULTY_COMPLEX);
    if (!verify_pow(&pc, pow_sol)) { SOLVE_FAIL(req, ERR_POW_FAIL,domain,user_ip,1); return 0; }

    /* Puzzle answer */
    int dx = abs(user_px - (int)tok_solx);
    int dy = abs(user_py - (int)tok_soly);
    if (dx > PUZZLE_TOLERANCE || dy > PUZZLE_TOLERANCE) {

        SOLVE_FAIL(req, ERR_PUZZLE_WRONG,domain,user_ip,1);
        return 0;
    }

    /* Trajectory */
    static __thread trajectory_point_t traj[MAX_TRAJECTORY_POINTS];
    size_t traj_n = parse_trajectory_fast(data, dlen, traj, MAX_TRAJECTORY_POINTS);
    if (traj_n < MIN_PUZZLE_POINTS) { SOLVE_FAIL(req, ERR_TRAJ_SHORT,domain,user_ip,1); return 0; }

    int dxt = abs((int)traj[traj_n-1].x - (int)tok_solx);
    int dyt = abs((int)traj[traj_n-1].y - (int)tok_soly);
    if (dxt > PUZZLE_TOLERANCE || dyt > PUZZLE_TOLERANCE) {

        SOLVE_FAIL(req, ERR_PUZZLE_WRONG,domain,user_ip,1);
        return 0;
    }

    char ua[512] = {0};
    get_request_header(req, "user-agent", 10, ua, sizeof(ua));
    bool istouchpad = check_is_touchpad(ua);

    const char *fail_json = NULL;
    float bot_score = run_trajectory_analysis(traj, traj_n, istouchpad,
                                               &fail_json, false);
    if (bot_score < 0.0f) {
        send_json_response(req, 403, fail_json, strlen(fail_json));

        return 0;
    }
    if (bot_score >= BOT_SCORE_MAX) {

        SOLVE_FAIL(req, ERR_BOT_SCORE,domain,user_ip,1);
        return 0;
    }

    /* Issue signed pass token */
    char pass_token[512];
    if (!generate_final_token(false,pass_token, sizeof(pass_token), short_ja4, user_ip, short_ja4o)) {
        h2o_send_error_500(req, "Server Error", "Token sign failed", 0);
        return 0;
    }
    attach_pass_token(req, pass_token, strlen(pass_token));

    udp_report_event(domain, user_ip, 1, 1);

    send_json_response(req, 200, "true", 4);

    return 0;

    bad_request:
        send_json_response(req, 400, H2O_STRLIT("{\"valid\":false,\"error\":\"bad_request\"}"));
        return 0;
}


/* --------------------------------------------------------------------------- */
/* 5f. GET /api/validate                                                          */
/* --------------------------------------------------------------------------- */
/* ---- Extract and validate api_token ---- */
/*

*/
static int handle_validate(h2o_handler_t *self, h2o_req_t *req) {
    (void)self;
    HANDLE_PREFLIGHT(req);
    if (!h2o_memis(req->method.base, req->method.len, H2O_STRLIT("POST")))
        return -1;

    h2o_iovec_t body = req->entity;
    if (body.len == 0 || body.len > 4096) {
        send_json_response(req, 400, H2O_STRLIT("{\"valid\":false,\"error\":\"bad_request\"}"));
        return 0;
    }
    //api_token
    static __thread char api_tok_raw[API_TOKEN_TOTAL_LEN + 1];
    const char *av = find_json_field(body.base, body.len, "api_token", 9);
    if (!av || !extract_json_string(av, api_tok_raw, sizeof(api_tok_raw))) {
        send_json_response(req, 401, H2O_STRLIT("{\"valid\":false,\"error\":\"missing_api_token\"}"));
        return 0;
    }
    if (!api_token_verify(api_tok_raw)) {
        send_json_response(req, 401, H2O_STRLIT("{\"valid\":false,\"error\":\"invalid_api_token\"}"));
        return 0;
    }

    /* Extract token from JSON — result is already a mutable local array */
    static __thread char token_raw[768];
    const char *v = find_json_field(body.base, body.len, "captcha_token", 13);
    if (!v || !extract_json_string(v, token_raw, sizeof(token_raw))) {
        send_json_response(req, 400, H2O_STRLIT("{\"valid\":false,\"error\":\"bad_request\"}"));
        return 0;
    }

    char *response = h2o_mem_alloc_pool(&req->pool, 256);
    uint32_t num_req = validate_add_count_token(token_raw);

    if (num_req == UINT32_MAX) {
        int len = snprintf(response, 256,
            "{\"Is_Correct\":false,\"reason\":\"invalid_token\"}");
        send_json_response(req, 403, response, (size_t)len);
        return 0;
    }

    if (num_req > MAX_COUNT) {
        int len = snprintf(response, 256,
            "{\"Is_Correct\":true,\"RequestLimit\":true,\"requests\":%u}", num_req);
        send_json_response(req, 429, response, (size_t)len);
        return 0;
    }

    int len = snprintf(response, 256,
        "{\"Is_Correct\":true,\"RequestLimit\":false,\"requests\":%u}", num_req);
    send_json_response(req, 200, response, (size_t)len);
    return 0;
}


/* --------------------------------------------------------------------------- */
/* 6. TLS setup                                                                */
/* --------------------------------------------------------------------------- */

static int setup_ssl_ctx(const char *cert_file, const char *key_file) {
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();

    g_ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!g_ssl_ctx) { fprintf(stderr, "SSL_CTX_new failed\n"); return -1; }

    SSL_CTX_set_options(g_ssl_ctx,
        SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
        SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 |
        SSL_OP_NO_COMPRESSION | SSL_OP_CIPHER_SERVER_PREFERENCE);

    SSL_CTX_set_session_cache_mode(g_ssl_ctx, SSL_SESS_CACHE_OFF);


    /* ✅ FIXED: use _chain_file to send the full cert chain (leaf + intermediate) */
    if (SSL_CTX_use_certificate_chain_file(g_ssl_ctx, cert_file) != 1) {
        fprintf(stderr, "Failed to load cert chain: %s\n", cert_file);
        ERR_print_errors_fp(stderr);   /* prints the OpenSSL error queue */
        return -1;
    }
    if (SSL_CTX_use_PrivateKey_file(g_ssl_ctx, key_file, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "Failed to load key: %s\n", key_file);
        ERR_print_errors_fp(stderr);
        return -1;
    }
    /* Sanity check: key must match the leaf cert */
    if (SSL_CTX_check_private_key(g_ssl_ctx) != 1) {
        fprintf(stderr, "Private key does not match certificate\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    #if H2O_USE_ALPN
        h2o_ssl_register_alpn_protocols(g_ssl_ctx, h2o_http2_alpn_protocols);
        fprintf(stderr, "HTTP/2 via ALPN registered\n");
    #else
    #  error "Compile with -DH2O_USE_ALPN=1"
    #endif

    ja4_init_ssl_ctx(g_ssl_ctx);
    fprintf(stderr, "JA4 fingerprinting initialized\n");

    return 0;
}


//ROBOTS
//robot of reseting ip rate limiting
static void cms_reset_cb(uv_timer_t *handle) {
    (void)handle;
    cms_reset();

}

static void tok_reset_cb(uv_timer_t *handle){
    (void)handle;
    tok_reset();

}

static void bloom_reset_cb(uv_timer_t *handle) {
    (void)handle;

    //double load = captcha_bloom_load();
    /* Hourly forced reset regardless, plus load is logged */
    captcha_bloom_reset();

}

// Add new signal handler
static void on_sighup(int signo) {
    (void)signo;
    reload_ssl_requested = 1;
}

// New function: atomically swap the SSL_CTX
static void reload_ssl_ctx_if_needed(void) {
    if (!reload_ssl_requested) return;
    reload_ssl_requested = 0;

    SSL_CTX *new_ctx = SSL_CTX_new(TLS_server_method());
    if (!new_ctx) {

        return;
    }

    SSL_CTX_set_options(new_ctx,
        SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
        SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 |
        SSL_OP_NO_COMPRESSION | SSL_OP_CIPHER_SERVER_PREFERENCE);
    SSL_CTX_set_session_cache_mode(new_ctx, SSL_SESS_CACHE_OFF);

    // ← USE TLS_CERT_FILE and TLS_KEY_FILE (with underscores — matches your #defines)
    if (SSL_CTX_use_certificate_chain_file(new_ctx, TLS_CERT_FILE) != 1) {

        SSL_CTX_free(new_ctx);
        return;
    }
    if (SSL_CTX_use_PrivateKey_file(new_ctx, TLS_KEY_FILE, SSL_FILETYPE_PEM) != 1) {

        SSL_CTX_free(new_ctx);
        return;
    }
    if (SSL_CTX_check_private_key(new_ctx) != 1) {

        SSL_CTX_free(new_ctx);
        return;
    }

    #if H2O_USE_ALPN
        h2o_ssl_register_alpn_protocols(new_ctx, h2o_http2_alpn_protocols);
    #endif
    ja4_init_ssl_ctx(new_ctx);

    SSL_CTX *old_ctx = g_ssl_ctx;
    __atomic_store_n(&g_ssl_ctx, new_ctx, __ATOMIC_SEQ_CST);
    sleep(5);
    SSL_CTX_free(old_ctx);


}

/* --------------------------------------------------------------------------- */
/* 7. libuv TCP accept & worker threads                                        */
/* --------------------------------------------------------------------------- */

static void on_accept(uv_stream_t *listener, int status) {
    if (status != 0) return;

    struct st_worker_t *worker = listener->data;
    uv_tcp_t *conn = h2o_mem_alloc(sizeof(*conn));
    uv_tcp_init(listener->loop, conn);

    if (uv_accept(listener, (uv_stream_t *)conn) != 0) {
        uv_close((uv_handle_t *)conn, (uv_close_cb)free);
        return;
    }

    uv_tcp_nodelay(conn, 1);
    uv_tcp_keepalive(conn, 0, 0);

    h2o_socket_t *sock = h2o_uv_socket_create((uv_stream_t *)conn,
                                                (uv_close_cb)free);
    h2o_accept(&worker->accept_ctx, sock);
}

static int create_listener(uv_loop_t *loop, int port,
                             uv_tcp_t *listener,
                             struct st_worker_t *worker) {
    int sockfd   = -1;
    int use_ipv6 = 1;

    /* ── 1. Try AF_INET6 dual-stack first ───────────────────────────────── */
    sockfd = socket(AF_INET6, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "Worker %d: AF_INET6 socket failed: %s — falling back to AF_INET\n",
                worker->worker_id, strerror(errno));
        use_ipv6 = 0;
    }

    if (use_ipv6) {
        /* Debian 13 / kernel 6.12 may enforce net.ipv6.conf.all.disable_ipv6 or
           net.ipv6.bindv6only=1 at kernel level.  If IPV6_V6ONLY=0 fails, we
           close this fd and fall through to a plain AF_INET socket rather than
           silently staying IPv6-only while claiming dual-stack coverage.        */
        int v6only = 0;
        if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY,
                       &v6only, sizeof(v6only)) != 0) {
            fprintf(stderr,
                    "Worker %d: IPV6_V6ONLY=0 failed (%s) — closing AF_INET6 fd, "
                    "retrying as AF_INET\n",
                    worker->worker_id, strerror(errno));
            close(sockfd);   /* ← BUG FIX: original left fd open on fallback */
            sockfd   = -1;
            use_ipv6 = 0;
        }
    }

    /* ── 2. AF_INET fallback ─────────────────────────────────────────────── */
    if (!use_ipv6) {
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            fprintf(stderr, "Worker %d: AF_INET socket failed: %s\n",
                    worker->worker_id, strerror(errno));
            return -1;
        }
    }

    /* ── 3. SO_REUSEADDR — must be set BEFORE bind, and checked ─────────── */
    /* BUG FIX: original ignored the return value */
    int optval = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
                   &optval, sizeof(optval)) != 0) {
        fprintf(stderr, "Worker %d: SO_REUSEADDR failed: %s\n",
                worker->worker_id, strerror(errno));
        close(sockfd);
        return -1;
    }

    /* ── 4. SO_REUSEPORT — required, checked ────────────────────────────── */
    #ifdef SO_REUSEPORT
        optval = 1;
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT,
                    &optval, sizeof(optval)) != 0) {
            fprintf(stderr, "Worker %d: SO_REUSEPORT failed: %s\n",
                    worker->worker_id, strerror(errno));
            close(sockfd);
            return -1;
        }
    #else
    #  error "SO_REUSEPORT is required on this platform"
    #endif

        /* ── 5. Optional performance knobs (non-fatal) ───────────────────────── */
    #ifdef TCP_FASTOPEN
        { int qlen = 256;
        if (setsockopt(sockfd, IPPROTO_TCP, TCP_FASTOPEN,
                        &qlen, sizeof(qlen)) != 0)
            fprintf(stderr, "Worker %d: TCP_FASTOPEN failed (non-fatal)\n",
                    worker->worker_id); }
    #endif

    #ifdef TCP_DEFER_ACCEPT
        { int timeout = 5;
        if (setsockopt(sockfd, IPPROTO_TCP, TCP_DEFER_ACCEPT,
                        &timeout, sizeof(timeout)) != 0)
            fprintf(stderr, "Worker %d: TCP_DEFER_ACCEPT failed (non-fatal)\n",
                    worker->worker_id); }
    #endif

    /* ── 6. Bind — two separate paths for IPv6 / IPv4 ───────────────────── */
    if (use_ipv6) {
        struct sockaddr_in6 addr = {0};
        addr.sin6_family = AF_INET6;
        addr.sin6_addr   = in6addr_any;
        addr.sin6_port   = htons((uint16_t)port);

        if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
            fprintf(stderr, "Worker %d: bind [::] failed: %s\n",
                    worker->worker_id, strerror(errno));
            close(sockfd);
            return -1;
        }
    } else {
        /* BUG FIX: original never had this branch — on Debian 13, after
           IPV6_V6ONLY fallback, we were left with no valid bind target.  */
        struct sockaddr_in addr = {0};
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port        = htons((uint16_t)port);

        if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
            fprintf(stderr, "Worker %d: bind 0.0.0.0 failed: %s\n",
                    worker->worker_id, strerror(errno));
            close(sockfd);
            return -1;
        }
    }

    /* ── 7. Non-blocking ─────────────────────────────────────────────────── */
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags < 0 || fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        fprintf(stderr, "Worker %d: fcntl failed: %s\n",
                worker->worker_id, strerror(errno));
        close(sockfd);
        return -1;
    }

    /* ── 8. Hand the raw fd to libuv ─────────────────────────────────────── */
    if (uv_tcp_init(loop, listener) != 0 ||
        uv_tcp_open(listener, sockfd) != 0) {
        fprintf(stderr, "Worker %d: uv_tcp_init/open failed\n",
                worker->worker_id);
        close(sockfd);   /* BUG FIX: original leaked fd here */
        return -1;
    }

    uv_tcp_nodelay(listener, 1);
    listener->data = worker;

    /* ── 9. Start listening ──────────────────────────────────────────────── */
    if (uv_listen((uv_stream_t *)listener, 4096, on_accept) != 0) {
        fprintf(stderr, "Worker %d: uv_listen failed\n",
                worker->worker_id);
        return -1;
    }

    fprintf(stderr, "Worker %d: listening on %s:%d (backlog=4096)\n",
            worker->worker_id,
            use_ipv6 ? "[::]" : "0.0.0.0",
            port);
    return 0;
}

static void ssl_reload_timer_cb(uv_timer_t *handle) {
    (void)handle;
    reload_ssl_ctx_if_needed();
}

static void *run_worker(void *arg) {
    struct st_worker_t *worker = arg;
    uv_tcp_t listener;

    #ifdef __linux__
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        int core_id = WORKER_CORE_START + (worker->worker_id % WORKER_THREADS);
        CPU_SET(core_id, &cpuset);
        pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
        printf("Worker %d: pinned to core %d\n", worker->worker_id, core_id);
    #endif

    worker->loop = uv_loop_new();
    h2o_context_init(&worker->ctx, worker->loop, &config);

    uv_timer_t cms_timer;
    if (worker->worker_id == 0) {
        uv_timer_init(worker->loop, &cms_timer);
        uv_timer_start(&cms_timer, cms_reset_cb,
                       (uint64_t)CMS_RESET_SEC * 1000,
                       (uint64_t)CMS_RESET_SEC * 1000);
    }

    uv_timer_t tok_timer;
    if (worker->worker_id == 0) {
        uv_timer_init(worker->loop, &tok_timer);
        uv_timer_start(&tok_timer, tok_reset_cb,
                       (uint64_t)TOK_RESET_SEC * 1000,
                       (uint64_t)TOK_RESET_SEC * 1000);
    }

    uv_timer_t bloom_timer;
    if (worker->worker_id == 0) {
        uv_timer_init(worker->loop, &bloom_timer);
        uv_timer_start(&bloom_timer, bloom_reset_cb,
                       3600ULL * 1000,
                       3600ULL * 1000);
    }

    uv_timer_t udp_timer;
    if (worker->worker_id == 0) {
        uv_timer_init(worker->loop, &udp_timer);
        uv_timer_start(&udp_timer, udp_flush_timer_cb,
                       UDP_FLUSH_MS, UDP_FLUSH_MS);
    }

    uv_timer_t ssl_reload_timer;
    if (worker->worker_id == 0) {
        uv_timer_init(worker->loop, &ssl_reload_timer);
        uv_timer_start(&ssl_reload_timer, ssl_reload_timer_cb, 60000, 60000);
    }

    memset(&worker->accept_ctx, 0, sizeof(worker->accept_ctx));
    worker->accept_ctx.ctx     = &worker->ctx;
    worker->accept_ctx.hosts   = config.hosts;
    worker->accept_ctx.ssl_ctx = g_ssl_ctx;

    if (create_listener(worker->loop, SERVER_PORT,
                        &listener, worker) != 0) {
        fprintf(stderr, "Worker %d failed to create listener\n",
                worker->worker_id);
        return NULL;
    }

    printf("Worker %d ready\n", worker->worker_id);
    while (!shutdown_requested)
        uv_run(worker->loop, UV_RUN_DEFAULT);

    printf("Worker %d shutting down\n", worker->worker_id);
    return NULL;
}


/* --------------------------------------------------------------------------- */
/* Signal handlers                                                             */
/* --------------------------------------------------------------------------- */

static void on_sigterm(int signo) { (void)signo; shutdown_requested = 1; }


/* --------------------------------------------------------------------------- */
/* main                                                                        */
/* --------------------------------------------------------------------------- */

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, on_sigterm);
    signal(SIGINT,  on_sigterm);
    signal(SIGHUP, on_sighup);


    printf("\n");
    printf("╔══════════════════════════════════════╗\n");
    printf("║   CAPTCHA SERVER — SIMPLE + COMPLEX  ║\n");
    printf("╚══════════════════════════════════════╝\n\n");

    /* TLS */
    if (setup_ssl_ctx(TLS_CERT_FILE, TLS_KEY_FILE) != 0) {
        fprintf(stderr, "Failed to initialize TLS\n"); return 1;
    }

    /* Challenge-token encryption key (ephemeral) */
    if (RAND_bytes(g_challenge_key, sizeof(g_challenge_key)) != 1) {
        fprintf(stderr, "FATAL: failed to generate challenge key\n"); return 1;
    }
    fprintf(stderr, "Challenge encryption key generated (32 B, ephemeral)\n");

    /* Captcha image/puzzle engine */
    if (!captcha_system_init(NULL, WORKER_THREADS)) {
        fprintf(stderr, "ERROR: failed to initialize CAPTCHA system\n"); return 1;
    }

    if (ip_bloom_init() < 0) {
        fprintf(stderr, "ERROR: IP bloom filter init failed\n");
        return 1;
    }
    ip_bloom_start_rotation_thread();

    /* Ed25519 signing key for pass tokens */
    if (!token_init()) {
        fprintf(stderr, "Token init failed, aborting\n"); return 1;
    }
    initUdpClient(LOGS_SERVER_IP,LOGS_SERVER_PORT);

    /* H2O global config */
    h2o_config_init(&config);
    config.http2.max_concurrent_requests_per_connection = 4;
    config.http2.idle_timeout   = 8000;   /* 8 s */
    config.http1.req_timeout    = 5000;   /* 5 s */


    h2o_hostconf_t *host = h2o_config_register_host(
        &config, h2o_iovec_init(H2O_STRLIT("default")), 65535);

    h2o_pathconf_t *path;
    h2o_handler_t  *handler;

#define ROUTE(uri, fn) \
    path = h2o_config_register_path(host, uri, 0); \
    handler = h2o_create_handler(path, sizeof(*handler)); \
    handler->on_req = (fn);

    ROUTE("/challenge/simp",    handle_challenge_simp)
    ROUTE("/solve/simp",        handle_solve_simp)
    ROUTE("/challenge/complex", handle_challenge_complex)
    ROUTE("/solve/complex",     handle_solve_complex)
    ROUTE("/api/validate",       handle_validate)
#undef ROUTE

    /* Static files */
    h2o_pathconf_t *root = h2o_config_register_path(host, "/", 0);
    h2o_file_register(root, "/var/www/html", NULL, NULL, 0);

    printf("Configuration:\n");
    printf("  Port:         %d\n", SERVER_PORT);
    printf("  Workers:      %d\n", WORKER_THREADS);
    printf("  PoW simple:   %d bits  complex: %d bits\n",
           POW_DIFFICULTY_SIMPLE, POW_DIFFICULTY_COMPLEX);
    printf("  Token TTL:    %d s\n\n", CHALLENGE_MAX_AGE_SECS);

    /* Spawn workers */
    struct st_worker_t workers[WORKER_THREADS];
    for (int i = 0; i < WORKER_THREADS; i++) {
        workers[i].worker_id = i;
        if (pthread_create(&workers[i].tid, NULL, run_worker, &workers[i]) != 0) {
            fprintf(stderr, "Failed to create worker %d\n", i); return 1;
        }
        usleep(100000); /* staggered startup */
    }
    printf("All %d workers active\n", WORKER_THREADS);

    for (int i = 0; i < WORKER_THREADS; i++)
        pthread_join(workers[i].tid, NULL);

    printf("Server shutdown complete\n");
    captcha_system_destroy();
    token_cleanup();
    cleanupUdp();
    flush_udp_batch();
    return 0;
}
