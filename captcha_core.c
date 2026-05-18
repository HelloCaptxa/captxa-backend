/* =============================================================================
 * captcha_core.c  —  On-demand hybrid CAPTCHA engine
 *
 * Sections (in order):
 *   1. Includes & compile-time constants
 *   2. Global state & thread-local storage
 *   3. Fast PRNG  (Xoshiro256**)
 *   4. Cryptographic helpers  (ChaCha20-Poly1305, SHA-256 pool)
 *   5. Bloom filter  (replay-attack prevention)
 *   6. Image pool  (base images in RAM)
 *   7. Puzzle mask templates  (precomputed at startup)
 *   8. Sliding-puzzle generation
 *   9. Proof-of-Work  (challenge + verify)
 *  10. CPU topology detection
 *  11. GeoIP / timezone helpers
 *  12. Trajectory analysis
 *      12a. Integrity filters  (I4 / I6 / I7)
 *      12b. Fitts' Law
 *      12c. Burstiness  (Goh & Barabási 2008)
 *      12d. Sample-entropy / jerk
 *      12e. Velocity CV
 *      12f. Final feature checks  (F4)
 *  13. Bot detector
 *  14. Public API
 * ============================================================================= */

/* --------------------------------------------------------------------------- */
/* 1. Includes & compile-time constants                                         */
/* --------------------------------------------------------------------------- */

#include "captcha_core.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <time.h>
#include <math.h>
#include <float.h>
#include <ctype.h>

#include <openssl/rand.h>
#include <openssl/evp.h>

#include <turbojpeg.h>
#include <gd.h>
#include <maxminddb.h>

#include <dirent.h>

#ifdef __linux__
#  include <unistd.h>
#endif
#ifdef __APPLE__
#  include <sys/sysctl.h>
#endif

#define NUM_MASK_TEMPLATES   5
#define MAX_JPEG_SIZE        (150 * 1024)
#define MAX_BOT_SCORE 5
#define RELOAD_GRACE_US  500000

/* --------------------------------------------------------------------------- */
/* 2. Global state & thread-local storage                                       */
/* --------------------------------------------------------------------------- */

captcha_system_t  *g_system           = NULL;
cpu_topology_t     g_cpu_topology     = { .total_cores = 0 };
MMDB_s             g_mmdb;

static image_pool_t g_image_pool  = { .loaded = false };

/* Background reload state */
static _Atomic int     g_reload_running  = 0;
static char            g_image_dir[512]  = {0};

/* Flat list of all .jpg paths discovered at startup */
static char            g_image_filenames[MAX_IMAGE_FILES][512];
static int             g_image_file_count = 0;
static pthread_mutex_t g_filelist_mutex   = PTHREAD_MUTEX_INITIALIZER;

/* Mask templates – filled once at startup */
static uint8_t  g_mask_templates[NUM_MASK_TEMPLATES][PUZZLE_PIECE_SIZE * PUZZLE_PIECE_SIZE];
static bool     g_masks_initialized  = false;

/* Per-thread OpenSSL contexts (lazy-initialised, never freed – h2o thread lifetime) */
static __thread EVP_CIPHER_CTX *tls_encrypt_ctx    = NULL;
static __thread EVP_CIPHER_CTX *tls_decrypt_ctx    = NULL;

/* Per-thread TurboJPEG handle */
static __thread tjhandle             tls_tj_handle        = NULL;
static __thread uint8_t              tls_jpeg_background[MAX_JPEG_SIZE];
static __thread uint8_t              tls_jpeg_piece[MAX_JPEG_SIZE];

/* Per-thread image buffers (reused per request, zero heap allocation) */
_Thread_local static uint8_t tls_background[BASE_IMAGE_WIDTH * BASE_IMAGE_HEIGHT * 4];
_Thread_local static uint8_t tls_piece[PUZZLE_PIECE_SIZE * PUZZLE_PIECE_SIZE * 4];

/* Per-thread Xoshiro256** state */
static __thread xoshiro256_state_t tls_prng_state;
static __thread bool               tls_prng_initialized = false;

/* Per-thread cryptographic random pool (1 MB, refilled on exhaustion) */
static __thread struct {
    unsigned char pool[1024 * 1024];
    size_t        offset;
    bool          initialized;
} tls_random_pool = { .initialized = false };

/* --------------------------------------------------------------------------- */
/* 3. Fast PRNG — Xoshiro256**                                                  */
/* --------------------------------------------------------------------------- */

static inline uint64_t rotl(const uint64_t x, int k) {
    return (x << k) | (x >> (64 - k));
}

static uint64_t xoshiro256_next(xoshiro256_state_t *state) {
    const uint64_t result = rotl(state->s[1] * 5, 7) * 9;
    const uint64_t t      = state->s[1] << 17;

    state->s[2] ^= state->s[0];
    state->s[3] ^= state->s[1];
    state->s[1] ^= state->s[2];
    state->s[0] ^= state->s[3];
    state->s[2] ^= t;
    state->s[3]  = rotl(state->s[3], 45);

    return result;
}

static void xoshiro256_init(xoshiro256_state_t *state) {
    unsigned char seed[32];
    RAND_bytes(seed, 32);
    memcpy(state->s, seed, 32);
}

static inline uint64_t get_fast_random(void) {
    if (!tls_prng_initialized) {
        xoshiro256_init(&tls_prng_state);
        tls_prng_initialized = true;
    }
    return xoshiro256_next(&tls_prng_state);
}

/* --------------------------------------------------------------------------- */
/* 4. Cryptographic helpers                                                      */
/* --------------------------------------------------------------------------- */

/* Refill-on-demand random byte pool (avoids frequent RAND_bytes syscalls) */
static void get_crypto_random(uint8_t *out, size_t len) {
    if (!tls_random_pool.initialized ||
        tls_random_pool.offset + len > sizeof(tls_random_pool.pool)) {
        RAND_bytes(tls_random_pool.pool, sizeof(tls_random_pool.pool));
        tls_random_pool.offset      = 0;
        tls_random_pool.initialized = true;
    }
    memcpy(out, &tls_random_pool.pool[tls_random_pool.offset], len);
    tls_random_pool.offset += len;
}

/* ChaCha20-Poly1305 encrypt.  nonce_out must be 12 bytes. */
static bool encrypt_token(const unsigned char *key,
                           const void *plaintext, size_t pt_len,
                           unsigned char *ciphertext, size_t *ct_len,
                           unsigned char *nonce_out) {
    if (!tls_encrypt_ctx) {
        tls_encrypt_ctx = EVP_CIPHER_CTX_new();
        if (!tls_encrypt_ctx) return false;
    }

    if (RAND_bytes(nonce_out, 12) != 1) return false;

    int len;
    if (EVP_EncryptInit_ex(tls_encrypt_ctx, EVP_chacha20_poly1305(),
                           NULL, key, nonce_out) != 1) return false;
    if (EVP_EncryptUpdate(tls_encrypt_ctx, ciphertext, &len,
                          plaintext, (int)pt_len) != 1) return false;
    *ct_len = (size_t)len;
    if (EVP_EncryptFinal_ex(tls_encrypt_ctx, ciphertext + len, &len) != 1) return false;
    *ct_len += (size_t)len;
    if (EVP_CIPHER_CTX_ctrl(tls_encrypt_ctx, EVP_CTRL_AEAD_GET_TAG,
                             16, ciphertext + *ct_len) != 1) return false;
    *ct_len += 16;
    return true;
}

/* ChaCha20-Poly1305 decrypt.  nonce must be 12 bytes. */
static bool decrypt_token(const unsigned char *key,
                           const unsigned char *ciphertext, size_t ct_len,
                           unsigned char *plaintext, size_t *pt_len,
                           const unsigned char *nonce) {
    if (ct_len < 16) return false;

    if (!tls_decrypt_ctx) {
        tls_decrypt_ctx = EVP_CIPHER_CTX_new();
        if (!tls_decrypt_ctx) return false;
    }

    size_t data_len          = ct_len - 16;
    const unsigned char *tag = ciphertext + data_len;

    int len;
    if (EVP_DecryptInit_ex(tls_decrypt_ctx, EVP_chacha20_poly1305(),
                           NULL, key, nonce) != 1) return false;
    if (EVP_CIPHER_CTX_ctrl(tls_decrypt_ctx, EVP_CTRL_AEAD_SET_TAG,
                             16, (void *)tag) != 1) return false;
    if (EVP_DecryptUpdate(tls_decrypt_ctx, plaintext, &len,
                          ciphertext, (int)data_len) != 1) return false;
    *pt_len = (size_t)len;
    if (EVP_DecryptFinal_ex(tls_decrypt_ctx, plaintext + len, &len) != 1) return false;
    *pt_len += (size_t)len;
    return true;
}

/* OpenSSL 3.x compatible SHA-256 (EVP, no deprecated SHA256() call) */
static inline void sha256_hash(const uint8_t *data, size_t len, uint8_t *out) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1) {
        EVP_DigestUpdate(ctx, data, len);
        EVP_DigestFinal_ex(ctx, out, NULL);
    }
    EVP_MD_CTX_free(ctx);
}

/* --------------------------------------------------------------------------- */
/* 5. Bloom filter — replay-attack prevention                                   */
/* --------------------------------------------------------------------------- */

/* FNV-1a variant seeded for multiple hash functions */
static inline uint64_t bloom_hash(const unsigned char *data, size_t len,
                                   uint32_t seed) {
    uint64_t h = 14695981039346656037ULL + seed;
    for (size_t i = 0; i < len; i++) {
        h ^= data[i];
        h *= 1099511628211ULL;
    }
    return h;
}

bool bloom_check_and_add(const unsigned char *token, size_t token_len) {
    /* Read active slot once — stays consistent for this whole call */
    int slot = atomic_load_explicit(&g_system->bloom_active, memory_order_acquire);
    bloom_entry_t *bf = g_system->bloom[slot];

    bool found = true;
    for (int i = 0; i < BLOOM_HASH_FUNCTIONS; i++) {
        uint64_t idx = bloom_hash(token, token_len, (uint32_t)i) % BLOOM_FILTER_SIZE;
        if (atomic_load(&bf[idx].count) == 0) {
            found = false;
            break;
        }
    }

    if (!found) {
        for (int i = 0; i < BLOOM_HASH_FUNCTIONS; i++) {
            uint64_t h   = bloom_hash(token, token_len, (uint32_t)i);
            uint64_t idx = h % BLOOM_FILTER_SIZE;
            uint8_t old;
            do {
                old = atomic_load(&bf[idx].count);
                if (old == 255) break;
            } while (!atomic_compare_exchange_weak(&bf[idx].count, &old, old + 1));

            if (old == 0) {
                bf[idx].hash_sample = h;
                /* Track occupied slots — used for load check below */
                atomic_fetch_add_explicit(&g_system->bloom_occupied[slot],
                                          1, memory_order_relaxed);
            }
        }

        uint64_t occupied = atomic_load_explicit(&g_system->bloom_occupied[slot],
                                                  memory_order_relaxed);
        if ((occupied & 127) == 0 && (occupied >= (uint64_t)(BLOOM_FILTER_SIZE * 0.60))) { // 60% RESET BLOOM FILTER
            int expected = 0;
            if (atomic_compare_exchange_strong(&g_system->bloom_reset_running,
                                               &expected, 1)) {
                captcha_bloom_reset();
                atomic_store(&g_system->bloom_reset_running, 0);
            }
        }
    }

    return found; /* true = already seen (replay) */
}

void captcha_bloom_reset(void) {
    if (!g_system) return;

    int current = atomic_load_explicit(&g_system->bloom_active,
                                        memory_order_acquire);
    int next = 1 - current;

    memset(g_system->bloom[next], 0, BLOOM_FILTER_SIZE * sizeof(bloom_entry_t));
    atomic_store_explicit(&g_system->bloom_occupied[next], 0,
                           memory_order_relaxed);

    /* Step 2: publish the switch — seq_cst ensures all threads see it */
    atomic_store_explicit(&g_system->bloom_active, next,
                           memory_order_seq_cst);

}

double captcha_bloom_load(void) {
    if (!g_system) return 0.0;
    int slot = atomic_load_explicit(&g_system->bloom_active, memory_order_acquire);
    return (double)atomic_load(&g_system->bloom_occupied[slot])
           / (double)BLOOM_FILTER_SIZE;
}

/* --------------------------------------------------------------------------- */
/* 6. Image pool — double-buffer hot-swap, 200 random images per bank          */
/* --------------------------------------------------------------------------- */

/* Scan image_dir and populate g_image_filenames[].
 * Thread-safe (mutex protected). Returns file count found. */
static int scan_image_directory(const char *dir) {
    pthread_mutex_lock(&g_filelist_mutex);
    g_image_file_count = 0;

    DIR *d = opendir(dir);
    if (!d) {

        pthread_mutex_unlock(&g_filelist_mutex);
        return 0;
    }

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL && g_image_file_count < MAX_IMAGE_FILES) {
        const char *name = ent->d_name;
        size_t nlen = strlen(name);
        if (nlen < 5) continue;

        /* Accept *.jpg and *.jpeg (case-insensitive) */
        const char *ext4 = name + nlen - 4;
        const char *ext5 = (nlen > 4) ? name + nlen - 5 : name;
        if (strcasecmp(ext4, ".jpg") != 0 && strcasecmp(ext5, ".jpeg") != 0)
            continue;

        snprintf(g_image_filenames[g_image_file_count],
                 sizeof(g_image_filenames[0]),
                 "%s/%s", dir, name);
        g_image_file_count++;
    }
    closedir(d);

    pthread_mutex_unlock(&g_filelist_mutex);
    return g_image_file_count;
}

/* In-place Fisher-Yates shuffle on an integer index array. */
static void shuffle_indices(int *arr, int n) {
    for (int i = n - 1; i > 0; i--) {
        int j = (int)(get_fast_random() % (uint64_t)(i + 1));
        int tmp = arr[i]; arr[i] = arr[j]; arr[j] = tmp;
    }
}

/* Decode a single JPEG file at `path` into a newly malloc'd RGBA buffer.
 * Returns the buffer on success (caller must free), NULL on error. */
static uint8_t *decode_jpeg_to_rgba(const char *path, size_t *out_size) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;

    gdImagePtr img = gdImageCreateFromJpeg(fp);
    fclose(fp);
    if (!img) {

        return NULL;
    }
    if (gdImageSX(img) != BASE_IMAGE_WIDTH || gdImageSY(img) != BASE_IMAGE_HEIGHT) {

        gdImageDestroy(img);
        return NULL;
    }

    size_t raw_size = (size_t)(BASE_IMAGE_WIDTH * BASE_IMAGE_HEIGHT * 4);
    uint8_t *raw = malloc(raw_size);
    if (!raw) { gdImageDestroy(img); return NULL; }

    for (int y = 0; y < BASE_IMAGE_HEIGHT; y++) {
        for (int x = 0; x < BASE_IMAGE_WIDTH; x++) {
            int color = gdImageGetPixel(img, x, y);
            int idx   = (y * BASE_IMAGE_WIDTH + x) * 4;
            raw[idx+0] = (uint8_t)gdImageRed  (img, color);
            raw[idx+1] = (uint8_t)gdImageGreen(img, color);
            raw[idx+2] = (uint8_t)gdImageBlue (img, color);
            raw[idx+3] = (uint8_t)(255 - gdImageAlpha(img, color) * 2);
        }
    }
    gdImageDestroy(img);
    *out_size = raw_size;
    return raw;
}

/* Fill `bank` with up to NUM_BASE_IMAGES randomly selected images
 * from g_image_filenames[]. Returns true if at least 1 loaded. */
static bool load_bank(image_bank_t *bank) {
    bank->count = 0;

    if (g_image_file_count == 0) {
        fprintf(stderr, "g_image_file_count == 0 failed\n");
        return false;
    }

    int total    = g_image_file_count;
    int to_load  = (total < NUM_BASE_IMAGES) ? total : NUM_BASE_IMAGES;

    /* Build a shuffled index list so we pick randomly without repetition */
    int *indices = malloc((size_t)total * sizeof(int));
    if (!indices){
        fprintf(stderr, "indices failed\n");
        return false;
    }
    for (int i = 0; i < total; i++) indices[i] = i;
    shuffle_indices(indices, total);

    int loaded = 0;
    for (int slot = 0; slot < to_load && loaded < NUM_BASE_IMAGES; slot++) {
        size_t raw_size = 0;
        uint8_t *raw = decode_jpeg_to_rgba(g_image_filenames[indices[slot]], &raw_size);
        if (!raw) continue;          /* skip bad files, try next */
        bank->images[loaded] = raw;
        bank->sizes [loaded] = raw_size;
        loaded++;
    }
    free(indices);

    bank->count = loaded;

    return loaded > 0;
}

/* Free all RGBA buffers inside a bank (call only after it is no longer active). */
static void free_bank(image_bank_t *bank) {
    for (int i = 0; i < bank->count; i++) {
        free(bank->images[i]);
        bank->images[i] = NULL;
    }
    bank->count = 0;
}

/* ---- Background hot-swap thread ------------------------------------------ */

typedef struct { int old_bank; } reload_args_t;

/* Detached thread: fills the idle bank, flips the active pointer,
 * then frees the old bank after RELOAD_GRACE_US microseconds. */
static void *reload_thread_func(void *arg) {
    reload_args_t *ra       = (reload_args_t *)arg;
    int            old_bank = ra->old_bank;
    int            new_bank = 1 - old_bank;
    free(ra);

    if (!load_bank(&g_image_pool.banks[new_bank])) {

        atomic_store(&g_reload_running, 0);
        return NULL;
    }

    /* Publish the new bank atomically — all threads see it immediately */
    atomic_store_explicit(&g_image_pool.active, new_bank, memory_order_release);

    /* Grace period: let any in-flight generate_sliding_puzzle() calls that
     * loaded the old base_img pointer finish their pixel work. 500 ms is
     * several orders of magnitude more than the function's runtime. */
    usleep(RELOAD_GRACE_US);

    free_bank(&g_image_pool.banks[old_bank]);

    atomic_store(&g_reload_running, 0);
    return NULL;
}

/* Spawn the background reload thread (no-op if one is already running).
 * Uses compare-exchange so only one reload ever runs at a time. */
static void trigger_pool_reload(void) {
    int expected = 0;
    if (!atomic_compare_exchange_strong_explicit(
            &g_reload_running, &expected, 1,
            memory_order_acq_rel, memory_order_relaxed)) {
        return;  /* reload already in progress */
    }

    reload_args_t *ra = malloc(sizeof(*ra));
    if (!ra) {
        atomic_store(&g_reload_running, 0);
        return;
    }
    ra->old_bank = atomic_load_explicit(&g_image_pool.active, memory_order_acquire);

    pthread_t        tid;
    pthread_attr_t   attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    if (pthread_create(&tid, &attr, reload_thread_func, ra) != 0) {

        free(ra);
        atomic_store(&g_reload_running, 0);
    }
    pthread_attr_destroy(&attr);
}

/* --------------------------------------------------------------------------- */
/* Public API: load_image_pool / destroy_image_pool                            */
/* --------------------------------------------------------------------------- */

bool load_image_pool(const char *image_dir) {
    /* Remember dir for subsequent background reloads */
    strncpy(g_image_dir, image_dir, sizeof(g_image_dir) - 1);
    g_image_dir[sizeof(g_image_dir) - 1] = '\0';

    if (scan_image_directory(image_dir) == 0) {
        fprintf(stderr, "scan_image_directory(image_dir) == 0\n");
        return false;
    }

    /* Load initial set into bank 0 */
    if (!load_bank(&g_image_pool.banks[0])) {
        fprintf(stderr, "!load_bank(&g_image_pool.banks[0] failed\n");
        return false;
    }

    /* Bank 1 starts empty */
    memset(&g_image_pool.banks[1], 0, sizeof(image_bank_t));

    atomic_store(&g_image_pool.active, 0);
    g_image_pool.loaded = true;

    return true;
}

void destroy_image_pool(void) {
    free_bank(&g_image_pool.banks[0]);
    free_bank(&g_image_pool.banks[1]);
    g_image_pool.loaded = false;
}

/* --------------------------------------------------------------------------- */
/* 7. Puzzle mask templates — precomputed polar-distorted circles               */
/* --------------------------------------------------------------------------- */

static void precompute_mask_templates(void) {
    const int center_x = PUZZLE_PIECE_SIZE / 2;
    const int center_y = PUZZLE_PIECE_SIZE / 2;

    for (int t = 0; t < NUM_MASK_TEMPLATES; t++) {
        uint8_t *mask         = g_mask_templates[t];
        float    shape_var    = 0.85f + (t * 0.06f);
        int      num_notches  = 2 + (t % 3);
        float    notch_freq   = 2.5f + (float)(t % 3);
        float    notch_depth  = 3.0f + (float)(t % 3);

        for (int y = 0; y < PUZZLE_PIECE_SIZE; y++) {
            for (int x = 0; x < PUZZLE_PIECE_SIZE; x++) {
                int   dx    = x - center_x;
                int   dy    = y - center_y;
                float dist  = sqrtf((float)(dx*dx + dy*dy));
                float angle = atan2f((float)dy, (float)dx);
                float base_r = PUZZLE_PIECE_SIZE / 2.3f;
                float mod;

                switch (t % 5) {
                    case 0: mod = sinf(angle * notch_freq) * notch_depth; break;
                    case 1: mod = sinf(angle * 4.0f) * 2.0f + cosf(angle * notch_freq) * notch_depth; break;
                    case 2: mod = sinf(angle * (float)num_notches) * 4.0f; break;
                    case 3: mod = sinf(angle * 3.0f + 0.5f) * 2.5f + cosf(angle * 5.0f) * 2.0f; break;
                    default: mod = sinf(angle * 4.0f) * (((int)(angle * 2.0f / 3.14159f) % 2 == 0) ? 5.0f : -5.0f); break;
                }

                float r = base_r * shape_var + mod;
                if      (dist < r - 1.5f) mask[y * PUZZLE_PIECE_SIZE + x] = 255;
                else if (dist < r + 1.5f) mask[y * PUZZLE_PIECE_SIZE + x] =
                    (uint8_t)fmaxf(0.0f, fminf(255.0f, (r - dist + 1.5f) * 85.0f));
                else                      mask[y * PUZZLE_PIECE_SIZE + x] = 0;
            }
        }
    }

    g_masks_initialized = true;

}

/* --------------------------------------------------------------------------- */
/* 8. Sliding-puzzle generation                                                 */
/* --------------------------------------------------------------------------- */

bool generate_sliding_puzzle(puzzle_metadata_t *meta) {
    if (!g_image_pool.loaded || !g_masks_initialized) return false;

    /* NEW — reads from whichever bank is currently live */
    int           _bank       = atomic_load_explicit(&g_image_pool.active,memory_order_acquire);
    image_bank_t *_active_bank = &g_image_pool.banks[_bank];
    uint8_t      *base_img    = _active_bank->images[get_fast_random() % (uint64_t)_active_bank->count];
    uint16_t min_x = (uint16_t)(BASE_IMAGE_WIDTH * 0.4f);
    uint16_t max_x = (uint16_t)(BASE_IMAGE_WIDTH - PUZZLE_PIECE_SIZE);
    uint16_t range_x = max_x - min_x;
    uint16_t piece_x = (uint16_t)((get_fast_random() % range_x) + min_x);

    uint16_t piece_y     = (uint16_t)((get_fast_random() % (BASE_IMAGE_HEIGHT - PUZZLE_PIECE_SIZE - 40)) + 20);

    int      tmpl        = (int)(get_fast_random() % NUM_MASK_TEMPLATES);
    const uint8_t *mask  = g_mask_templates[tmpl];

    /* Background = full base image copy */
    memcpy(tls_background, base_img, (size_t)(BASE_IMAGE_WIDTH * BASE_IMAGE_HEIGHT * 4));

    /* --- Extract piece pixels (with soft edge from mask) --- */
    memset(tls_piece, 0, (size_t)(PUZZLE_PIECE_SIZE * PUZZLE_PIECE_SIZE * 4));
    for (int y = 0; y < PUZZLE_PIECE_SIZE; y++) {
        for (int x = 0; x < PUZZLE_PIECE_SIZE; x++) {
            uint8_t mv = mask[y * PUZZLE_PIECE_SIZE + x];
            if (mv == 0) continue;
            int src = ((piece_y + y) * BASE_IMAGE_WIDTH + piece_x + x) * 4;
            int dst = (y * PUZZLE_PIECE_SIZE + x) * 4;
            if (mv == 255) {
                *(uint32_t *)&tls_piece[dst] = *(uint32_t *)&base_img[src];
            } else {
                float a = mv / 255.0f;
                tls_piece[dst+0] = (uint8_t)(base_img[src+0] * a + 255.0f * (1.0f - a));
                tls_piece[dst+1] = (uint8_t)(base_img[src+1] * a + 255.0f * (1.0f - a));
                tls_piece[dst+2] = (uint8_t)(base_img[src+2] * a + 255.0f * (1.0f - a));
                tls_piece[dst+3] = mv;
            }
        }
    }

    /* --- Cutout in background: donor texture + radial gradient shadow --- */
    uint16_t donor_x  = (uint16_t)(get_fast_random() % (BASE_IMAGE_WIDTH  - PUZZLE_PIECE_SIZE));
    uint16_t donor_y  = (uint16_t)(get_fast_random() % (BASE_IMAGE_HEIGHT - PUZZLE_PIECE_SIZE));
    int      cx       = PUZZLE_PIECE_SIZE / 2;
    int      cy       = PUZZLE_PIECE_SIZE / 2;
    float    max_dist = PUZZLE_PIECE_SIZE / 2.3f;

    for (int y = 0; y < PUZZLE_PIECE_SIZE; y++) {
        for (int x = 0; x < PUZZLE_PIECE_SIZE; x++) {
            if (mask[y * PUZZLE_PIECE_SIZE + x] <= 50) continue;
            int   bg_i    = ((piece_y + y) * BASE_IMAGE_WIDTH + piece_x + x) * 4;
            int   don_i   = ((donor_y + y) * BASE_IMAGE_WIDTH + donor_x + x) * 4;
            float d       = sqrtf((float)((x-cx)*(x-cx) + (y-cy)*(y-cy)));
            float depth   = 1.0f - fminf(1.0f, d / max_dist);
            float darken  = 0.30f + depth * 0.25f;
            tls_background[bg_i+0] = (uint8_t)(base_img[don_i+0] * darken);
            tls_background[bg_i+1] = (uint8_t)(base_img[don_i+1] * darken);
            tls_background[bg_i+2] = (uint8_t)(base_img[don_i+2] * darken);
            tls_background[bg_i+3] = 255;
        }
    }

    /* --- Edge darkening on background cutout --- */
    for (int y = 0; y < PUZZLE_PIECE_SIZE; y++) {
        for (int x = 0; x < PUZZLE_PIECE_SIZE; x++) {
            if (mask[y * PUZZLE_PIECE_SIZE + x] <= 200) continue;
            bool is_edge = false;
            for (int dy = -1; dy <= 1 && !is_edge; dy++) {
                for (int dx = -1; dx <= 1 && !is_edge; dx++) {
                    int nx = x + dx, ny = y + dy;
                    if (nx >= 0 && nx < PUZZLE_PIECE_SIZE &&
                        ny >= 0 && ny < PUZZLE_PIECE_SIZE &&
                        mask[ny * PUZZLE_PIECE_SIZE + nx] < 50)
                        is_edge = true;
                }
            }
            if (is_edge) {
                int bi = ((piece_y + y) * BASE_IMAGE_WIDTH + piece_x + x) * 4;
                tls_background[bi+0] = (uint8_t)(tls_background[bi+0] * 0.5f);
                tls_background[bi+1] = (uint8_t)(tls_background[bi+1] * 0.5f);
                tls_background[bi+2] = (uint8_t)(tls_background[bi+2] * 0.5f);
            }
        }
    }

    /* --- Decoy shadow (anti-bot confusion) --- */
    uint16_t decoy_x = (uint16_t)((get_fast_random() % (BASE_IMAGE_WIDTH  - PUZZLE_PIECE_SIZE - 40)) + 20);
    uint16_t decoy_y = (uint16_t)((get_fast_random() % (BASE_IMAGE_HEIGHT - PUZZLE_PIECE_SIZE - 40)) + 20);
    if (abs((int)decoy_x - piece_x) > (int)(PUZZLE_PIECE_SIZE * 1.3f) ||
        abs((int)decoy_y - piece_y) > (int)(PUZZLE_PIECE_SIZE * 1.3f)) {
        int   ds  = (int)(PUZZLE_PIECE_SIZE * 0.65f);
        int   dc  = ds / 2;
        float rad = ds / 2.5f;
        for (int y = 0; y < ds; y++) {
            for (int x = 0; x < ds; x++) {
                float d = sqrtf((float)((x-dc)*(x-dc) + (y-dc)*(y-dc)));
                if (d >= rad) continue;
                int ix = decoy_x + x, iy = decoy_y + y;
                if (ix < 0 || ix >= BASE_IMAGE_WIDTH || iy < 0 || iy >= BASE_IMAGE_HEIGHT) continue;
                int   idx    = (iy * BASE_IMAGE_WIDTH + ix) * 4;
                float darken = 0.25f + (1.0f - d / rad) * 0.20f;
                tls_background[idx+0] = (uint8_t)(tls_background[idx+0] * darken);
                tls_background[idx+1] = (uint8_t)(tls_background[idx+1] * darken);
                tls_background[idx+2] = (uint8_t)(tls_background[idx+2] * darken);
            }
        }
    }

    /* --- Subtle pixel noise --- */
    for (int i = 0; i < 50; i++) {
        uint64_t noise = get_fast_random();
        int nx  = (int)(noise % BASE_IMAGE_WIDTH);
        int ny  = (int)((noise >> 16) % BASE_IMAGE_HEIGHT);
        int idx = (ny * BASE_IMAGE_WIDTH + nx) * 4;
        int8_t delta = (int8_t)(((noise >> 32) % 16) - 8);
        tls_background[idx+0] = (uint8_t)fmaxf(0, fminf(255, tls_background[idx+0] + delta));
        tls_background[idx+1] = (uint8_t)fmaxf(0, fminf(255, tls_background[idx+1] + delta));
        tls_background[idx+2] = (uint8_t)fmaxf(0, fminf(255, tls_background[idx+2] + delta));
    }

    /* --- JPEG compress (thread-local TurboJPEG handle, pre-allocated buffers) --- */
    if (!tls_tj_handle) {
        tls_tj_handle = tjInitCompress();
        if (!tls_tj_handle) return false;
    }

    unsigned char   *bg_ptr   = tls_jpeg_background;
    unsigned long    bg_size  = MAX_JPEG_SIZE;
    unsigned char   *pc_ptr   = tls_jpeg_piece;
    unsigned long    pc_size  = MAX_JPEG_SIZE;
    const int        quality  = 50;
    const int        flags    = TJFLAG_FASTDCT | TJFLAG_NOREALLOC | TJFLAG_FASTUPSAMPLE;

    if (tjCompress2(tls_tj_handle, tls_background,
                    BASE_IMAGE_WIDTH, BASE_IMAGE_WIDTH * 4, BASE_IMAGE_HEIGHT,
                    TJPF_RGBA, &bg_ptr, &bg_size, TJSAMP_420, quality, flags) != 0
        || bg_size > MAX_JPEG_SIZE) return false;

    if (tjCompress2(tls_tj_handle, tls_piece,
                    PUZZLE_PIECE_SIZE, PUZZLE_PIECE_SIZE * 4, PUZZLE_PIECE_SIZE,
                    TJPF_RGBA, &pc_ptr, &pc_size, TJSAMP_420, quality, flags) != 0
        || pc_size > MAX_JPEG_SIZE) return false;

    if (bg_size > sizeof(meta->background_png) || pc_size > sizeof(meta->piece_png)) {

        return false;
    }

    memcpy(meta->background_png, tls_jpeg_background, bg_size);
    memcpy(meta->piece_png,      tls_jpeg_piece,      pc_size);
    meta->background_size = bg_size;
    meta->piece_size      = pc_size;
    meta->solution_x      = piece_x;
    meta->solution_y      = piece_y;
    meta->tolerance       = 7;
    meta->piece_origin_x  = (uint16_t)(20 + get_fast_random() % 10);
    meta->piece_origin_y  = (uint16_t)((BASE_IMAGE_HEIGHT / 2) - (PUZZLE_PIECE_SIZE / 2)
                                        + (int)(get_fast_random() % 40) - 20);
    return true;
}

/* --------------------------------------------------------------------------- */
/* 9. Proof-of-Work                                                             */
/* --------------------------------------------------------------------------- */

void generate_pow_challenge(pow_challenge_t *pow) {
    get_crypto_random(pow->challenge, 32);
    pow->target_leading_zeros = POW_DIFFICULTY_BITS;
    pow->timestamp_created    = time(NULL);
}

bool verify_pow(const pow_challenge_t *pow, uint64_t nonce) {
    uint8_t input[40];
    memcpy(input, pow->challenge, 32);
    for (int i = 0; i < 8; i++)
        input[32 + i] = (uint8_t)((nonce >> (i * 8)) & 0xFF);  /* little-endian */

    uint8_t hash[32];
    sha256_hash(input, 40, hash);

    uint32_t zero_bits = 0;
    for (int i = 0; i < 32 && zero_bits < pow->target_leading_zeros; i++) {
        if (hash[i] == 0) {
            zero_bits += 8;
        } else {
            uint8_t b = hash[i];
            while ((b & 0x80) == 0 && zero_bits < pow->target_leading_zeros) {
                zero_bits++;
                b <<= 1;
            }
            break;
        }
    }

    return zero_bits >= pow->target_leading_zeros;
}

/* --------------------------------------------------------------------------- */
/* 10. CPU topology detection                                                   */
/* --------------------------------------------------------------------------- */

static void detect_cpu_topology(cpu_topology_t *topo) {
#ifdef __linux__
    topo->total_cores = (int)sysconf(_SC_NPROCESSORS_ONLN);
#elif defined(__APPLE__)
    size_t len = sizeof(topo->total_cores);
    sysctlbyname("hw.ncpu", &topo->total_cores, &len, NULL, 0);
#else
    topo->total_cores = 4;
#endif
    if (topo->total_cores < 1)   topo->total_cores = 1;
    if (topo->total_cores > 128) topo->total_cores = 128;

}

/* --------------------------------------------------------------------------- */
/* 11. GeoIP / timezone helpers                                                 */
/* --------------------------------------------------------------------------- */

bool init_geoip(const char *db_path) {
    int s = MMDB_open(db_path, MMDB_MODE_MMAP, &g_mmdb);
    if (s != MMDB_SUCCESS) {

        return false;
    }

    return true;
}

void close_geoip(void) { MMDB_close(&g_mmdb); }

static void normalize_tz(const char *in, char *out, size_t out_size) {
    if (!in || !out || out_size == 0) return;
    while (*in == ' ') in++;
    size_t len = strnlen(in, out_size - 1);
    memcpy(out, in, len);
    out[len] = '\0';
    for (size_t i = 0; i < len; i++)
        if (out[i] == '%') out[i] = '_';   /* sanitize format-string hazard */
    if (strcasecmp(out, "UTC")     == 0 || strcasecmp(out, "Etc/UTC") == 0 ||
        strcasecmp(out, "GMT")     == 0 || strcasecmp(out, "Etc/GMT") == 0) {
        strncpy(out, "Etc/UTC", out_size);
        out[out_size - 1] = '\0';
    }
}

bool ip_is_timezone(const char *user_ip, const char *browser_timezone) {
    if (!user_ip || !browser_timezone) return false;

    int gai_err = 0, mmdb_err = MMDB_SUCCESS;
    MMDB_lookup_result_s result =
        MMDB_lookup_string(&g_mmdb, user_ip, &gai_err, &mmdb_err);

    if (gai_err != 0 || mmdb_err != MMDB_SUCCESS || !result.found_entry)
        return true;   /* no data → pass */

    MMDB_entry_data_s entry;
    if (MMDB_get_value(&result.entry, &entry, "location", "time_zone", NULL) != MMDB_SUCCESS
        || !entry.has_data || entry.type != MMDB_DATA_TYPE_UTF8_STRING)
        return true;

    char ip_tz_raw[128];
    size_t len = entry.data_size;
    if (len >= sizeof(ip_tz_raw)) len = sizeof(ip_tz_raw) - 1;
    memcpy(ip_tz_raw, entry.utf8_string, len);
    ip_tz_raw[len] = '\0';

    char ip_tz[128], browser_tz[128];
    normalize_tz(ip_tz_raw,       ip_tz,      sizeof(ip_tz));
    normalize_tz(browser_timezone, browser_tz, sizeof(browser_tz));

    if (strcmp(ip_tz, browser_tz) == 0) return true;

    return false;
}

/* --------------------------------------------------------------------------- */
/* 12. Trajectory analysis                                                      */
/* --------------------------------------------------------------------------- */

/* Euclidean distance (used everywhere) */
static inline float pt_dist(float x1, float y1, float x2, float y2) {
    float dx = x2 - x1, dy = y2 - y1;
    return sqrtf(dx*dx + dy*dy);
}

/* --- 12a. Integrity filters (I4 / I6 / I7) --------------------------------- */

static bool validate_timestamps(const trajectory_point_t *pts, size_t count,
                                  uint32_t *dt_arr, float *dd_arr,
                                  float *t_avg, float *avg_p1,
                                  float *avg_p2, float *avg_p3,
                                  bool issimple) {
    size_t   duplicates = 0;
    uint32_t prev_t     = pts[0].timestamp_ms;
    float    prev_x     = pts[0].x, prev_y = pts[0].y;
    float    tot_time   = 0.0f, tot_dist = 0.0f;
    float    a_p1 = 0.0f, a_p2 = 0.0f, a_p3 = 0.0f;

    int p1_fi  = (int)(count * 0.3);
    int p3_ini = (int)(count * 0.7);

    for (size_t i = 1; i < count; i++) {
        float    cx = pts[i].x, cy = pts[i].y;
        uint32_t ct = pts[i].timestamp_ms;

        if (ct < prev_t)      {  return false; }
        if (cx < 0 || cy < 0) {  return false; }

        uint32_t dt  = ct - prev_t;
        float    d   = pt_dist(prev_x, prev_y, cx, cy);

        if (dt == 0) duplicates++;
        if (d > 200.0f && dt < 75) {  }

        dt_arr[i-1] = dt;
        dd_arr[i-1] = d;
        tot_dist   += d;
        tot_time   += dt;

        if ((int)(i-1) < p1_fi)       a_p1 += dt;
        else if ((int)(i-1) < p3_ini) a_p2 += dt;
        else                           a_p3 += dt;

        prev_t = ct; prev_x = cx; prev_y = cy;
    }

    *t_avg  = tot_time / (float)(count - 1);
    *avg_p1 = a_p1 / (float)(p1_fi > 0 ? p1_fi : 1);
    *avg_p2 = a_p2 / (float)((p3_ini - p1_fi) > 0 ? (p3_ini - p1_fi) : 1);
    *avg_p3 = a_p3 / (float)((count - (size_t)p3_ini) > 0 ? (count - (size_t)p3_ini) : 1);

    if (tot_time > TRAJECTORY_TIMEOUT_MS) {

        return false;
    }
    if (!issimple) {
        float opt = pt_dist(pts[0].x, pts[0].y, pts[count-1].x, pts[count-1].y);
        if (opt > 0.01f && tot_dist / opt >= 3.0f) {

            return false;
        }
    }
    if (duplicates * 2 > count - 1) {

        return false;
    }
    return true;
}

bool validate_integrity_filters(const trajectory_point_t *pts, size_t count,
                                  bool istouchpad,
                                  uint32_t *dt_arr, float *dd_arr,
                                  float *t_avg, float *avg_p1,
                                  float *avg_p2, float *avg_p3,
                                  bool issimple) {
    if (!pts || count < MIN_PUZZLE_POINTS) {  return false; }
    if (!validate_timestamps(pts, count, dt_arr, dd_arr, t_avg, avg_p1, avg_p2, avg_p3, issimple)){

        return false;
    }
    return true;
}

/* --- 12b. Fitts' Law -------------------------------------------------------- */

bool validate_trajectory_fitts(const trajectory_point_t *pts, size_t n, float *bot_score) {
    if (n < 2) {

        return false;
    }

    float direct = pt_dist(pts[0].x, pts[0].y, pts[n-1].x, pts[n-1].y);
    float total_ms = (float)(pts[n-1].timestamp_ms - pts[0].timestamp_ms);
    if (total_ms < 1.0f) total_ms = 1.0f;

    // Fitts's Law expected time calculation
    float id = log2f(direct / 50.0f + 1.0f);
    float expected_ms = 50.0f + 150.0f * id;
    float ratio = total_ms / expected_ms;

    // Calculate actual path length
    float path = 0.0f;
    for (size_t i = 1; i < n; i++) {
        path += pt_dist(pts[i-1].x, pts[i-1].y, pts[i].x, pts[i].y);
    }

    float eff = (direct > 0.1f) ? (path / direct) : 1.0f;
    float penalty = 0.0f;

    if (eff < 1.018f && direct > 100.0f) {
        float eff_penalty = powf((1.018f - eff) / 0.018f, 2.0f) * 0.25f;
        penalty += eff_penalty;

    }
    if (ratio > 12.0f) {
        float slow_penalty = (1.0f - expf(-0.2f * (ratio - 12.0f))) * 0.50f;
        penalty += slow_penalty;
    }
    else if (ratio < 1.5f) {
        // Penalización cuadrática para movimientos inhumanamente rápidos (max 0.35)
        float fast_penalty = powf((1.5f - ratio) / 1.5f, 2.0f) * 0.35f;
        penalty += fast_penalty;
    }

    *bot_score += penalty;

    return true;
}

/* --- 12c. Burstiness (Goh & Barabási 2008) --------------------------------- */

bool calculate_correct_burstiness(const trajectory_point_t *pts, size_t count,
                                    bool istouchpad,
                                    uint32_t *dt_arr, float *dd_arr,
                                    float *t_avg, float *avg_p1,
                                    float *avg_p2, float *avg_p3,
                                    float *bot_score) {
    (void)pts; (void)istouchpad; (void)dd_arr;
    (void)t_avg; (void)avg_p1; (void)avg_p2; (void)avg_p3;

    size_t n = count - 1;

    /* Global stats */
    float sum = 0.0f, sum_sq = 0.0f;
    for (size_t i = 0; i < n; i++) {
        float dt = (float)dt_arr[i];
        sum    += dt;
        sum_sq += dt * dt;
    }
    float mean   = sum / (float)n;
    float var    = (sum_sq / (float)n) - (mean * mean);
    float stddev = sqrtf(var);
    float B      = (stddev - mean) / (stddev + mean + 1e-9f);

    /* Phase stats helper lambda-style inline */
    size_t p1 = (size_t)(count * 0.3), p3 = (size_t)(count * 0.7);

    float s1=0, sq1=0, s2=0, sq2=0, s3=0, sq3=0;
    for (size_t i = 0; i < n; i++) {
        float dt = (float)dt_arr[i];
        if      (i < p1) { s1 += dt; sq1 += dt*dt; }
        else if (i < p3) { s2 += dt; sq2 += dt*dt; }
        else             { s3 += dt; sq3 += dt*dt; }
    }
    size_t l1 = p1, l2 = p3 - p1, l3 = n - p3;

    #define BURST(s,sq,l) ({ float _m=(l>0)?((s)/(float)(l)):0.0f; \
                            float _v=(l>0)?(((sq)/(float)(l))-_m*_m):0.0f; \
                            float _sd=sqrtf(_v); (_sd-_m)/(_sd+_m+1e-9f); })
        float B1 = BURST(s1,sq1,l1);
        float B2 = BURST(s2,sq2,l2);
        float B3 = BURST(s3,sq3,l3);
    #undef BURST

    float mb = (B1+B2+B3)/3.0f;
    float cb = sqrtf(((B1-mb)*(B1-mb)+(B2-mb)*(B2-mb)+(B3-mb)*(B3-mb))/3.0f);

    *bot_score += fminf(0.10f, expf(-100.0f * fabsf(B)) * 0.15f);

    if (fabsf(B) < 0.05f && cb < 0.05f){
        *bot_score += 0.05f;

    }

    return true;
}

/* --- 12d. Sample entropy on jerk signal ------------------------------------ */

static float compute_sampen(const float *sig, int len, int m, float r) {
    if (len < m + 1) return NAN;

    int   nm  = len - m,   nm1 = len - m - 1;
    int   cm  = 0,         cm1 = 0;

    for (int i = 0; i < nm; i++) {
        for (int j = i + 1; j < nm; j++) {
            float mx = 0.0f;
            for (int k = 0; k < m; k++) {
                float d = fabsf(sig[i+k] - sig[j+k]);
                if (d > mx) mx = d;
            }
            if (mx <= r) {
                cm++;
                if (i < nm1 && j < nm1) {
                    float d = fabsf(sig[i+m] - sig[j+m]);
                    if (fmaxf(mx, d) <= r) cm1++;
                }
            }
        }
    }

    if (cm == 0 || cm1 == 0) return NAN;
    return -logf((float)cm1 / (float)cm);
}

bool calculate_sample_entropy_jerk(const trajectory_point_t *pts, size_t count,
                                    bool istouchpad,
                                    uint32_t *dt_arr, float *dd_arr,
                                    float *scalar_speed, float *acceleration,
                                    float *bot_score) {
    if (count < 4) return false;

    /* Build speed and acceleration arrays */
    scalar_speed[0] = dd_arr[0] / ((float)dt_arr[0] + 0.001f);
    for (size_t i = 1; i < count - 1; i++) {
        float dt  = (float)dt_arr[i] + 0.001f;
        float v   = dd_arr[i] / dt;
        scalar_speed[i]    = v;
        acceleration[i-1]  = (v - scalar_speed[i-1]) / ((float)dt_arr[i-1] + 0.001f);
    }

    /* Jerk = dAccel/dt */
    size_t  jlen   = count - 2;
    float  *jerk   = alloca(jlen * sizeof(float));
    float   jsum   = 0.0f;
    for (size_t i = 1; i < jlen; i++) {
        jerk[i-1]  = (acceleration[i] - acceleration[i-1]) / ((float)dt_arr[i-1] + 0.001f);
        jsum      += jerk[i-1];
    }
    float javg = jsum / (float)jlen;

    float jvar = 0.0f;
    for (size_t i = 0; i < jlen; i++) jvar += (jerk[i]-javg)*(jerk[i]-javg);
    float jstd = sqrtf(jvar / (float)jlen) + 1e-9f;

    float *sig = alloca(jlen * sizeof(float));
    for (size_t i = 0; i < jlen; i++) sig[i] = (jerk[i] - javg) / jstd;

    if ((int)jlen < 4) { return false; }

    float r   = istouchpad ? 0.25f : 0.20f;
    float sg  = compute_sampen(sig, (int)jlen, 2, r);
    if (isnan(sg)) {

        *bot_score += 0.2f;
    }

    int th = (int)jlen / 3;
    float s1 = compute_sampen(sig,        th,               2, r);
    float s2 = compute_sampen(sig + th,   th,               2, r);
    float s3 = compute_sampen(sig + 2*th, (int)jlen - 2*th, 2, r);

    //float contrast = NAN;
    if (!isnan(s1) && !isnan(s2) && !isnan(s3)) {
        //float ms = (s1+s2+s3)/3.0f;
        //contrast  = sqrtf(((s1-ms)*(s1-ms)+(s2-ms)*(s2-ms)+(s3-ms)*(s3-ms))/3.0f);
    }

    // Change your SAMPEN thresholds to this:
    if      (sg < 0.005f) *bot_score += 1.00f * 0.15f;
    else if (sg < 0.015f) *bot_score += 0.50f * 0.15f;

    return true;
}

/* --- 12e. Velocity coefficient of variation -------------------------------- */

bool is_human_velocity_cv(const float *dd, const uint32_t *dt, size_t count,
                            float *bot_score) {
    float   sum = 0.0f, sum_sq = 0.0f;
    int     valid = 0;

    for (size_t i = 0; i < count - 1; i++) {
        float dti = (float)dt[i];
        if (dti < 0.1f) continue;
        float spd  = dd[i] / dti;
        sum       += spd;
        sum_sq    += spd * spd;
        valid++;
    }
    if (valid < 2) return false;

    float mean = sum / (float)valid;
    if (mean < 0.0001f) return false;

    float var  = fmaxf(0.0f, (sum_sq / (float)valid) - mean * mean);
    float cv   = sqrtf(var) / mean;

    if (cv < 0.20f) {
        *bot_score += 0.40f;
    }
    else if (cv < 0.40f) {
        *bot_score += 0.20f;
    }
    if (cv < 0.66f) {
        // Curva cuadrática: castiga exponencialmente a medida que CV baja de 0.66
        *bot_score += powf((0.66f - cv) / 0.66f, 2.0f) * 0.40f;
    }
    else if (cv > 2.0f) {
        // Curva exponencial: castiga movimientos que exceden por mucho el límite humano (1.36)
        *bot_score += (1.0f - expf(-0.5f * (cv - 2.0f))) * 0.30f;
    }
    if (cv > 3.5f) {
        *bot_score += 0.20f;
    }

    return true;
}

/* --- 12f. Final feature checks (F4) ---------------------------------------- */

bool f4_final_features(const trajectory_point_t *pts,  size_t count,bool istouchpad,uint32_t *dt_arr,
                       float *dd_arr,float *scalar_speed, float *acceleration, float *bot_score) {

    (void)pts; (void)istouchpad; (void)dt_arr; (void)dd_arr; (void)acceleration;

    int prin_mig = (int)(count * 0.35);
    int fin_mig  = (int)(count * 0.65);
    int part_fin = (int)(count * 0.85);

    float vel_max = 0.0f;
    for (int i = prin_mig; i < fin_mig && i < (int)(count - 1); i++)
        if (scalar_speed[i] > vel_max) vel_max = scalar_speed[i];

    float fin_sum = 0.0f;
    int   fin_n   = 0;
    for (int i = part_fin; i < (int)(count - 1); i++) {
        fin_sum += scalar_speed[i];
        fin_n++;
    }
    float avg_fin = (fin_n > 0) ? fin_sum / (float)fin_n : 0.0f;

    if (vel_max > 0.001f && (avg_fin / vel_max) > 0.5f) {

        *bot_score += 0.3f;
    }

    /* Duplicate slope (identical consecutive speed readings) */
    size_t m_dup = 0;
    for (size_t i = 1; i < count - 1; i++)
        if (fabsf(scalar_speed[i] - scalar_speed[i-1]) < 1e-6f) m_dup++;

    if (m_dup * 2 > count) {

        return false;
    }
    return true;
}

/* --------------------------------------------------------------------------- */
/* 13. Bot detector (fingerprint-based pre-filter)                              */
/* --------------------------------------------------------------------------- */

/* Case-insensitive substring search (wrapper for strcasestr) */
static bool str_contains(const char *hay, const char *needle) {
    if (!hay || !needle) return false;
    return strcasestr(hay, needle) != NULL;
}

bool check_is_touchpad(const char *ua) {
    if (!ua) return false;
    if (str_contains(ua, "Android") || str_contains(ua, "iPhone") ||
        str_contains(ua, "iPad")    || str_contains(ua, "Mobile")){

        return true;
    }

    return false;   /* desktop: assume mouse */
}

bool captcha_bot_detector(char *ua, int hw_concurrency, int inner_w, int inner_h,
                          int outer_w, int outer_h, const char *webgl,
                          bool *isphone, int device_mem, const char *timezone,
                          const char *user_ip, bool webdriver,
                          bool chromewebdrivermissing, bool error_stack_tripwire) {
    int pts = 0;
    *isphone = false;

    // 1. ABSOLUTE DEALBREAKERS (Early Returns)
    if (webdriver || error_stack_tripwire) {

        return true;
    }

    if (ua && str_contains(ua, "HeadlessChrome")) {

        return true;
    }

    // Software renderers are primary indicators of headless server environments
    if (webgl && webgl[0] != '\0') {
        if (str_contains(webgl, "SwiftShader") || str_contains(webgl, "llvmpipe") ||
            str_contains(webgl, "VirtualBox")  || str_contains(webgl, "VMware")) {

            return true;
        }
        if (str_contains(webgl, "Mesa")) {
            pts += 2;

        }
    }

    // 2. CUMULATIVE HEURISTICS
    if (chromewebdrivermissing) {
        pts += 2;
    }

    // Avoid penalizing 0 values if the browser simply blocked the hardware API
    if (device_mem > 0 && device_mem <= 2) {
        pts++;

    }

    if (hw_concurrency > 0 && hw_concurrency <= 2) {
        pts++;

    }

    // Phone detection safely checking ua
    const char *pt = NULL;
    if (ua) {
        if (str_contains(ua, "Android")) { pt = "Android"; *isphone = true; }
        else if (str_contains(ua, "iPhone"))  { pt = "iPhone";  *isphone = true; }
        else if (str_contains(ua, "iPad"))    { pt = "iPad";    *isphone = true; }
    }

    if (pt && strcmp(pt, "iPhone") == 0 && hw_concurrency > 8) {
        pts++;

    }

    // Viewport and Geometry validation
    if (*isphone) {
        // Prevent Division by Zero and catch 0x0 headless windows
        if (outer_w == 0 || outer_h == 0) {
            pts += 2;

        } else {
            int chrome_w = outer_w - inner_w;
            int chrome_h = outer_h - inner_h;

            if (outer_h * 0.25 < chrome_w || outer_w * 0.30 < chrome_h){
                pts++;

            }

            double ratio = (double)outer_h / (double)outer_w;
            if (ratio > 2.6 || ratio < 1.7) {
                pts++;

            }
        }
    }

    // IP/Timezone correlation cross-check
    if (user_ip && timezone) {
        if (!ip_is_timezone(user_ip, timezone)) {
            pts++;

        }
    } else {
        pts++; // Penalize missing network data from spoofers

    }

    // OS Spoofing: Linux renderer faking a Windows User-Agent
    if (ua && webgl && str_contains(ua, "Windows") && str_contains(webgl, "Mesa")) {
        pts += 2;

    }

    return pts >= MAX_BOT_SCORE;
}

/* --------------------------------------------------------------------------- */
/* 14. Public API                                                               */
/* --------------------------------------------------------------------------- */

bool captcha_system_init(const char *image_mmap_path, int num_workers_override) {
    (void)image_mmap_path;

    detect_cpu_topology(&g_cpu_topology);

    int nw = (num_workers_override > 0)
             ? num_workers_override
             : g_cpu_topology.total_cores;
    if (nw > MAX_WORKERS) {
        fprintf(stderr, "ERROR: num_workers %d > MAX_WORKERS %d\n", nw, MAX_WORKERS);
        return false;
    }

    g_system = calloc(1, sizeof(captcha_system_t));
    if (!g_system){
        fprintf(stderr, "g_system failed\n");
        return false;
    }

    g_system->num_workers  = nw;
    g_system->worker_pools = calloc((size_t)nw, sizeof(worker_captcha_pool_t));
    if (!g_system->worker_pools) {
        free(g_system);
         fprintf(stderr, "g_system->worker_pools failed\n");
        return false;
    }

    g_system->bloom[0] = calloc(BLOOM_FILTER_SIZE, sizeof(bloom_entry_t));
    g_system->bloom[1] = calloc(BLOOM_FILTER_SIZE, sizeof(bloom_entry_t));
    if (!g_system->bloom[0] || !g_system->bloom[1]) {
        free(g_system->bloom[0]);
        free(g_system->bloom[1]);
        free(g_system->worker_pools);
        free(g_system);
        fprintf(stderr, "!g_system->bloom[0] || !g_system->bloom[1] failed\n");
        return false;
    }
    atomic_store(&g_system->bloom_active,        0);
    atomic_store(&g_system->bloom_occupied[0],   0);
    atomic_store(&g_system->bloom_occupied[1],   0);
    atomic_store(&g_system->bloom_reset_running, 0);

    for (int i = 0; i < nw; i++) {
        g_system->worker_pools[i].worker_id = i;
        if (RAND_bytes(g_system->worker_pools[i].crypto_key, 32) != 1) {
            fprintf(stderr, "ERROR: RAND_bytes failed for worker %d\n", i);
            return false;
        }
        printf("[Worker %d] Initialized\n", i);
    }

    const char *img_dir = getenv("CAPTCHA_IMAGE_DIR");
    if (!img_dir) img_dir = "./puzzle_images";
    if (!load_image_pool(img_dir)) { fprintf(stderr, "ERROR: load_image_pool failed\n"); return false; }

    precompute_mask_templates();
    atomic_store(&g_system->total_requests, 0);

    printf("CAPTCHA system ready ” workers=%d bloom=%.1f MB\n",
           nw, (BLOOM_FILTER_SIZE * sizeof(bloom_entry_t)) / (1024.0 * 1024.0));

    const char *geoip = getenv("GEOIP_DB_PATH");
    if (!geoip) geoip = "/usr/share/GeoIP/GeoLite2-City.mmdb";
    if (!init_geoip(geoip))
        fprintf(stderr, "WARNING: GeoIP not loaded â€” TZ checks disabled\n");

    return true;
}

void captcha_system_destroy(void) {
    if (!g_system) return;
    close_geoip();
    destroy_image_pool();
    free(g_system->bloom[0]);
    free(g_system->bloom[1]);
    free(g_system->worker_pools);
    free(g_system);
    g_system = NULL;

}

bool captcha_get_puzzle(int worker_id,
                         puzzle_token_payload_t *token_out,
                         unsigned char *encrypted_token, size_t *encrypted_len,
                         puzzle_metadata_t *puzzle_out) {
    if (!g_system || worker_id < 0 || worker_id >= g_system->num_workers) return false;
    if (!generate_sliding_puzzle(puzzle_out)) return false;

    generate_pow_challenge(&token_out->pow_data);
    token_out->timestamp_generated  = time(NULL);
    token_out->puzzle_x_solution    = puzzle_out->solution_x;
    token_out->puzzle_y_solution    = puzzle_out->solution_y;
    token_out->puzzle_solution_hash = 0;

    worker_captcha_pool_t *pool = &g_system->worker_pools[worker_id];
    unsigned char ciphertext[512];
    unsigned char nonce[12];
    size_t ct_len = 0;

    if (!encrypt_token(pool->crypto_key, token_out, sizeof(*token_out),
                       ciphertext, &ct_len, nonce)) return false;

    memcpy(encrypted_token,      nonce,      12);
    memcpy(encrypted_token + 12, ciphertext, ct_len);
    *encrypted_len = 12 + ct_len;

    uint64_t req_n = atomic_fetch_add(&g_system->total_requests, 1) + 1;
    if ((req_n % POOL_RELOAD_THRESH) == 0) {

        trigger_pool_reload();
    }
    return true;

}

bool captcha_validate_hybrid(const unsigned char *encrypted_token, size_t token_len,
                               uint64_t pow_nonce,
                               uint16_t user_x, uint16_t user_y,
                               const trajectory_point_t *traj, size_t n_traj,
                               int *num_error) {
    if (!g_system || token_len < 28) return false;   /* 12 nonce + min ct */

    if (bloom_check_and_add(encrypted_token, token_len)) return false;
    if (n_traj > 999) {  return false; }

    unsigned char nonce[12];
    memcpy(nonce, encrypted_token, 12);

    puzzle_token_payload_t payload;
    size_t pt_len  = 0;
    bool   ok      = false;

    for (int i = 0; i < g_system->num_workers && !ok; i++) {
        ok = decrypt_token(g_system->worker_pools[i].crypto_key,
                           encrypted_token + 12, token_len - 12,
                           (unsigned char *)&payload, &pt_len, nonce);
    }
    if (!ok || pt_len != sizeof(payload)) return false;

    if (difftime(time(NULL), payload.timestamp_generated) > CAPTCHA_VALIDITY_SECONDS) {
        *num_error = 1; return false;
    }
    if (!verify_pow(&payload.pow_data, pow_nonce)) {
        *num_error = 2; return false;
    }

    int dx  = abs((int)user_x - (int)payload.puzzle_x_solution);
    int dy  = abs((int)user_y - (int)payload.puzzle_y_solution);
    int dxt = abs((int)traj[n_traj-1].x - (int)payload.puzzle_x_solution);
    int dyt = abs((int)traj[n_traj-1].y - (int)payload.puzzle_y_solution);

    if (dx > 7 || dy > 7 || dxt > 7 || dyt > 7) {
        *num_error = 3; return false;
    }
    return true;
}

void get_client_browser(char *useragent, char *client_browser) {
    if (useragent == NULL || client_browser == NULL) return;

    // 1. Check for Edge (contains 'Chrome' and 'Safari', so check it first)
    if (strstr(useragent, "Edg/") || strstr(useragent, "Edge/")) {
        strcpy(client_browser, "chrome");
    }
    // 2. Check for Opera (also contains 'Chrome')
    else if (strstr(useragent, "OPR/") || strstr(useragent, "Opera/")) {
        strcpy(client_browser, "chrome");
    }
    // 3. Check for Firefox
    else if (strstr(useragent, "Firefox/")) {
        strcpy(client_browser, "firefox");
    }
    // 4. Check for Chrome (contains 'Safari', so check it before Safari)
    else if (strstr(useragent, "Chrome/")) {
        strcpy(client_browser, "chrome");
    }
    // 5. Check for Safari
    else if (strstr(useragent, "Safari/")) {
        strcpy(client_browser, "safari");
    }
    // 6. Unknown fallback
    else {
        strcpy(client_browser, "unknown");
    }

}

bool ja4_matches_ua(char *client_browser, char *ja4) {
    if (!client_browser || !ja4){

        return false;
    }

    char ja4_copy[256];
    strncpy(ja4_copy, ja4, sizeof(ja4_copy) - 1);
    ja4_copy[sizeof(ja4_copy) - 1] = '\0';

    char *saveptr;

    // 2. Use strtok_r instead of strtok
    char *p1 = strtok_r(ja4_copy, "_", &saveptr);
    char *p2 = strtok_r(NULL, "_", &saveptr);

    if (!p1 || !p2) {

        return false;
    }

    // Use strcmp to compare strings. It returns 0 if they match.
    if (strcmp(client_browser, "chrome") == 0) {
        // Grouping comparisons makes the code much cleaner
        if (strcmp(p1, "t13d1516h2") == 0 || strcmp(p1, "t13d1517h2") == 0 ||
            strcmp(p1, "t13d1714h2") == 0 || strcmp(p1, "q13d0310h3") == 0 ||
            strcmp(p1, "t13d1518h2") == 0 || strcmp(p1, "q13d0311h3") == 0 ||
            strcmp(p1, "q13d0312h3") == 0 || strcmp(p1, "t13i1515h2") == 0 ||
            strcmp(p1, "q13i0311h3") == 0 || strcmp(p1, "t13i1516h2") == 0) {
            return true;
        }

        if (strcmp(p2, "8daaf6152771") == 0 || strcmp(p2, "5b57614c22b0") == 0 ||
            strcmp(p2, "24fc43eb1c96") == 0 || strcmp(p2, "55b375c5d22e") == 0) {
            return true;
        }
        return false;
    }

    if (strcmp(client_browser, "firefox") == 0) {
        if (strcmp(p1, "t13d1715h2") == 0 || strcmp(p1, "t13i1714h2") == 0 ||
            strcmp(p1, "t13d1717h2") == 0 || strcmp(p1, "t13d1615h2") == 0){
            return true;
        }

        if (strcmp(p2, "5b57614c22b0") == 0 || strcmp(p2, "86a278354501") == 0) {
            return true;
        }
        return false;
    }

    if (strcmp(client_browser, "safari") == 0) {
        if (strcmp(p1, "t13d2014h2") == 0 || strcmp(p1, "t13i2013h2") == 0 ||
            strcmp(p1, "t13d2013h2")) {
            return true;
        }

        if (strcmp(p2, "a09f3c656075") == 0 ) {
            return true;
        }
        return false;
    }

    return false;
}
