/* =============================================================================
 * captcha_core.h  —  Public interface for the on-demand hybrid CAPTCHA engine
 *
 * Include this header in every translation unit that calls the captcha API.
 * Do NOT include captcha_core.c directly.
 * ============================================================================= */

#ifndef CAPTCHA_CORE_H
#define CAPTCHA_CORE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <time.h>
#include <maxminddb.h>



/* ============================================================================
 * COMPILE-TIME CONFIGURATION
 * ============================================================================ */

/* Image dimensions (pixels) */
#ifndef BASE_IMAGE_WIDTH
#  define BASE_IMAGE_WIDTH       400
#endif
#ifndef BASE_IMAGE_HEIGHT
#  define BASE_IMAGE_HEIGHT      300
#endif

/* Puzzle piece bounding-box size (pixels) */
#ifndef PUZZLE_PIECE_SIZE
#  define PUZZLE_PIECE_SIZE      80
#endif

#define MIN_PUZZLE_POINTS 50

/* =========================================================================
 * Image pool — double-buffer, hot-swap on demand
 * ========================================================================= */

#define NUM_BASE_IMAGES     200   /* images per bank (hot in RAM)             */
#define POOL_RELOAD_THRESH  800   /* complex requests before pool refresh     */
#define MAX_IMAGE_FILES    8192   /* max .jpg files scannable in image dir    */

/* One bank: up to NUM_BASE_IMAGES decoded RGBA images */
typedef struct {
    uint8_t *images[NUM_BASE_IMAGES];
    size_t   sizes [NUM_BASE_IMAGES];
    int      count;                    /* actual images loaded (≤ NUM_BASE_IMAGES) */
} image_bank_t;

/* Double-buffer pool — only g_image_pool.banks[active] is ever served */
typedef struct {
    image_bank_t  banks[2];
    _Atomic int   active;              /* 0 or 1 — live bank index             */
    bool          loaded;
} image_pool_t;


/* Maximum pre-allocated puzzle images per worker (pool base) */
#ifndef POOL_SIZE_PER_WORKER_BASE
#  define POOL_SIZE_PER_WORKER_BASE  64
#endif

/* Maximum number of h2o worker threads */
#ifndef MAX_WORKERS
#  define MAX_WORKERS            128
#endif

/* Maximum trajectory points accepted per submission */
#ifndef MAX_TRAJECTORY_POINTS
#  define MAX_TRAJECTORY_POINTS  1000
#endif

/* Trajectory total-time ceiling (milliseconds) */
#ifndef TRAJECTORY_TIMEOUT_MS
#  define TRAJECTORY_TIMEOUT_MS  15000
#endif

/* Proof-of-Work: required leading zero bits in SHA-256(challenge || nonce) */
#ifndef POW_DIFFICULTY_BITS
#  define POW_DIFFICULTY_BITS    18
#endif

/* How long an issued captcha challenge remains valid (seconds) */
#ifndef CAPTCHA_VALIDITY_SECONDS
#  define CAPTCHA_VALIDITY_SECONDS  180
#endif

/* Bloom filter: number of hash functions and total slot count */
#ifndef BLOOM_HASH_FUNCTIONS
#  define BLOOM_HASH_FUNCTIONS   7
#endif
#ifndef BLOOM_FILTER_SIZE
#  define BLOOM_FILTER_SIZE      (1ULL << 22)   /* ~4 M slots, ~4 MB */
#endif

/* Per-image JPEG buffer ceiling in puzzle_metadata_t */
#ifndef PUZZLE_JPEG_MAX
#  define PUZZLE_JPEG_MAX        (150 * 1024)
#endif

/* ============================================================================
 * TYPES & STRUCTURES
 * ============================================================================ */

/* --- Xoshiro256** PRNG state ----------------------------------------------- */
typedef struct {
    uint64_t s[4];
} xoshiro256_state_t;

/* --- CPU topology ---------------------------------------------------------- */
typedef struct {
    int total_cores;
} cpu_topology_t;

/* --- Bloom-filter slot ----------------------------------------------------- */
typedef struct {
    _Atomic uint8_t  count;        /* saturating at 255 */
    uint64_t         hash_sample;  /* for diagnostic / clearing heuristics */
} bloom_entry_t;

/* --- Proof-of-Work challenge ----------------------------------------------- */
typedef struct {
    uint8_t   challenge[32];       /* random 32-byte nonce */
    uint32_t  target_leading_zeros;/* required SHA-256 leading zero bits */
    time_t    timestamp_created;
} pow_challenge_t;

/* --- Encrypted puzzle token payload (serialised as AEAD plaintext) --------- */
typedef struct {
    pow_challenge_t pow_data;
    time_t          timestamp_generated;
    uint16_t        puzzle_x_solution;
    uint16_t        puzzle_y_solution;
    uint32_t        puzzle_solution_hash;  /* reserved / future use */
} puzzle_token_payload_t;

/* --- Puzzle metadata returned to the HTTP handler -------------------------- */
typedef struct {
    /* JPEG-compressed images (stack-allocated, no malloc) */
    uint8_t  background_png[PUZZLE_JPEG_MAX];
    uint8_t  piece_png[PUZZLE_JPEG_MAX];
    size_t   background_size;
    size_t   piece_size;

    /* Puzzle geometry */
    uint16_t solution_x;           /* correct piece drop X position */
    uint16_t solution_y;           /* correct piece drop Y position */
    uint16_t piece_origin_x;       /* starting X shown to client (left rail) */
    uint16_t piece_origin_y;       /* starting Y shown to client (vertical centre) */
    uint8_t  tolerance;            /* acceptance window in pixels */
} puzzle_metadata_t;

/* --- Per-worker crypto + pool state ---------------------------------------- */
typedef struct {
    int           worker_id;
    unsigned char crypto_key[32];  /* ChaCha20-Poly1305 key, per-worker */
} worker_captcha_pool_t;



/* --- Global captcha system state ------------------------------------------- */
typedef struct {
    worker_captcha_pool_t *worker_pools;
    bloom_entry_t  *bloom[2];              /* double buffer — slot 0 and slot 1   */
    atomic_int      bloom_active;          /* which slot is currently live (0|1)  */
    _Atomic uint64_t  bloom_occupied[2];
    _Atomic int       bloom_reset_running;
    int                    num_workers;
    _Atomic uint64_t       total_requests;
} captcha_system_t;

/* --- Single mouse/touch trajectory point ----------------------------------- */
typedef struct {
    float    x;
    float    y;
    uint32_t timestamp_ms;
} trajectory_point_t;

/* ============================================================================
 * GLOBAL INSTANCES  (defined in captcha_core.c, extern here)
 * ============================================================================ */

extern captcha_system_t *g_system;
extern cpu_topology_t    g_cpu_topology;
extern MMDB_s            g_mmdb;

/* ============================================================================
 * PUBLIC API
 * ============================================================================ */

/* --- Lifecycle -------------------------------------------------------------- */

/**
 * captcha_system_init()
 *   Initialise the entire captcha engine:
 *     - Detects CPU topology and sets worker count.
 *     - Allocates the bloom filter and per-worker crypto keys.
 *     - Loads base images from $CAPTCHA_IMAGE_DIR (default: ./puzzle_images).
 *     - Pre-computes puzzle mask templates.
 *     - Opens the GeoIP MMDB from $GEOIP_DB_PATH (default: /usr/share/GeoIP/...).
 *
 *   @param image_mmap_path  Reserved for future mmap path; pass NULL.
 *   @param num_workers_override  0 = auto-detect from CPU cores.
 *   @return true on success.
 */
bool captcha_system_init(const char *image_mmap_path, int num_workers_override);

/**
 * captcha_system_destroy()
 *   Free all resources allocated by captcha_system_init().
 *   Call once at shutdown; not thread-safe relative to active requests.
 */
void captcha_system_destroy(void);

/* --- GeoIP ----------------------------------------------------------------- */

bool init_geoip(const char *db_path);
void close_geoip(void);

/* --- Image pool ------------------------------------------------------------ */

bool load_image_pool(const char *image_dir);
void destroy_image_pool(void);

/* --- Puzzle generation & validation ---------------------------------------- */

/**
 * captcha_get_puzzle()
 *   Generate a new sliding-puzzle captcha for the given worker thread.
 *   Fills *token_out, writes the encrypted token to *encrypted_token,
 *   and fills *puzzle_out with JPEG-compressed image data.
 *
 *   Thread-safe (uses thread-local buffers, no locks required).
 *   @return true on success.
 */
bool captcha_get_puzzle(int worker_id,
                         puzzle_token_payload_t *token_out,
                         unsigned char          *encrypted_token,
                         size_t                 *encrypted_len,
                         puzzle_metadata_t      *puzzle_out);

/**
 * captcha_validate_hybrid()
 *   Fully validate a solve submission:
 *     1. Bloom-filter replay check.
 *     2. Decrypt + authenticate the puzzle token.
 *     3. Expiry check.
 *     4. PoW verification.
 *     5. Puzzle X/Y position check (user_x/y and last trajectory point).
 *
 *   @param num_error  Set to an error code on failure:
 *                       1 = token expired
 *                       2 = PoW failed
 *                       3 = puzzle position wrong
 *   @return true if all checks pass.
 */
bool captcha_validate_hybrid(const unsigned char   *encrypted_token,
                               size_t                 token_len,
                               uint64_t               pow_nonce,
                               uint16_t               user_puzzle_x,
                               uint16_t               user_puzzle_y,
                               const trajectory_point_t *trajectory,
                               size_t                 num_trajectory_points,
                               int                   *num_error);

/* --- Proof-of-Work --------------------------------------------------------- */

/**
 * generate_pow_challenge()
 *   Fill a pow_challenge_t with fresh random bytes and the configured
 *   difficulty level. Uses the thread-local crypto random pool.
 */
void generate_pow_challenge(pow_challenge_t *pow);

/**
 * verify_pow()
 *   Return true iff SHA-256(challenge || nonce_le64) has at least
 *   pow->target_leading_zeros leading zero bits.
 */
bool verify_pow(const pow_challenge_t *pow, uint64_t nonce);

/* --- Trajectory analysis --------------------------------------------------- */

/**
 * validate_integrity_filters()
 *   Integrity pre-checks (I4/I6/I7):
 *     - Minimum point count (60 for touchpad, 80 for mouse).
 *     - Monotonic timestamps, no teleportation, duplicate-ratio check.
 *     - Total-time ceiling.
 *     - Path-length vs. straight-line ratio (when !issimple).
 *
 *   Also computes dt_arr, dd_arr, and phase-averaged timing values that
 *   subsequent analysis functions consume.
 *
 *   @param time_difference   Caller-allocated array of (count-1) uint32_t.
 *   @param distance_difference Caller-allocated array of (count-1) float.
 *   @return false on hard rejection.
 */
bool validate_integrity_filters(const trajectory_point_t *points,
                                  size_t    count,
                                  bool      istouchpad,
                                  uint32_t *time_difference,
                                  float    *distance_difference,
                                  float    *t_average,
                                  float    *avg_p1,
                                  float    *avg_p2,
                                  float    *avg_p3,
                                  bool      issimple);

/**
 * validate_trajectory_fitts()
 *   Fitts' Law timing + path-efficiency check.
 *   Adds a penalty to *bot_score on suspicious patterns.
 *   @return false if score falls below 0.3.
 */
bool validate_trajectory_fitts(const trajectory_point_t *points,
                                  size_t  num_points,
                                  float  *bot_score);

/**
 * calculate_correct_burstiness()
 *   Goh & Barabási (2008) burstiness on inter-event Δt values,
 *   split into three temporal phases and a phase-contrast metric.
 *   Adds to *bot_score.
 *   @return false on catastrophic failure (not normally reachable).
 */
bool calculate_correct_burstiness(const trajectory_point_t *points,
                                    size_t    count,
                                    bool      istouchpad,
                                    uint32_t *time_difference,
                                    float    *distance_difference,
                                    float    *t_average,
                                    float    *avg_p1,
                                    float    *avg_p2,
                                    float    *avg_p3,
                                    float    *bot_score);

/**
 * calculate_sample_entropy_jerk()
 *   Computes the jerk signal (third derivative of position), normalises it,
 *   and calculates SampEn(m=2) globally and per phase.
 *   Adds to *bot_score for suspiciously low entropy.
 *   Also fills scalar_speed[] and acceleration[] for downstream use.
 *   @return false if signal is too short or NaN-degenerate.
 */
bool calculate_sample_entropy_jerk(const trajectory_point_t *points,
                                    size_t    count,
                                    bool      istouchpad,
                                    uint32_t *time_difference,
                                    float    *distance_difference,
                                    float    *scalar_speed,
                                    float    *acceleration,
                                    float    *bot_score);

/**
 * is_human_velocity_cv()
 *   Checks that the coefficient of variation of instantaneous speed is
 *   above a human-plausible threshold.
 *   Adds to *bot_score for excessively uniform speed.
 *   @return false if too few valid samples.
 */
bool is_human_velocity_cv(const float    *distance_difference,
                            const uint32_t *time_difference,
                            size_t          count,
                            float          *bot_score);

/**
 * f4_final_features()
 *   Checks that:
 *     - Average final-phase velocity is well below mid-trajectory peak (deceleration).
 *     - Consecutive identical-slope count is below threshold.
 *   @return false on hard rejection.
 */
bool f4_final_features(const trajectory_point_t *points,
                       size_t count,
                       bool istouchpad,
                       uint32_t *time_difference,
                       float *distance_difference,
                       float *scalar_speed,
                       float *acceleration,
                       float *bot_score);

/* --- Bot detector ---------------------------------------------------------- */

/**
 * captcha_bot_detector()
 *   Fingerprint-based pre-filter.  Scores browser environment signals:
 *     - Device memory / hardware concurrency
 *     - Screen geometry consistency (mobile vs desktop)
 *     - WebGL renderer (virtualization detection)
 *     - IP–timezone mismatch via GeoIP
 *
 *   @param isphone  Set to true if UA suggests a mobile device.
 *   @return true if suspicious_points > 3 (reject).
 */
bool captcha_bot_detector(char *f_user_agent,
                           int         f_hardwareConcurrency,
                           int         f_innerwidth,
                           int         f_innerheight,
                           int         f_outer_width,
                           int         f_outer_height,
                           const char *f_webgl,
                           bool       *isphone,
                           int         f_devicememory,
                           const char *f_timezone,
                           const char *user_ip,
                           bool webdriver,
                           bool chromewebdrivermissing,
                           bool error_stack_tripwire);

/**
 * check_is_touchpad()
 *   Returns true if the User-Agent suggests a mobile/touch device,
 *   used to relax trajectory thresholds.
 */
bool check_is_touchpad(const char *user_agent);

/**
 * ip_is_timezone()
 *   Returns true if the IP's GeoIP timezone matches the browser-reported
 *   timezone (or if the IP cannot be resolved — fail-open).
 */
bool ip_is_timezone(const char *user_ip, const char *browser_timezone);

/* --- Statistics ------------------------------------------------------------- */

void get_client_browser(char *useragent, char *client_browser);

bool ja4_matches_ua(char *client_browser, char *ja4);

void   captcha_bloom_reset(void);
double captcha_bloom_load(void);       /* returns 0.0–1.0 of active filter    */

bool bloom_check_and_add(const unsigned char *token, size_t len);


#ifdef __cplusplus
}
#endif

#endif /* CAPTCHA_CORE_H */
