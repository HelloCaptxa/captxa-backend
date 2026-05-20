# Captxa — High-Performance CAPTCHA Server

**Captxa** is a production-grade, anti-bot CAPTCHA engine written in C.
It serves both a lightweight proof-of-work challenge ("simple") and a
full slider-puzzle challenge ("complex") with mouse/touch trajectory
analysis, TLS fingerprinting (JA4), GeoIP correlation, and IP reputation
filtering.

Zero-heap-allocation hot path. Sub-millisecond puzzle generation.
Designed for 50k+ concurrent validations per second per core.

**Recommended hosting: Debian Linux server.**

---

## How It Works

See the full technical deep-dive at **[captxa.com/how_it_works](https://captxa.com/how_it_works)**.

---

## API Endpoints

| Method | Path                 | Description                              |
|--------|----------------------|------------------------------------------|
| POST   | `/challenge/simp`    | Request a simple PoW challenge           |
| POST   | `/solve/simp`        | Submit simple PoW solution               |
| GET    | `/challenge/complex` | Request a slider-puzzle captcha          |
| POST   | `/solve/complex`     | Submit complex puzzle + trajectory       |
| POST   | `/api/validate`      | Validate a previously-issued pass token  |

---

## Dependencies

### Debian 12

```bash
apt update && apt install -y \
  gcc make pkg-config git curl \
  libssl-dev \
  libh2o-dev \
  libuv1-dev \
  libgd-dev \
  libturbojpeg0-dev \
  libjpeg-dev \
  libpng-dev \
  zlib1g-dev \
  libmaxminddb-dev \
  mmdb-bin \
  libcurl4-openssl-dev \
  libatomic1
```

`libh2o-dev` is available in Debian 12 repositories.

### Debian 13

All packages above except `libh2o-dev`, which was removed from Debian 13
repositories. Build h2o from source:

**https://github.com/h2o/h2o**

---

## Quick Start

### 1. Clone

```bash
git clone https://github.com/captxa/captxa-backend.git
cd captxa-backend
```

### 2. TLS Certificates (Let's Encrypt)

```bash
# Install acme.sh
curl https://get.acme.sh | sh -s email=hello@captxa.com
source ~/.bashrc

# Issue certificate (use your DNS provider's API)
~/.acme.sh/acme.sh --issue -d yourdomain.com \
  --dns dns_your_provider \
  --key-file       certs/privkey.pem \
  --fullchain-file certs/fullchain.pem \
  --reloadcmd      "pkill -HUP captcha_server"

~/.acme.sh/acme.sh --install-cronjob
```

The server watches for `SIGHUP` and atomically reloads TLS certificates
without dropping connections.

### 3. Ed25519 Signing Key

```bash
openssl genpkey -algorithm ed25519 -out certs/ed25519_private.pem
```

This key signs the pass tokens returned to clients after a successful solve.

### 4. GeoIP Database

```bash
mkdir -p /usr/share/GeoIP
wget -O /usr/share/GeoIP/GeoLite2-City.mmdb \
  "https://git.io/GeoLite2-City.mmdb"
```

Override the path with `GEOIP_DB_PATH` if needed.

### 5. Puzzle Images

Place **400×300 JPG images** in `puzzle_images/`. The server loads 200
random images into RAM at startup and hot-swaps banks every ~800 requests.

Minimum recommended: 500 images. The repo ships with 5 sample images.
Generate your own set or use a free stock-photo dataset.

Override the directory with `CAPTCHA_IMAGE_DIR`.

### 6. IP Blocklists

```bash
# Build the IP-list regeneration tool
gcc -O2 -o regenerate_ip regenerate_ip.c -lcurl

# Download and deduplicate malicious IP/CIDR feeds
./regenerate_ip
```

This populates `ip_list/malicious_ip.txt` and `ip_list/malicious_cidr.txt`.
The server auto-rotates these lists daily at 3:00 AM.

### 7. Compile

```bash
gcc -O3 -march=native -flto -ffast-math \
    -Wall -Wextra -Wno-unused-parameter -Wno-deprecated-declarations \
    -pthread -D_GNU_SOURCE -DH2O_USE_ALPN=1 \
    captcha_core.c h2o_server.c ip_functions.c token_functions.c \
    rate_limiting.c send_udp.c ja4_functions.c api_token.c \
    -o captcha_server \
    -lh2o -luv -lssl -lcrypto -lgd -lturbojpeg -ljpeg -lpng -lz \
    -lmaxminddb -lpthread -lm -latomic
```

### 8. Run

```bash
./captcha_server &
```

The server binds port 443 on all interfaces, spawns one worker thread per
CPU core, and pins each worker to a dedicated core.

---

## Directory Structure

```
.
├── captcha_core.c          # Puzzle engine, crypto, trajectory analysis, bot detector
├── captcha_core.h          # Public API + compile-time config
├── h2o_server.c            # HTTP server, route handlers, TLS, worker threads
├── ip_functions.c          # IP reputation: bloom filters, CIDR lookup, datacenter detection
├── ip_functions.h          # IP reputation API
├── token_functions.c       # Ed25519 token sign/verify + anti-replay CMS
├── token_functions.h       # Token API
├── rate_limiting.c         # Per-fingerprint rate limiter (Count-Min Sketch)
├── rate_limiting.h         # Rate limiter API
├── send_udp.c              # UDP telemetry sender (batch-flushed every 5 min)
├── send_udp.h              # UDP API
├── ja4_functions.c         # JA4 / JA4o TLS fingerprint extraction
├── ja4_functions.h         # JA4 API
├── api_token.c             # API-key verification (base-62 + CRC-32)
├── api_token.h             # API token API
├── regenerate_ip.c         # IP/CIDR blocklist downloader
├── certs/                  # TLS certs + Ed25519 key
├── puzzle_images/          # 400×300 JPG background images
└─── ip_list/                # malicious_ip.txt, malicious_cidr.txt
```

---


## Configuration

All tunables are compile-time `#define` macros. Pass them with `-DNAME=VALUE`
on the gcc command line.

## Must change 

LOGS_SERVER_IP --> If you want to use our server for logs, contact us.
                   If not firewall will block the packets.
                   
MY_API_TOKEN   --> Must be len of API_TOKEN_LEN

### Server & Networking — `h2o_server.c`

| Define                  | Default                        | Description                                   |
|-------------------------|--------------------------------|-----------------------------------------------|
| `SERVER_PORT`           | `443`                          | Listening port                                |
| `WORKER_THREADS`        | `8`                            | Number of worker threads (0 = auto-detect)    | 
| `WORKER_CORE_START`     | `0`                            | First CPU core to pin workers to              |
| `TLS_CERT_FILE`         | `certs/fullchain.pem`          | TLS certificate chain path                    |
| `TLS_KEY_FILE`          | `certs/privkey.pem`            | TLS private key path                          |
| `LOGS_SERVER_IP`        | `"159.195.38.167"`             | UDP telemetry destination IP                  |
| `LOGS_SERVER_PORT`      | `5000`                         | UDP telemetry destination port                |

### Proof-of-Work — `h2o_server.c`

| Define                     | Default | Description                              |
|----------------------------|---------|------------------------------------------|
| `POW_DIFFICULTY_SIMPLE`    | `18`    | Leading zero bits for simple PoW         |
| `POW_DIFFICULTY_COMPLEX`   | `19`    | Leading zero bits for complex PoW        |

### Challenge Lifetimes — `h2o_server.c` / `captcha_core.h`

| Define                      | Default | Description                              |
|-----------------------------|---------|------------------------------------------|
| `CHALLENGE_MAX_AGE_SECS`    | `180`   | Seconds a challenge token remains valid  |
| `CAPTCHA_VALIDITY_SECONDS`  | `180`   | Seconds an issued captcha remains valid  |

### Puzzle & Image Engine — `captcha_core.h`

| Define                   | Default         | Description                                   |
|--------------------------|-----------------|-----------------------------------------------|
| `BASE_IMAGE_WIDTH`       | `400`           | Puzzle image width (must match source images) |
| `BASE_IMAGE_HEIGHT`      | `300`           | Puzzle image height                           |
| `PUZZLE_PIECE_SIZE`      | `80`            | Puzzle piece bounding-box size                |
| `NUM_BASE_IMAGES`        | `200`           | Images preloaded into RAM per bank            |
| `POOL_RELOAD_THRESH`     | `800`           | Requests between image-pool bank swaps        |
| `MAX_IMAGE_FILES`        | `8192`          | Max .jpg files scanned in puzzle_images/      |
| `PUZZLE_JPEG_MAX`        | `153600`        | Per-image JPEG buffer ceiling (bytes)         |

### Trajectory Analysis — `captcha_core.h`

| Define                    | Default  | Description                                   |
|---------------------------|----------|-----------------------------------------------|
| `MAX_TRAJECTORY_POINTS`   | `1000`   | Max trajectory points accepted                |
| `TRAJECTORY_TIMEOUT_MS`   | `15000`  | Max total trajectory time (ms)                |
| `MIN_PUZZLE_POINTS`       | `50`     | Minimum trajectory points required            |
| `PUZZLE_TOLERANCE`        | `7`      | Puzzle answer acceptance window (pixels)      |

### Bot Scoring — `h2o_server.c`

| Define                | Default | Description                                 |
|-----------------------|---------|---------------------------------------------|
| `BOT_SCORE_MAX`       | `0.5`   | Max bot score before rejection (complex)    |
| `BOT_SCORE_MAX_SIMP`  | `0.30`  | Max bot score before rejection (simple)     |

### Bloom Filters — `captcha_core.h`

| Define                | Default          | Description                              |
|-----------------------|------------------|------------------------------------------|
| `BLOOM_HASH_FUNCTIONS`| `7`              | Hash functions per token                 |
| `BLOOM_FILTER_SIZE`   | `4194304` (4 Mi) | Token-replay bloom filter slots          |
| `MAX_WORKERS`         | `128`            | Maximum h2o worker threads               |

### Rate Limiting — `rate_limiting.h`

| Define              | Default | Description                                   |
|---------------------|---------|-----------------------------------------------|
| `CMS_DEPTH`         | `4`     | Count-Min Sketch depth                        |
| `CMS_WIDTH`         | `4096`  | Count-Min Sketch width                        |
| `CMS_LIMIT`         | `20`    | Max requests per window (simple challenge)    |
| `CMS_LIMIT_COMPLEX` | `400`   | Max requests per window (complex challenge)   |
| `CMS_RESET_SEC`     | `600`   | Rate-limit window reset interval (seconds)    |

### Token System — `token_functions.h`

| Define                    | Default                    | Description                             |
|---------------------------|----------------------------|-----------------------------------------|
| `TOKEN_PRIVATE_KEY_PATH`  | `certs/ed25519_private.pem`| Ed25519 signing key path                |
| `MAX_COUNT`               | `100`                      | Max token reuse before new challenge    |
| `MAX_MINUTES`             | `30`                       | Token lifetime (minutes)                |
| `TOK_RESET_SEC`           | `3600`                     | Token anti-replay CMS reset interval    |

### IP Reputation — `ip_functions.h`

| Define                     | Default                      | Description                             |
|----------------------------|------------------------------|-----------------------------------------|
| `IP_LIST_PATH`              | `ip_list/malicious_ip.txt`  | Individual malicious IPs                |
| `CIDR_LIST_PATH`            | `ip_list/malicious_cidr.txt`| Malicious CIDR ranges                   |
| `REGENERATE_IP_BIN`         | `./regenerate_ip`           | Path to blocklist updater binary        |
| `REGENERATE_IP_TIMEOUT_SECS`| `300`                       | Max seconds to wait for regeneration    |

### API Token — `api_token.h`

| Define                     | Default                     | Description                             |
|----------------------------|-----------------------------|-----------------------------------------|
| `MY_API_TOKEN`             | `00000000000000000000`      | Set your token for /api/validate        |
| `API_TOKEN_LEN`            | 20                          | Length of MY_API_TOKEN                  |



### Environment Variables

| Variable              | Default                              | Description                          |
|-----------------------|--------------------------------------|--------------------------------------|
| `CAPTCHA_IMAGE_DIR`   | `./puzzle_images`                    | Directory of 400×300 JPG images      |
| `GEOIP_DB_PATH`       | `/usr/share/GeoIP/GeoLite2-City.mmdb`| Path to MaxMind GeoIP database       |

---

## Signal Handling

| Signal   | Effect                                              |
|----------|-----------------------------------------------------|
| `SIGTERM`| Graceful shutdown                                    |
| `SIGINT` | Graceful shutdown (Ctrl+C)                           |
| `SIGHUP` | Atomically reload TLS certificate chain + private key|

---

## Contact

Email: **[hello@captxa.com](mailto:hello@captxa.com)**

Website: **[captxa.com](https://captxa.com)**

---

## License
This captxa code cannot be commercialized 
MIT — see [LICENSE](LICENSE) file.
