/*
 * regenerate_ip.c
 *
 * Descarga todas las listas de IPs/CIDRs maliciosas (IPs maliciosas,
 * VPNs, proxies, datacenters), desduplica y escribe:
 *   - ip_list/malicious_ip.txt   -> IPs individuales (sin '/')
 *   - ip_list/malicious_cidr.txt -> CIDRs (con '/')
 *
 * Compile:
 *   gcc -O2 -o regenerate_ip regenerate_ip.c -lcurl
 *
 * Requires: libcurl-dev
 *   Ubuntu/Debian:  sudo apt install libcurl4-openssl-dev
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/stat.h>
#include <curl/curl.h>


#define OUTPUT_DIR   "ip_list"
#define OUTPUT_IPS   "ip_list/malicious_ip.txt"
#define OUTPUT_CIDRS "ip_list/malicious_cidr.txt"


#define STR_HASH_SIZE  (1u << 23)   /* 8 388 608 buckets */
#define STR_HASH_MASK  (STR_HASH_SIZE - 1)

typedef struct {
    char   **keys;
    size_t   count;
} strset_t;

static uint32_t hash_str(const char *s)
{
    uint32_t h = 2166136261u;
    while (*s) { h ^= (unsigned char)*s++; h *= 16777619u; }
    return h & STR_HASH_MASK;
}

static bool strset_init(strset_t *set)
{
    set->keys  = calloc(STR_HASH_SIZE, sizeof(char *));
    set->count = 0;
    return set->keys != NULL;
}


static bool strset_insert(strset_t *set, const char *key)
{
    uint32_t idx = hash_str(key);
    while (set->keys[idx]) {
        if (strcmp(set->keys[idx], key) == 0) return false;
        idx = (idx + 1) & STR_HASH_MASK;
    }
    set->keys[idx] = strdup(key);
    if (!set->keys[idx]) return false;
    set->count++;
    return true;
}


static void strset_free(strset_t *set)
{
    if (!set->keys) return;
    for (size_t i = 0; i < STR_HASH_SIZE; i++) {
        free(set->keys[i]);
    }
    free(set->keys);
    set->keys = NULL;
    set->count = 0;
}


typedef struct {
    char  *buf;
    size_t len;
    size_t cap;
} membuf_t;

static size_t curl_write(void *data, size_t sz, size_t nmemb, void *userp)
{
    membuf_t *mb = (membuf_t *)userp;
    size_t    n  = sz * nmemb;
    if (mb->len + n + 1 > mb->cap) {
        size_t nc  = mb->cap + n + (4 << 20);
        char  *tmp = realloc(mb->buf, nc);
        if (!tmp) return 0;
        mb->buf = tmp;
        mb->cap = nc;
    }
    memcpy(mb->buf + mb->len, data, n);
    mb->len += n;
    mb->buf[mb->len] = '\0';
    return n;
}


static int normalize_entry(const char *line, char *out, size_t outsz)
{

    while (*line == ' ' || *line == '\t') line++;


    if (!*line || *line == '#' || *line == ';' || *line == '/') return 0;


    const char *p = line;
    while (*p && (*p < '0' || *p > '9')) p++;
    if (!*p) return 0;

    unsigned a, b, c, d;
    int prefix = -1;
    int n = sscanf(p, "%u.%u.%u.%u/%d", &a, &b, &c, &d, &prefix);

    if (n < 4) return 0;
    if (a > 255 || b > 255 || c > 255 || d > 255) return 0;
    if (n == 5 && (prefix < 0 || prefix > 32)) return 0;

    if (n >= 5) {
        /* Es un CIDR: normalizar la direccion de red (aplicar mascara) */
        uint32_t ip32   = ((uint32_t)a << 24) | ((uint32_t)b << 16) |
                          ((uint32_t)c <<  8) |  (uint32_t)d;
        uint32_t mask   = (prefix == 0) ? 0u : (0xFFFFFFFFu << (32 - prefix));
        uint32_t net    = ip32 & mask;
        snprintf(out, outsz, "%u.%u.%u.%u/%d",
                 (net >> 24) & 0xFF, (net >> 16) & 0xFF,
                 (net >>  8) & 0xFF,  net        & 0xFF,
                 prefix);
        return 2;
    } else {

        snprintf(out, outsz, "%u.%u.%u.%u", a, b, c, d);
        return 1;
    }
}


static void fetch_and_parse(CURL *curl, const char *url,
                            strset_t *ip_set, strset_t *cidr_set,
                            size_t *new_ips, size_t *new_cidrs)
{
    membuf_t mb = { NULL, 0, 0 };
    mb.buf = malloc(4 << 20);
    if (!mb.buf) { return; }
    mb.cap = 4 << 20;

    curl_easy_setopt(curl, CURLOPT_URL,            url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,  curl_write);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,      &mb);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,        45L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT,
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");

    CURLcode res = curl_easy_perform(curl);

    *new_ips   = 0;
    *new_cidrs = 0;

    if (res != CURLE_OK) {
        fprintf(stderr, "[ERROR] curl failed for %s: %s\n",
                url, curl_easy_strerror(res));
    } else {
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        if (http_code >= 400) {
            fprintf(stderr, "[ERROR] HTTP %ld for %s\n", http_code, url);
        } else {
            char entry[64];
            char *saveptr = NULL;
            char *line    = strtok_r(mb.buf, "\n", &saveptr);
            while (line) {
                int type = normalize_entry(line, entry, sizeof(entry));
                if (type == 1) {
                    if (strset_insert(ip_set,   entry)) (*new_ips)++;
                } else if (type == 2) {
                    if (strset_insert(cidr_set, entry)) (*new_cidrs)++;
                }
                line = strtok_r(NULL, "\n", &saveptr);
            }
        }
    }
    free(mb.buf);
}


typedef struct { const char *category; const char *url; } source_t;

static const source_t SOURCES[] = {
    /* -- Malicious / compromised --------------------------------------- */
    { "Malicious",  "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt" },
    { "Malicious",  "https://lists.blocklist.de/lists/all.txt" },
    { "Malicious",  "https://www.spamhaus.org/drop/drop.txt" },
    { "Malicious",  "https://www.spamhaus.org/drop/edrop.txt" },
    { "Malicious",  "https://www.binarydefense.com/banlist.txt" },
    { "Malicious",  "https://rules.emergingthreats.net/blockrules/compromised-ips.txt" },
    { "Malicious",  "http://cinsscore.com/list/ci-badguys.txt" },
    /* -- Bots / spam --------------------------------------------------- */
    { "Bots/Spam",  "https://www.stopforumspam.com/downloads/toxic_ip_cidr.txt" },
    { "Bots/Spam",  "https://feodotracker.abuse.ch/downloads/ipblocklist.txt" },
    { "Bots/Spam",  "https://www.botvrij.eu/data/ioclist.ip-dst" },
    { "Bots/Spam",  "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/greensnow.ipset" },
    /* -- Tor ----------------------------------------------------------- */
    { "Tor",        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/tor_exits.ipset" },
    { "Tor",        "https://secureupdates.checkpoint.com/IP-list/TOR.txt" },
    /* -- Anon / proxy -------------------------------------------------- */
    { "Anon/Proxy", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_anonymous.netset" },
    { "Anon/Proxy", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset" },
    { "Anon/Proxy", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset" },
    { "Anon/Proxy", "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt" },
    { "Anon/Proxy", "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt" },
    /* -- VPN providers ------------------------------------------------- */
    { "VPN",        "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt" },
    { "VPN+DC",     "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt" },
    { "ProtonVPN",  "https://raw.githubusercontent.com/tn3w/ProtonVPN-IPs/refs/heads/master/protonvpn_ips.txt" },
    { "ProtonVPN",  "https://raw.githubusercontent.com/scriptzteam/ProtonVPN-VPN-IPs/main/ips" },
    { "Mullvad",    "https://blacklist.thugs.red/services/mullvad/all-addresses.ipv4.csv" },
    /* -- Datacenters / cloud ------------------------------------------- */
    { "Datacenter", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/datacenters.netset" },
    { "Datacenter", "https://raw.githubusercontent.com/jhassine/server-ip-addresses/master/data/datacenters.txt" },
};
#define NUM_SOURCES  (sizeof(SOURCES) / sizeof(SOURCES[0]))


static int cmp_str(const void *a, const void *b)
{
    return strcmp(*(const char **)a, *(const char **)b);
}


static bool write_set(strset_t *set, const char *path)
{
    if (set->count == 0) {

        FILE *f = fopen(path, "w");
        if (f) fclose(f);
        return true;
    }

    char **sorted = malloc(set->count * sizeof(char *));
    if (!sorted) { return false; }

    size_t j = 0;
    for (size_t i = 0; i < STR_HASH_SIZE; i++)
        if (set->keys[i]) sorted[j++] = set->keys[i];

    qsort(sorted, j, sizeof(char *), cmp_str);

    FILE *out = fopen(path, "w");
    if (!out) {
        perror("fopen");
        free(sorted);
        return false;
    }

    for (size_t i = 0; i < j; i++) {
        fprintf(out, "%s\n", sorted[i]);
    }

    fclose(out);
    free(sorted);
    return true;
}


int main(void)
{

    strset_t ip_set, cidr_set;
    if (!strset_init(&ip_set)) {
        fprintf(stderr, "Failed to init ip_set\n");
        return 1;
    }
    if (!strset_init(&cidr_set)) {
        fprintf(stderr, "Failed to init cidr_set\n");
        strset_free(&ip_set);
        return 1;
    }

    curl_global_init(CURL_GLOBAL_DEFAULT);
    CURL *curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Failed to init curl\n");
        strset_free(&ip_set);
        strset_free(&cidr_set);
        return 1;
    }

    for (size_t i = 0; i < NUM_SOURCES; i++) {
        const char *name = strrchr(SOURCES[i].url, '/');
        name = name ? name + 1 : SOURCES[i].url;

        size_t prev_ips   = ip_set.count;
        size_t prev_cidrs = cidr_set.count;
        size_t new_ips, new_cidrs;

        fetch_and_parse(curl, SOURCES[i].url,
                        &ip_set, &cidr_set,
                        &new_ips, &new_cidrs);

        printf("[%s] %s: +%zu IPs, +%zu CIDRs  (total %zu / %zu)\n",
               SOURCES[i].category, name,
               new_ips, new_cidrs,
               ip_set.count, cidr_set.count);
        fflush(stdout);
    }

    curl_easy_cleanup(curl);
    curl_global_cleanup();


    if (mkdir(OUTPUT_DIR, 0755) != 0 && errno != EEXIST) {
        perror("mkdir");
    }


    if (!write_set(&ip_set,   OUTPUT_IPS)) {
        fprintf(stderr, "Failed to write %s\n", OUTPUT_IPS);
        strset_free(&ip_set);
        strset_free(&cidr_set);
        return 1;
    }
    if (!write_set(&cidr_set, OUTPUT_CIDRS)) {
        fprintf(stderr, "Failed to write %s\n", OUTPUT_CIDRS);
        strset_free(&ip_set);
        strset_free(&cidr_set);
        return 1;
    }

    printf("Done.  IPs: %zu  CIDRs: %zu\n", ip_set.count, cidr_set.count);


    strset_free(&ip_set);
    strset_free(&cidr_set);

    return 0;
}
