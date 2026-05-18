/* ========================================================================== */
/* ip_functions.h - BLOOM FILTER FOR MALICIOUS IP DETECTION                  */
/* ========================================================================== */

#ifndef IP_FUNCTIONS_H
#define IP_FUNCTIONS_H

#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>

/* ── Bloom filter — IPs individuales ─────────────────────────────────────── */
/* Sized for 3 M IPs, k=10 → FP rate ≈ 2×10⁻⁷ %                            */
#define IP_BLOOM_BITS   (1u << 27)           /* 128 Mi-bits = 16 MiB         */
#define IP_BLOOM_BYTES  (IP_BLOOM_BITS >> 3) /* 16 777 216 bytes             */
#define IP_BLOOM_K      10

/* ── Bloom filter — CIDRs maliciosos ─────────────────────────────────────── */
/* Sized for 200 k CIDRs, k=10 → FP rate despreciable con 512 KiB           */
#define CIDR_BLOOM_BITS   (1u << 23)             /* 4 Mi-bits = 512 KiB      */
#define CIDR_BLOOM_BYTES  (CIDR_BLOOM_BITS >> 3) /* 524 288 bytes            */
#define CIDR_BLOOM_K      10

/* ── Paths ───────────────────────────────────────────────────────────────── */
#define IP_LIST_PATH               "ip_list/malicious_ip.txt"
#define CIDR_LIST_PATH             "ip_list/malicious_cidr.txt"
#define REGENERATE_IP_BIN          "./regenerate_ip"
#define REGENERATE_IP_TIMEOUT_SECS 300

/* ── Public API ──────────────────────────────────────────────────────────── */

/*
 * ip_bloom_init()
 * Aloja ambos double-buffers (IP + CIDR) y carga los ficheros en buffer[0].
 * Retorna nº de IPs cargadas, o -1 en error fatal.
 */
int  ip_bloom_init(void);

/*
 * ip_bloom_is_suspicious()
 * Thread-safe, lock-free. Comprueba: datacenter estático → CIDR bloom → IP bloom.
 * Retorna true si la IP es sospechosa (probable positivo).
 */
bool ip_bloom_is_suspicious(const char *ip_str);

/*
 * ip_is_datacenter()
 * Comprueba la tabla CIDR estática de proveedores cloud (AWS, GCP, Azure...).
 * Thread-safe: solo lee datos estáticos const.
 */
bool ip_is_datacenter(const char *ip_str);

/*
 * ip_bloom_destroy()
 * Libera todos los buffers. Seguro si init nunca fue llamado.
 */
void ip_bloom_destroy(void);

/*
 * ip_bloom_start_rotation_thread()
 * Lanza el hilo de rotación a las 3:00 AM. Llamar una vez tras ip_bloom_init().
 */
void ip_bloom_start_rotation_thread(void);

#endif /* IP_FUNCTIONS_H */
