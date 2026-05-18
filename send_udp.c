#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>       /* getaddrinfo */
#include <arpa/inet.h>

/* Socket fd and pre-resolved destination.
 * Initialized once by initUdpClient(), -1 means "not ready". */
static int               global_udp_fd = -1;
static struct sockaddr_storage  g_dest;
static socklen_t                g_dest_len;

/* ── Run ONCE at startup ────────────────────────────────────────────────── */
bool initUdpClient(const char *ip, int port)
{
    /* Reset in case of re-init */
    if (global_udp_fd >= 0) {
        close(global_udp_fd);
        global_udp_fd = -1;
    }

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct addrinfo hints = {0};
    hints.ai_family   = AF_UNSPEC;   /* accepts both IPv4 and IPv6 */
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags    = AI_NUMERICHOST | AI_NUMERICSERV;

    struct addrinfo *res = NULL;
    int rc = getaddrinfo(ip, port_str, &hints, &res);
    if (rc != 0) {

        return false;   /* global_udp_fd stays -1 → udpSend() is a no-op */
    }

    /* Create the socket matching the resolved address family */
    global_udp_fd = socket(res->ai_family, SOCK_DGRAM, 0);
    if (global_udp_fd < 0) {
        perror("[UDP] initUdpClient: socket");
        freeaddrinfo(res);
        return false;
    }

    /* Snapshot the destination so we don't hold the addrinfo forever */
    memcpy(&g_dest, res->ai_addr, res->ai_addrlen);
    g_dest_len = (socklen_t)res->ai_addrlen;
    freeaddrinfo(res);

    /* Quick sanity: print the resolved address for confirmation */
    char addr_buf[INET6_ADDRSTRLEN];
    void *addr_ptr = (res->ai_family == AF_INET)
        ? (void *)&((struct sockaddr_in  *)&g_dest)->sin_addr
        : (void *)&((struct sockaddr_in6 *)&g_dest)->sin6_addr;
    inet_ntop(res->ai_family, addr_ptr, addr_buf, sizeof(addr_buf));


    return true;
}

/* ── Call per event / per flush ─────────────────────────────────────────── */
bool udpSend(const char *msg)
{
    if (global_udp_fd < 0) return false;   /* init failed or not called */

    ssize_t sent = sendto(global_udp_fd,
                          msg, strlen(msg),
                          0,
                          (struct sockaddr *)&g_dest, g_dest_len);
    if (sent < 0) {
        perror("[UDP] sendto");
        return false;
    }
    return true;
}

/* ── Run ONCE on shutdown ───────────────────────────────────────────────── */
void cleanupUdp(void)
{
    if (global_udp_fd >= 0) {
        close(global_udp_fd);
        global_udp_fd = -1;
    }
}
