#ifndef SEND_UDP_H
#define SEND_UDP_H

#include <stdbool.h>

/**
 * @brief Sets up the global socket and target server address.
 * * Call this once at the start of your program.
 * * @param ip   The destination IP address (e.g., "192.168.1.10").
 * @param port The destination port (e.g., 5005).
 * @return true if the socket is ready, false if something went wrong.
 */
bool initUdpClient(const char* ip, int port);

/**
 * @brief Sends a message via the existing UDP socket.
 * * Since the socket is already open, this is very fast.
 * * @param msg The string to be sent.
 * @return true if sent successfully, false on error.
 */
bool udpSend(char *msg);

/**
 * @brief Closes the socket and cleans up resources.
 * * Call this before your program exits.
 */
void cleanupUdp(void);

#endif // SEND_UDP_H
