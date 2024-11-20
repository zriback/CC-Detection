#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h> /* for NF_ACCEPT */

#include <arpa/inet.h> /* for inet_ntoa */
#include <time.h>      /* for time functions */

#include <stdint.h>
#include <sys/types.h>

#include <openssl/evp.h> /* For EVP encryption */
#include <openssl/err.h>

/* Define the conn_info struct */
typedef struct conn_info {
    uint32_t client_ip;
    uint32_t server_ip;
    uint16_t client_port;
    uint16_t server_port;
    int32_t seq_offset;        // Difference between original and modified sequence numbers
    int fin_sent;              // Flag indicating if FIN has been sent by the client
    int fin_received;          // Flag indicating if FIN has been received from the server
    int closing;               // Flag indicating next ACK sent the conn will be closed
    time_t last_activity;      // Timestamp of the last activity
    struct conn_info *next;
} conn_info_t;

/* Head of the linked list to store active connections */
conn_info_t *conn_list_head = NULL;

/* Specify the target IP address */
const char *target_ip_str = "10.30.0.2"; /* Replace with your target IP */
uint32_t target_ip = 0;

/* AES key (must be 128 bits for AES-128) */
const unsigned char aes_key[16] = "mykey123"; /* Replace with your key */

/* Contains message to be sent */
unsigned char *message_buffer = NULL;
size_t message_length = 0;
size_t message_index = 0;
uint8_t message_number = 0; /* Message counter starting from 0 */


/* Function to find a connection in the list */
conn_info_t *find_connection(uint32_t client_ip, uint16_t client_port, uint32_t server_ip, uint16_t server_port) {
    conn_info_t *current = conn_list_head;
    while (current) {
        if (current->client_ip == client_ip && current->client_port == client_port &&
            current->server_ip == server_ip && current->server_port == server_port) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

/* Function to create a connection */
conn_info_t *create_connection(uint32_t client_ip, uint16_t client_port, uint32_t server_ip, uint16_t server_port) {
    conn_info_t *new_conn = (conn_info_t *)malloc(sizeof(conn_info_t));
    if (!new_conn) {
        fprintf(stderr, "Failed to allocate memory for new connection\n");
        exit(1);
    }
    new_conn->client_ip = client_ip;
    new_conn->client_port = client_port;
    new_conn->server_ip = server_ip;
    new_conn->server_port = server_port;
    new_conn->seq_offset = 0;
    new_conn->fin_sent = 0;
    new_conn->fin_received = 0;
    new_conn->closing = 0;
    new_conn->last_activity = time(NULL);
    new_conn->next = conn_list_head;
    conn_list_head = new_conn;
    return new_conn;
}

/* Function to remove a connection from the list */
void remove_connection(conn_info_t *conn) {
    conn_info_t **current = &conn_list_head;
    while (*current) {
        if (*current == conn) {
            *current = conn->next;
            free(conn);
            return;
        }
        current = &(*current)->next;
    }
}

/* Function to recalculate TCP checksum */
unsigned short tcp_checksum(struct iphdr *ipHeader, struct tcphdr *tcpHeader) {
    unsigned short *buf;
    unsigned int tcpLen = ntohs(ipHeader->tot_len) - ipHeader->ihl * 4;
    unsigned long sum = 0;

    // Pseudo-header fields
    struct pseudo_header {
        unsigned int src_addr;
        unsigned int dst_addr;
        unsigned char zero;
        unsigned char protocol;
        unsigned short tcp_length;
    } pseudoHeader;

    pseudoHeader.src_addr = ipHeader->saddr;
    pseudoHeader.dst_addr = ipHeader->daddr;
    pseudoHeader.zero = 0;
    pseudoHeader.protocol = IPPROTO_TCP;
    pseudoHeader.tcp_length = htons(tcpLen);

    // Calculate the checksum
    buf = (unsigned short *)&pseudoHeader;
    sum += buf[0];
    sum += buf[1];
    sum += buf[2];
    sum += buf[3];
    sum += buf[4];
    sum += buf[5];

    buf = (unsigned short *)tcpHeader;
    while (tcpLen > 1) {
        sum += *buf++;
        tcpLen -= 2;
    }
    if (tcpLen > 0) {
        sum += *((unsigned char *)buf);
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

/* Function to recalculate IP checksum */
unsigned short ip_checksum(unsigned short *buf, int nwords) {
    unsigned long sum = 0;
    for (; nwords > 0; nwords--) {
        sum += *buf++;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

/* Function to clean up stale connections */
#define CONNECTION_TIMEOUT 60  // Timeout in seconds

void cleanup_stale_connections() {
    conn_info_t **current = &conn_list_head;
    time_t now = time(NULL);
    while (*current) {
        conn_info_t *entry = *current;
        if ((now - entry->last_activity) > CONNECTION_TIMEOUT) {
            // Remove stale connection
            *current = entry->next;
            free(entry);
        } else {
            current = &entry->next;
        }
    }
}

static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                    struct nfq_data *nfa, void *data)
{
    unsigned char *packetData;
    int packetLen;
    struct nfqnl_msg_packet_hdr *ph;
    uint32_t id = 0;

    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
    }

    packetLen = nfq_get_payload(nfa, &packetData);
    if (packetLen >= 0) {
        // Parse IP header
        struct iphdr *ipHeader = (struct iphdr *)packetData;
        int ipHeaderLen = ipHeader->ihl * 4;

        if (ipHeader->protocol == IPPROTO_TCP && (ipHeader->saddr == target_ip || ipHeader->daddr == target_ip)) {
            // Parse TCP header
            struct tcphdr *tcpHeader = (struct tcphdr *)(packetData + ipHeaderLen);

            // Convert values from network byte order to host byte order
            uint16_t srcPort = ntohs(tcpHeader->source);
            uint16_t dstPort = ntohs(tcpHeader->dest);
            uint32_t seqNum = ntohl(tcpHeader->seq);
            uint32_t ackNum = ntohl(tcpHeader->ack_seq);

            // Extract flags
            uint8_t flags = tcpHeader->th_flags;

            // Flags
            uint8_t fin = (flags & TH_FIN) ? 1 : 0;
            uint8_t syn = (flags & TH_SYN) ? 1 : 0;
            uint8_t rst = (flags & TH_RST) ? 1 : 0;

            // Get source and destination IP addresses
            uint32_t srcIP = ipHeader->saddr;
            uint32_t dstIP = ipHeader->daddr;

            // Determine packet direction
            int is_outgoing = (srcIP != target_ip);

            // Define client and server IPs and ports
            uint32_t client_ip, server_ip;
            uint16_t client_port, server_port;

            if (is_outgoing) {
                client_ip = srcIP;
                client_port = srcPort;
                server_ip = dstIP;
                server_port = dstPort;
            } else {
                client_ip = dstIP;
                client_port = dstPort;
                server_ip = srcIP;
                server_port = srcPort;
            }

            conn_info_t *conn = find_connection(client_ip, client_port, server_ip, server_port);

            if (is_outgoing) {
                // Outgoing packets (from client to server)
                if (syn && !tcpHeader->ack) {
                    // SYN packet, create new connection
                    conn = create_connection(client_ip, client_port, server_ip, server_port);

                    /* Read up to three bytes from message_buffer */
                    unsigned char message_bytes[3] = {0, 0, 0};
                    int bytes_left = message_length - message_index;
                    int valid_char_count = 0;

                    if (bytes_left >= 3) {
                        for (int i = 0; i < 3; ++i) {
                            message_bytes[i] = message_buffer[message_index++];
                        }
                        valid_char_count = 3;
                    } else if (bytes_left > 0) {
                        for (int i = 0; i < bytes_left; ++i) {
                            message_bytes[i] = message_buffer[message_index++];
                        }
                        valid_char_count = bytes_left;
                    } else {
                        /* No more data, set valid_char_count to 0 */
                        valid_char_count = 0;
                        message_bytes[0] = message_bytes[1] = message_bytes[2] = 0;
                    }

                    /* Adjust message_index if it reaches the end */
                    if (message_index >= message_length) {
                        message_index = 0; /* Wrap around to the beginning */
                    }

                    /* Map valid_char_count to bits */
                    uint8_t valid_char_count_bits = 0;
                    switch (valid_char_count) {
                        case 1: valid_char_count_bits = 0x01; break;
                        case 2: valid_char_count_bits = 0x02; break;
                        case 3: valid_char_count_bits = 0x03; break;
                        default: valid_char_count_bits = 0x00; break;
                    }

                    /* Construct the first byte */
                    uint8_t first_byte = ((message_number & 0x3F)) | (valid_char_count_bits << 6);

                    /* Create covert_ISN */
                    uint32_t covert_ISN = 0;
                    covert_ISN |= ((uint32_t)first_byte) << 24;         /* First byte (MSB) */
                    covert_ISN |= ((uint32_t)message_bytes[0]) << 16;   /* Second byte */
                    covert_ISN |= ((uint32_t)message_bytes[1]) << 8;    /* Third byte */
                    covert_ISN |= ((uint32_t)message_bytes[2]);         /* Fourth byte (LSB) */

                    /* XOR encryption_mask and covert_ISN to get final_ISN */
                    uint32_t final_ISN = covert_ISN ^ 0b10100110101001101010011010100110;

                    /* Calculate sequence number offset */
                    int32_t seq_offset = final_ISN - seqNum;
                    conn->seq_offset = seq_offset;

                    /* Modify the TCP sequence number */
                    tcpHeader->seq = htonl(final_ISN);

                    /* Recalculate TCP checksum */
                    tcpHeader->check = 0; /* Reset checksum */
                    tcpHeader->check = tcp_checksum(ipHeader, tcpHeader);

                    /* Recalculate IP checksum */
                    ipHeader->check = 0;
                    ipHeader->check = ip_checksum((unsigned short *)ipHeader, ipHeader->ihl * 2);

                    /* Increment message_number and wrap around at 64 */
                    message_number = (message_number + 1) % 64;
                } else if (conn && conn->seq_offset != 0) {
                    // For other outgoing packets, adjust sequence numbers
                    seqNum += conn->seq_offset;
                    tcpHeader->seq = htonl(seqNum);

                    /* Recalculate TCP checksum */
                    tcpHeader->check = 0; /* Reset checksum */
                    tcpHeader->check = tcp_checksum(ipHeader, tcpHeader);

                    /* Recalculate IP checksum */
                    ipHeader->check = 0;
                    ipHeader->check = ip_checksum((unsigned short *)ipHeader, ipHeader->ihl * 2);
                }
            } else {
                // Incoming packets (from server to client)
                if (conn && conn->seq_offset != 0) {
                    // Adjust acknowledgment number
                    ackNum -= conn->seq_offset;
                    tcpHeader->ack_seq = htonl(ackNum);

                    /* Recalculate TCP checksum */
                    tcpHeader->check = 0; /* Reset checksum */
                    tcpHeader->check = tcp_checksum(ipHeader, tcpHeader);

                    /* Recalculate IP checksum */
                    ipHeader->check = 0;
                    ipHeader->check = ip_checksum((unsigned short *)ipHeader, ipHeader->ihl * 2);
                }
            }

            // Update last activity time
            if (conn) {
                conn->last_activity = time(NULL);
            }

            // Detect connection termination (FIN or RST packets)
            if (fin || rst) {
                if (conn) {
                    if (rst) {
                        // If RST is detected, remove the connection immediately
                        remove_connection(conn);
                    } else if (fin) {
                        if (is_outgoing) {
                            // FIN sent by client
                            conn->fin_sent = 1;
                        } else {
                            // FIN received from server
                            conn->fin_received = 1;
                        }
                        if (conn->fin_sent && conn->fin_received) {
                            // Both FIN packets have been seen, mark the connection as closing
                            conn->closing = 1;
                        }
                    }
                }
            }

            if (conn && conn->closing){
                if (is_outgoing && !fin && !rst){
                    if (tcpHeader->ack && !syn && !fin){
                        remove_connection(conn);
                    }

                }
            }

            /* Accept the modified packet */
            return nfq_set_verdict(qh, id, NF_ACCEPT, packetLen, packetData);
        }
    }

    // Accept the packet without modification
    return nfq_set_verdict(qh, id, NF_ACCEPT, packetLen, packetData);
}

int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__((aligned));

    /* Initialize target IP bits */
    target_ip = inet_addr(target_ip_str);

    /* Initialize OpenSSL */
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    printf("Opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "Error during nfq_open()\n");
        exit(1);
    }

    printf("Unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "Error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("Binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "Error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("Binding this socket to queue '0'\n");
    qh = nfq_create_queue(h, 0, &callback, NULL);
    if (!qh) {
        fprintf(stderr, "Error during nfq_create_queue()\n");
        exit(1);
    }

    printf("Setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "Can't set packet_copy mode\n");
        exit(1);
    }

    /* Read the entire message from message.txt */
    FILE *message_file = fopen("message.txt", "rb");
    if (!message_file) {
        perror("Failed to open message.txt");
        exit(1);
    }

    /* Determine the file size */
    fseek(message_file, 0, SEEK_END);
    message_length = ftell(message_file);
    fseek(message_file, 0, SEEK_SET);

    /* Allocate buffer */
    message_buffer = (unsigned char *)malloc(message_length);
    if (!message_buffer) {
        perror("Failed to allocate memory for message buffer");
        fclose(message_file);
        exit(1);
    }

    /* Read data into buffer */
    size_t bytes_read = fread(message_buffer, 1, message_length, message_file);
    if (bytes_read != message_length) {
        fprintf(stderr, "Failed to read entire message file\n");
        fclose(message_file);
        free(message_buffer);
        exit(1);
    }

    /* Close the file */
    fclose(message_file);

    message_index = 0;

    printf("message buffer is %s", message_buffer);

    fd = nfq_fd(h);

    printf("Starting packet processing loop\n");
    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
        nfq_handle_packet(h, buf, rv);
        // Periodically clean up stale connections
        cleanup_stale_connections();
    }

    printf("Unbinding from queue 0\n");
    nfq_destroy_queue(qh);

    printf("Closing library handle\n");
    nfq_close(h);

    /* Clean up OpenSSL */
    EVP_cleanup();
    ERR_free_strings();

    if (message_buffer) {
        free(message_buffer);
    }

    return 0;
}

