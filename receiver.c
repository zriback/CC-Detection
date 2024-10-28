#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ether.h>  // For Ethernet header
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <openssl/evp.h>
#include <openssl/err.h>

/* AES key (must be 128 bits for AES-128) */
const unsigned char aes_key[16] = "mykey123"; /* Use the same key as the sender */

/* File pointer to write to secret_message.txt */
FILE *secret_message_file = NULL;

/* Specify the sender IP address */
const char *sender_ip_str = "192.168.243.139";
uint32_t sender_ip;

/* Specify my IP address to make sure packetes are actually addressed to the receiver */
const char* my_ip_str = "192.168.243.138";

/* Variables to keep track of message reconstruction */
unsigned char *reconstructed_message = NULL;
size_t reconstructed_length = 0;
uint8_t expected_message_number = 0; /* Starts from 0 */

void initialize_openssl() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

void cleanup_openssl() {
    EVP_cleanup();
    ERR_free_strings();
}

uint32_t create_encryption_mask(uint16_t src_port, uint16_t dst_port, uint32_t src_ip, uint32_t dst_ip) {
    unsigned char data[16];  /* 128 bits */
    unsigned char input[8];  /* 64 bits */
    unsigned char output[16]; /* Output buffer for encryption */
    int outlen = 0;

    /* 16 bits that make the characters "CC" */
    input[0] = 'C';
    input[1] = 'C';

    /* 16-bit output from XORing the source port and destination port */
    uint16_t port_xor = src_port ^ dst_port;
    input[2] = (port_xor >> 8) & 0xFF;
    input[3] = port_xor & 0xFF;

    /* 32 bits from XORing the source IP and destination IP */
    uint32_t ip_xor = src_ip ^ dst_ip;
    input[4] = (ip_xor >> 24) & 0xFF;
    input[5] = (ip_xor >> 16) & 0xFF;
    input[6] = (ip_xor >> 8) & 0xFF;
    input[7] = ip_xor & 0xFF;

    /* Double it to make it 128 bits */
    memcpy(data, input, 8);
    memcpy(data + 8, input, 8);

    /* Initialize OpenSSL EVP context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create EVP_CIPHER_CTX\n");
        return 0;
    }

    /* Initialize encryption operation */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, aes_key, NULL)) {
        fprintf(stderr, "EVP_EncryptInit_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    /* Disable padding to ensure output size is same as input */
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    /* Perform encryption */
    if (1 != EVP_EncryptUpdate(ctx, output, &outlen, data, sizeof(data))) {
        fprintf(stderr, "EVP_EncryptUpdate failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    /* Finalize encryption */
    int tmplen = 0;
    if (1 != EVP_EncryptFinal_ex(ctx, output + outlen, &tmplen)) {
        fprintf(stderr, "EVP_EncryptFinal_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    outlen += tmplen;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    /* Take the first 32 bits of the output as encryption_mask */
    uint32_t encryption_mask = (output[0] << 24) | (output[1] << 16) | (output[2] << 8) | output[3];
    return encryption_mask;
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // Ethernet header is 14 bytes
    const struct ether_header *eth_header = (struct ether_header *)packet;

    // Check if the packet is IP
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return; // Not an IP packet
    }

    // IP header starts after Ethernet header
    const struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ether_header));

    // Check if the packet is TCP
    if (ip_header->protocol != IPPROTO_TCP) {
        return; // Not a TCP packet
    }

    // Calculate IP header length
    int ip_header_len = ip_header->ihl * 4;

    // TCP header starts after IP header
    const struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_header_len);

    // Check if the packet is a SYN packet
    if (tcp_header->syn && !tcp_header->ack) {
        // Get source and destination IP addresses
        uint32_t src_ip = ip_header->saddr;
        uint32_t dst_ip = ip_header->daddr;

        // Convert sender IP string to uint32_t
        uint32_t sender_ip_addr = inet_addr(sender_ip_str);

        // Check if the packet is from the specified sender IP
        if (src_ip == sender_ip_addr) {
            // Get source and destination ports
            uint16_t src_port = ntohs(tcp_header->source);
            uint16_t dst_port = ntohs(tcp_header->dest);

            // Get the received ISN
            uint32_t received_isn = ntohl(tcp_header->seq);

            // Compute the encryption mask
            uint32_t encryption_mask = create_encryption_mask(src_port, dst_port, src_ip, dst_ip);

            // Compute the covert ISN
            uint32_t covert_isn = received_isn ^ encryption_mask;

            // Extract the first byte (MSB)
            uint8_t first_byte = (covert_isn >> 24) & 0xFF;

            // Extract message number (bits 5-0)
            uint8_t message_number = first_byte & 0x3F;

            // Extract valid character count bits (bits 7-6)
            uint8_t valid_char_count_bits = (first_byte >> 6) & 0x03;

            // Map valid_char_count_bits to valid_char_count
            int valid_char_count = 0;
            switch (valid_char_count_bits) {
                case 0x00: valid_char_count = 0; break;
                case 0x01: valid_char_count = 1; break;
                case 0x02: valid_char_count = 2; break;
                case 0x03: valid_char_count = 3; break;
                default: valid_char_count = 0; break;
            }

            // Check if the message number matches the expected message number
            // If it does not, this is likely not a correct packet
            if (message_number != expected_message_number) {
                printf("Unexpected message number. Expected %u, got %u. Discarding packet.\n", expected_message_number, message_number);
                return; // Discard out-of-order message
            }

            // Extract the message bytes
            unsigned char message_bytes[3] = {0, 0, 0};

            if (valid_char_count >= 1) {
                message_bytes[0] = (covert_isn >> 16) & 0xFF; // Second byte
            }
            if (valid_char_count >= 2) {
                message_bytes[1] = (covert_isn >> 8) & 0xFF;  // Third byte
            }
            if (valid_char_count == 3) {
                message_bytes[2] = covert_isn & 0xFF;         // Fourth byte
            }

            // Append the valid characters to the reconstructed message
            reconstructed_message = realloc(reconstructed_message, reconstructed_length + valid_char_count);
            if (!reconstructed_message) {
                fprintf(stderr, "Failed to allocate memory for reconstructed message\n");
                exit(EXIT_FAILURE);
            }
            memcpy(reconstructed_message + reconstructed_length, message_bytes, valid_char_count);
            reconstructed_length += valid_char_count;

            // Open the secret_message.txt file in write mode if not already open
            if (!secret_message_file) {
                secret_message_file = fopen("secret_message.txt", "wb");
                if (!secret_message_file) {
                    perror("Failed to open secret_message.txt");
                    exit(EXIT_FAILURE);
                }
            }

            // Write the valid characters to the file
            fwrite(message_bytes, sizeof(unsigned char), valid_char_count, secret_message_file);
            fflush(secret_message_file); // Ensure data is written to disk

            // Print the extracted characters
            printf("Extracted characters: ");
            for (int i = 0; i < valid_char_count; i++) {
                printf("%c", message_bytes[i]);
            }
            printf("\n");

            // Print the whole message so far
            printf("Message so far: ");
            for (size_t i = 0; i < reconstructed_length; i++) {
                printf("%c", reconstructed_message[i]);
            }
            printf("\n\n");

            // Increment expected_message_number and wrap around at 64
            expected_message_number = (expected_message_number + 1) % 64;
        }
    }
}

int main(int argc, char *argv[]) {
    char *dev = NULL;             /* Capture device name */
    char errbuf[PCAP_ERRBUF_SIZE];/* Error buffer */
    pcap_t *handle;               /* Packet capture handle */
    char filter_exp[256];         /* Filter expression */
    struct bpf_program fp;        /* Compiled filter program */
    bpf_u_int32 mask;             /* Subnet mask */
    bpf_u_int32 net;              /* IP */
    int num_packets = 0;          /* Capture indefinitely */
    pcap_if_t *alldevs, *d;

    /* Initialize OpenSSL */
    initialize_openssl();

    /* Convert sender IP string to uint32_t */
    sender_ip = inet_addr(sender_ip_str);

    /* Find all available devices */
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    /* Select the first device if none is specified */
    if (argc < 2) {
        if (alldevs == NULL) {
            fprintf(stderr, "No devices found. Make sure you have the right privileges.\n");
            return EXIT_FAILURE;
        }
        dev = alldevs->name;
        printf("No device specified. Using the first device: %s\n", dev);
    } else {
        dev = argv[1];
    }

    /* Get the network address and netmask for the capture device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    /* Open capture device */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        pcap_freealldevs(alldevs);
        return EXIT_FAILURE;
    }

    /* Check if the link layer is Ethernet */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", dev);
        pcap_freealldevs(alldevs);
        return EXIT_FAILURE;
    }

    /* Compile and apply the filter */
    snprintf(filter_exp, sizeof(filter_exp), "tcp[tcpflags] & tcp-syn != 0 and src host %s and dst host %s", sender_ip_str, my_ip_str);
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_freealldevs(alldevs);
        return EXIT_FAILURE;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_freealldevs(alldevs);
        return EXIT_FAILURE;
    }

    printf("Listening on device %s, filter: %s\n", dev, filter_exp);

    /* Free the device list */
    pcap_freealldevs(alldevs);

    /* Start packet processing loop */
    pcap_loop(handle, num_packets, packet_handler, NULL);

    /* Clean up */
    pcap_freecode(&fp);
    pcap_close(handle);

    if (secret_message_file) {
        fclose(secret_message_file);
    }
    if (reconstructed_message) {
        free(reconstructed_message);
    }

    /* Clean up OpenSSL */
    cleanup_openssl();

    printf("Capture complete.\n");

    return EXIT_SUCCESS;
}
