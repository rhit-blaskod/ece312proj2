// Partners: Tanner Staus, Deagan Blasko
// Date modified: 2-14-2026
// Title: udp client code


#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <sys/time.h>

#define SERVER "137.112.38.47"
#define PORT 2526
#define BUFSIZE 1024
#define RHP_VER 12
#define RHP_CONTROL_TYPE 0
#define RHP_RHMP_TYPE 4
#define RHP_CONTROL_DST_PORT 0x1874
#define RHP_RHMP_DST_PORT 0x0ECE
#define SRC_PORT 1183
#define RHMP_COMM_ID 0x312
#define RHMP_MESSAGE_REQUEST 4
#define RHMP_MESSAGE_RESPONSE 6
#define RHMP_ID_REQUEST 16
#define RHMP_ID_RESPONSE 24


#pragma pack(push, 1)
//define structs for RHP header and RHMP header
typedef struct {
    uint8_t version;
    uint16_t srcPort;
    uint16_t dstPort;
    uint16_t len_and_type;
    uint8_t buff;
} RHPHeader;

typedef struct {
    uint16_t commID_low;
    uint8_t type_len_high;
    uint8_t len_low;
} RHMPHeader;
#pragma pack(pop)

// method for calculating checksum
uint16_t calc_checksum(uint8_t *data, int len) {
    uint32_t sum = 0;
    for(int i = 0; i < len - 1; i += 2) {
        uint16_t word = (data[i] << 8) | data[i + 1];
        sum += word;
        if(sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }

    if(len % 2 == 1) {
        sum += (data[len-1] << 8);
        if(sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }

    return (uint16_t) (~sum);
}

// method to create rhp packet
int create_rhp_control_packet(uint8_t *packet, const char *payload, uint16_t srcPort) {
    int payload_len = strlen(payload);
    int needs_padding = (payload_len % 2 == 1) ? 1 : 0;
    int packet_len = 7 + needs_padding + payload_len + 2;
    int offset = 0;
    
    // construct rhp
    memset(packet, 0, packet_len);
    packet[offset++] = RHP_VER;
    packet[offset++] = srcPort & 0xFF;
    packet[offset++] = (srcPort >> 8) & 0xFF;
    packet[offset++] = RHP_CONTROL_DST_PORT & 0xFF;
    packet[offset++] = (RHP_CONTROL_DST_PORT >> 8) & 0xFF;
    uint16_t length_type = (payload_len & 0x0FFF) | ((RHP_CONTROL_TYPE & 0x0F) << 12);
    packet[offset++] = length_type & 0xFF;
    packet[offset++] = (length_type >> 8) & 0xFF;

    if(needs_padding) {
        packet[offset++] = 0x00;
    }

    memcpy(&packet[offset], payload, payload_len);
    offset += payload_len; 
    
    // calculate checksum as last step
    uint16_t checksum = calc_checksum(packet, offset);
    packet[offset++] = checksum & 0xFF;
    packet[offset++] = (checksum >> 8) & 0xFF;

    return packet_len;
}

// method to create rhmp packet
int create_rhmp_packet(uint8_t *packet, uint8_t rhmp_type, uint8_t *rhmp_payload, 
                        uint16_t rhmp_payload_len, uint16_t srcPort) {
    int offset = 0;
    int rhmp_total_len = 4 + rhmp_payload_len;
    int needs_padding = (rhmp_total_len % 2 == 1) ? 1 : 0;
    int packet_len = 7 + needs_padding + rhmp_total_len + 2;
    
    // construct rhmp packet
    memset(packet, 0, packet_len);
    packet[offset++] = RHP_VER;
    packet[offset++] = srcPort & 0xFF;
    packet[offset++] = (srcPort >> 8) & 0xFF;
    packet[offset++] = RHP_RHMP_DST_PORT & 0xFF;
    packet[offset++] = (RHP_RHMP_DST_PORT >> 8) & 0xFF;
    uint16_t length_type = (rhmp_total_len & 0x0FFF) | ((RHP_RHMP_TYPE & 0x0F) << 12);
    packet[offset++] = length_type & 0xFF;
    packet[offset++] = (length_type >> 8) & 0xFF;

    if(needs_padding) {
        packet[offset++] = 0x00;
    }

    packet[offset++] = RHMP_COMM_ID & 0xFF;
    packet[offset++] = ((RHMP_COMM_ID >> 8) & 0x3F) | ((rhmp_type & 0x30) << 2);
    packet[offset++] = ((rhmp_type & 0x0F) << 4) | ((rhmp_payload_len >> 8) & 0x0F); 
    packet[offset++] = rhmp_payload_len & 0xFF;

    if(rhmp_payload_len > 0) {
        memcpy(&packet[offset], rhmp_payload, rhmp_payload_len);
        offset += rhmp_payload_len;
    }
    
    // calculate checksum as final step
    uint16_t checksum = calc_checksum(packet, offset);
    packet[offset++] = checksum & 0xFF;
    packet[offset++] = (checksum >> 8) & 0xFF;

    return packet_len;
}

// verify checksum using the existing calculate checksum method
int verify_checksum(uint8_t *packet, int len) {
    uint16_t result = calc_checksum(packet, len);
    return (result == 0);
}

// method to parse response to sent rhp packet
void parse_rhp_response(uint8_t *packet, int len, int message_num) {
    int offset = 0;
    uint8_t version = packet[offset++]; 
    uint16_t srcPort = packet[offset] | (packet[offset + 1] << 8);
    offset += 2;
    uint16_t dstPort = packet[offset] | (packet[offset + 1] << 8);
    offset += 2;
    uint16_t length_type = packet[offset] | (packet[offset + 1] << 8);
    offset += 2;
    uint16_t payload_len = length_type & 0x0FFF; 
    uint8_t type = (length_type >> 12) & 0x0F;
    
    int has_padding = (payload_len % 2 == 1) ? 1 : 0;
    if(has_padding) {
        offset++;
    }
    
    // print out message metadata
    printf("\n========== Message %d Response ==========\n", message_num);
    printf("RHP Header:\n");
    printf("  Version: %u\n", version);
    printf("  RHP Type: %u", type);
    if(type == RHP_CONTROL_TYPE) {
        printf(" (Control)\n");
    } else if(type == RHP_RHMP_TYPE) {
        printf(" (RHMP)\n");
    } else {
        printf("\n");
    }
    printf("  Communication ID: %u (0x%X)\n", srcPort, srcPort);
    printf("  Payload Length: %u\n", payload_len);

    // print out payload if type RHP
    if(type == RHP_CONTROL_TYPE) {
            char payload[BUFSIZE] = {0};
        if(payload_len > 0 && offset + payload_len <= len - 2) {
            memcpy(payload, &packet[offset], payload_len);
            payload[payload_len] = '\0';
            printf("  Payload: \"%s\"\n", payload);
        }
        offset += payload_len;
    }
    // print out RHMP header and response
    else if(type == RHP_RHMP_TYPE) {
        if(payload_len >= 4) {
            uint16_t commID = packet[offset] | ((packet[offset + 1] & 0x3F) << 8);
            uint16_t rhmp_type = ((packet[offset + 1] & 0xC0) >> 2) | ((packet[offset + 2] & 0xF0) >> 4);
            uint16_t rhmp_len = ((packet[offset + 2] & 0x0F) << 8) | packet[offset + 3];
            offset += 4;
            printf("\nRHMP Header:\n");
            printf("  Communication ID: %u (0x%X)\n", commID, commID);
            printf("  RHMP Type: %u", rhmp_type);
            if(rhmp_type == RHMP_MESSAGE_RESPONSE) {
                printf(" (Message_Response)\n");
            } else if(rhmp_type == RHMP_ID_RESPONSE) {
                printf(" (ID_Response)\n");
            } else {
                printf("\n");
            }
            printf("  RHMP Payload Length: %u\n", rhmp_len);

            if(rhmp_type == RHMP_MESSAGE_RESPONSE && rhmp_len > 0) {
                char rhmp_payload[BUFSIZE] = {0};
                if(offset + rhmp_len <= len - 2) {
                    memcpy(rhmp_payload, &packet[offset], rhmp_len);
                    rhmp_payload[rhmp_len] = '\0';
                    printf("  RHMP Payload: \"%s\"\n", rhmp_payload);
                }
                offset += rhmp_len;
            } else if(rhmp_type == RHMP_ID_RESPONSE && rhmp_len == 4) {
                uint32_t id = packet[offset] | (packet[offset + 1] << 8) | (packet[offset + 2] << 16) |
                (packet[offset + 3] << 24);
                printf("  RHMP Payload (ID): %u (0x%X)\n", id, id);
                offset += rhmp_len;
            }
        }
    }
    
    // verify checksum
    uint16_t checksum = packet[len - 2] | (packet[len - 1] << 8);
    int checksum_valid = verify_checksum(packet, len);
    printf("\nChecksum: 0x%04X\n", checksum);
    if(checksum_valid) {
        printf("Checksum: PASSED\n");
    } else {
        printf("Checksum: FAILED\n");
    }
    
}

int send_and_receive(int clientSocket, uint8_t *tx_buffer, int packet_len, uint8_t *rx_buffer, 
                    struct sockaddr_in *serverAddr, const char *msg_description, int msg_num) {
    int max_retries = 5;
    int retry_count = 0;
    int valid_response = 0;
    int nBytes;
    printf("\n>>> Sending %s...\n", msg_description);
    
    // send message
    if(sendto(clientSocket, tx_buffer, packet_len, 0, (struct sockaddr *) serverAddr, 
                sizeof(*serverAddr)) < 0) {
        perror("sendto failed");
        return 0;
    }
    
    // try to receive message
    while(retry_count < max_retries && !valid_response) {
        nBytes = recvfrom(clientSocket, rx_buffer, BUFSIZE, 0, NULL, NULL);
        if(nBytes < 0) {
            perror("recvfrom failed");
            break;
        }
	// verify checksum
        if(verify_checksum(rx_buffer, nBytes)) {
            valid_response = 1;
            parse_rhp_response(rx_buffer, nBytes, msg_num);
        } else {
            printf("\n*** Checksum FAILED on attempt %d for %s, retrying... ***\n", 
                   retry_count + 1, msg_description);
            retry_count++;
            if(retry_count < max_retries) {
                if(sendto(clientSocket, tx_buffer, packet_len, 0, 
                    (struct sockaddr *) serverAddr, sizeof(*serverAddr)) < 0) {
                        perror("sendto failed on retry");
                        break;
                    }
            }
        }
    }
    if(!valid_response) {
        printf("\n*** Failed to receive valid response after %d attempts ***\n", max_retries);
        return 0;
    }

    return 1;
}


int main() {
    int clientSocket;
    uint8_t tx_buffer[BUFSIZE];
    uint8_t rx_buffer[BUFSIZE];
    struct sockaddr_in clientAddr, serverAddr;

    /*Create UDP socket*/
    if ((clientSocket = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("cannot create socket");
        return 1;
    }

    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    if(setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("Error setting socket timeout");
        close(clientSocket);
        return 1;
    }

    /* Bind to an arbitrary return address.
     * Because this is the client side, we don't care about the address 
     * since no application will initiate communication here - it will 
     * just send responses 
     * INADDR_ANY is the IP address and 0 is the port (allow OS to select port) 
     * htonl converts a long integer (e.g. address) to a network representation 
     * htons converts a short integer (e.g. port) to a network representation */
    memset((char *) &clientAddr, 0, sizeof (clientAddr));
    clientAddr.sin_family = AF_INET;
    clientAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    clientAddr.sin_port = htons(0);

    if (bind(clientSocket, (struct sockaddr *) &clientAddr, sizeof (clientAddr)) < 0) {
        perror("bind failed");
        close(clientSocket);
        return 1;
    }

    /* Configure settings in server address struct */
    memset((char*) &serverAddr, 0, sizeof (serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(PORT);
    serverAddr.sin_addr.s_addr = inet_addr(SERVER);
    
    // 1. one RHP control message with string "hi" (odd len)
    int packet_len = create_rhp_control_packet(tx_buffer, "hi", SRC_PORT);
    send_and_receive(clientSocket, tx_buffer, packet_len, rx_buffer, &serverAddr, 
                    "RHP control message 'hi' (odd length)", 1);
    
    // 2. one RHP control message with the string "hello" (even len)
    packet_len = create_rhp_control_packet(tx_buffer, "hello", SRC_PORT);
    send_and_receive(clientSocket, tx_buffer, packet_len, rx_buffer, &serverAddr,
                     "RHP control message 'hello' (even length)", 2);
    
    // 3. one RHMP message of type Message_Request
    packet_len = create_rhmp_packet(tx_buffer, RHMP_MESSAGE_REQUEST, NULL, 0, SRC_PORT);
    send_and_receive(clientSocket, tx_buffer, packet_len, rx_buffer, &serverAddr,
                     "RHMP Message_Request", 3);
    
    // 4. one RHMP message of type ID_Request
    packet_len = create_rhmp_packet(tx_buffer, RHMP_ID_REQUEST, NULL, 0, SRC_PORT);
    send_and_receive(clientSocket, tx_buffer, packet_len, rx_buffer, &serverAddr,
                     "RHMP ID_Request", 4);
    
    printf("All messages sent and responses received!\n");

    close(clientSocket);
    return 0;
}
