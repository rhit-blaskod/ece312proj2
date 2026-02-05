/************* UDP CLIENT CODE *******************/

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

#define SERVER "137.112.38.47"
#define PORT 2526
#define BUFSIZE 1024
#define RHP_VER 12
#define RHP_CONTROL_TYPE 0
#define RHP_DST_PORT 0x1874
#define SRC_PORT 1183

#pragma pack(push, 1)
typedef struct {
    uint8_t version;
    uint16_t srcPort;
    uint16_t dstPort;
    uint16_t len_and_type;
    uint8_t buff;
} RHPHeader;
#pragma pack(pop)

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

int create_rhp_packet(uint8_t *packet, const char *payload, uint16_t srcPort) {
    int payload_len = strlen(payload);
    int needs_padding = (payload_len % 2 == 1) ? 1 : 0;
    int packet_len = 7 + needs_padding + payload_len + 2;
    int offset = 0;

    memset(packet, 0, packet_len);
    packet[offset++] = RHP_VER;
    packet[offset++] = srcPort & 0xFF;
    packet[offset++] = (srcPort >> 8) & 0xFF;
    packet[offset++] = RHP_DST_PORT & 0xFF;
    packet[offset++] = (RHP_DST_PORT >> 8) & 0xFF;
    uint16_t length_type = (payload_len & 0x0FFF) | ((RHP_CONTROL_TYPE & 0x0F) << 12);
    packet[offset++] = length_type & 0xFF;
    packet[offset++] = (length_type >> 8) & 0xFF;

    if(needs_padding) {
        packet[offset++] = 0x00;
    }

    memcpy(&packet[offset], payload, payload_len);
    offset += payload_len; 

    uint16_t checksum = calc_checksum(packet, offset);
    packet[offset++] = checksum & 0xFF;
    packet[offset++] = (checksum >> 8) & 0xFF;

    return packet_len;
}

int verify_checksum(uint8_t *packet, int len) {
    uint16_t result = calc_checksum(packet, len);
    return (result == 0);
}

void parse_rhp_response(uint8_t *packet, int len) {
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

    char payload[BUFSIZE] = {0};
    if(payload_len > 0 && offset + payload_len <= - 2) {
        memcpy(payload, &packet[offset], payload_len);
        payload[payload_len] = '\0';
    }
    offset += payload_len;
    
    uint16_t checksum = packet[offset] | (packet[offset + 1] << 8);
    int checksum_valid = verify_checksum(packet, len);

    printf("\nMessage received:\n");
    printf(" RHP version: %u\n", version);
    printf(" RHP type: %u\n", type);
    printf(" Communication ID: %u (0x%X)\n", srcPort, srcPort);
    printf(" length: %u\n", payload_len);
    printf(" checksum: 0x%04X\n", checksum);
    if(checksum_valid) {
        printf(" checksum passed . . .\n");
    } else {
        printf(" checksum FAILED!\n");
    }
}


int main() {
    int clientSocket, nBytes;
    uint8_t tx_buffer[BUFSIZE];
    uint8_t rx_buffer[BUFSIZE];
    struct sockaddr_in clientAddr, serverAddr;
    const char *message = "hello";

    /*Create UDP socket*/
    if ((clientSocket = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("cannot create socket");
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

    int packet_len = create_rhp_packet(tx_buffer, message, SRC_PORT);
    printf("Sending RHP message: %s\n", message);

    /* send a packet to the server */
    if (sendto(clientSocket, tx_buffer, packet_len, 0,
            (struct sockaddr *) &serverAddr, sizeof (serverAddr)) < 0) {
        perror("sendto failed");
        close(clientSocket);
        return 1;
    }

    int max_retries = 3;
    int retry_count = 0;
    int valid_response = 0;

    while(retry_count < max_retries && !valid_response) {
        /* Receive message from server */
        nBytes = recvfrom(clientSocket, rx_buffer, BUFSIZE, 0, NULL, NULL);
        if(nBytes < 0) {
            perror("recvform failed");
            break;
        }

        if(verify_checksum(rx_buffer, nBytes)) {
            valid_response = 1; 
            parse_rhp_response(rx_buffer, nBytes);
        } else {
            printf("\nChecksum failed on attempt %d, retrying...\n", retry_count + 1);
            retry_count++;
            if(retry_count < max_retries) {
                if(sendto(clientSocket, tx_buffer, packet_len, 0, 
                    (struct sockaddr *) &serverAddr, sizeof(serverAddr)) < 0) {
                        perror("sendto failed on retry");
                        break;
                    }
            }
        }
    }

    if(!valid_response) {
        printf("\nFailed to receive valid response after %d attempts\n", max_retries);
    }

    close(clientSocket);
    return 0;
}