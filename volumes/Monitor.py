import subprocess
import time
import argparse

# Argument parser setup
parser = argparse.ArgumentParser(description="Ping Monitor Script")
parser.add_argument("--interval", type=int, default=5, help="Interval between pings in seconds")
parser.add_argument("--type", type=str, default="p", help="Type of monitoring (for C or Python)")

args = parser.parse_args()

# Argument parsing
TARGET_IP = "10.9.0.4"  # Replace with your target server's IP address
INTERVAL = args.interval   # 5 seconds interval between pings
TYPE = args.type

# List to store the index and RTT
ping_results = []

# Function to send a ping and calculate RTT
def send_ping(target_ip):
    try:
        # Execute the ping command
        ping_output = subprocess.check_output(["ping", "-c", "1", target_ip], universal_newlines=True)
        
        # Extract the RTT from the ping output
        for line in ping_output.splitlines():
            if "time=" in line:
                rtt = float(line.split("time=")[1].split(" ")[0])
                return rtt
    except subprocess.CalledProcessError:
        return None

# Monitor function to send pings and store results
def monitor():
    i = 0
    try:
        while True:
            rtt = send_ping(TARGET_IP)
            if rtt is not None:
                ping_results.append((i, rtt))
                print(f"Ping {i}: RTT = {rtt} ms")
            else:
                print(f"Ping {i}: Request timed out")
            time.sleep(INTERVAL)
            i += 1
    except KeyboardInterrupt:
        print("Monitoring stopped by user.")
    
    # Save results to a file
    print("Saving results to file.")
    with open(f'./ping_results_{TYPE}.txt', 'w') as file:
        for index, rtt in ping_results:
            file.write(f"{index} {rtt}\n")

if __name__ == '__main__':
    monitor()
