import numpy as np
import matplotlib.pyplot as plt

# Load data from file
def load_data(file_path):
    data = np.loadtxt(file_path)
    return data

# Calculate statistics
def calculate_statistics(data):
    avg = np.mean(data)
    std = np.std(data)
    return avg, std

# Plot histogram with logarithmic y-axis
def plot_histogram(data, title, xlabel, ylabel, filename):
    plt.figure()
    plt.hist(data, bins=20, color='blue', edgecolor='black', log=True)
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.grid(True)
    plt.savefig(filename)
    plt.close()

# Load and process data
python_rtts = load_data('./ping_results_p.txt')[:, 1]
c_rtts = load_data('./ping_results_c.txt')[:, 1]
python_times = load_data('./syns_result_p.txt')[:, 1]
c_times = load_data('./syns_result_c.txt')[:, 1]

# Calculate statistics
python_ping_avg, python_ping_std = calculate_statistics(python_rtts)
c_ping_avg, c_ping_std = calculate_statistics(c_rtts)
python_syn_avg, python_syn_std = calculate_statistics(python_times)
c_syn_avg, c_syn_std = calculate_statistics(c_times)

# Plot graphs
plot_histogram(python_rtts, 'Python Attack RTT Distribution', 'Ping RTT (ms)', 'Number of Pings (log scale)', 'Pings_p.png')
plot_histogram(c_rtts, 'C Attack RTT Distribution', 'Ping RTT (ms)', 'Number of Pings (log scale)', 'Pings_c.png')
plot_histogram(python_times, 'Python Attack Packet Send Time Distribution', 'Time to Send Packet (ms)', 'Number of Packets (log scale)', 'Syn_pkts_p.png')
plot_histogram(c_times, 'C Attack Packet Send Time Distribution', 'Time to Send Packet (ms)', 'Number of Packets (log scale)', 'Syn_pkts_c.png')

# Print statistics for report
print("Python Attack Pings:")
print(f"  Average RTT: {python_ping_avg:.2f} ms")
print(f"  Standard Deviation of RTT: {python_ping_std:.2f} ms\n")

print("C Attack Pings:")
print(f"  Average RTT: {c_ping_avg:.2f} ms")
print(f"  Standard Deviation of RTT: {c_ping_std:.2f} ms\n")

print("Python Attack Syns:")
print(f"  Average Time to Send Packet: {python_syn_avg:.2f} ms")
print(f"  Standard Deviation of Time to Send Packet: {python_syn_std:.2f} ms\n")

print("C Attack Syns:")
print(f"  Average Time to Send Packet: {c_syn_avg:.2f} ms")
print(f"  Standard Deviation of Time to Send Packet: {c_syn_std:.2f} ms\n")
