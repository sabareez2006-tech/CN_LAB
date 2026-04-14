from scapy.all import rdpcap, TCP, UDP, ARP, IP
import pandas as pd
from collections import defaultdict

# Load the PCAP file
pcap_file = r"24bce5508_week7_pcap.pcap" # Make sure to update this path if needed
packets = rdpcap(pcap_file)

# Part 1: Protocol Hierarchy
protocol_counts = defaultdict(int)
total_data_size = 0
total_header_size = 0

# Calculate protocol hierarchy and packet sizes
for packet in packets:
    total_data_size += len(packet.payload)
    total_header_size += len(packet) - len(packet.payload)

    if packet.haslayer(ARP):
        protocol_counts['ARP'] += 1
    if packet.haslayer(UDP):
        protocol_counts['UDP'] += 1
    if packet.haslayer(TCP):
        protocol_counts['TCP'] += 1

# Print protocol hierarchy results
print(f"Total number of packets: {len(packets)}")
print(f"Total data size (bytes): {total_data_size}")
print(f"Total header size (bytes): {total_header_size}")
print("Protocol Counts:", protocol_counts)

# Save Protocol Hierarchy to CSV
protocol_df = pd.DataFrame(list(protocol_counts.items()), columns=["Protocol", "Packet Count"])
protocol_df.to_csv("protocol_hierarchy.csv", index=False)

# Part 2: Conversations
conversations = defaultdict(lambda: {'packets': 0, 'bytes': 0, 'first_time': None, 'last_time': None})

# Track each pair of communicating hosts (IP pairs)
for packet in packets:
    if packet.haslayer(IP):
        src, dst = packet[IP].src, packet[IP].dst
        pair = (src, dst)
        conversations[pair]["packets"] += 1
        conversations[pair]["bytes"] += len(packet)

        if conversations[pair]["first_time"] is None:
            conversations[pair]["first_time"] = packet.time
        conversations[pair]["last_time"] = packet.time

# Calculate average inter-packet time and total packets per pair
pair_stats = []
for pair, stats in conversations.items():
    inter_packet_time = stats['last_time'] - stats['first_time'] if stats['first_time'] is not None else 0
    avg_inter_packet_time = inter_packet_time / (stats['packets'] - 1) if stats['packets'] > 1 else 0
    pair_stats.append({
        'Address Pair': f"{pair[0]} -> {pair[1]}",
        'Total Packets': stats['packets'],
        'Total Bytes': stats['bytes'],
        'Avg Inter-Packet Time (s)': avg_inter_packet_time
    })

# Convert to DataFrame and save as CSV
conversations_df = pd.DataFrame(pair_stats)
conversations_df.to_csv("conversations.csv", index=False)

# Print summary for the address pair with maximum bytes
if conversations:
    max_pair = max(conversations, key=lambda x: conversations[x]['bytes'])
    print(f"\nAddress pair with max data: {max_pair[0]} -> {max_pair[1]}")
    print(f"Total bytes: {conversations[max_pair]['bytes']}")
    print(f"Total packets: {conversations[max_pair]['packets']}")
