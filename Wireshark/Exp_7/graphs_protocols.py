import matplotlib.pyplot as plt
from scapy.all import rdpcap, TCP, UDP, ARP, IP
import numpy as np

# Load your capture file
packets = rdpcap('24bce5508_week7_pcap.pcap')
start_time = float(packets[0].time)

def get_data(packet_list, filter_type=None, mode='packets'):
    """
    Groups packets into 1-second intervals for the X-axis.
    """
    times = []
    values = []
    seen_flows = set() # For TCP Retransmission detection

    for pkt in packet_list:
        # Filter Logic
        if filter_type == 'udp' and UDP not in pkt:
            continue
        if filter_type == 'arp' and ARP not in pkt:
            continue
        if filter_type == 'tcp_error':
            if TCP in pkt:
                # Logic: Check for RST flag (0x04) or Retransmissions (Same Seq)
                is_error = (pkt[TCP].flags & 0x04)
                flow_id = (pkt[IP].src, pkt[IP].dst, pkt[TCP].seq)
                if flow_id in seen_flows:
                    is_error = True
                seen_flows.add(flow_id)
                if not is_error:
                    continue
            else:
                continue

        times.append(float(pkt.time) - start_time)
        values.append(len(pkt) if mode == 'bytes' else 1)

    if not times:
        return [0], [0]

    # Create 1-second bins
    bins = np.arange(0, max(times) + 2, 1)
    if mode == 'packets':
        counts, edges = np.histogram(times, bins=bins)
        return edges[:-1], counts
    else:
        bin_indices = np.digitize(times, bins) - 1
        byte_totals = np.zeros(len(bins)-1)
        for i, idx in enumerate(bin_indices):
            if 0 <= idx < len(byte_totals):
                byte_totals[idx] += values[i]
        return bins[:-1], byte_totals

# Prepare the Figure
plt.style.use('ggplot') # Makes it look modern like Wireshark 4.0
fig, axes = plt.subplots(2, 3, figsize=(16, 10))
fig.suptitle('Wireshark Statistics - Scapy Replication', fontsize=16)

# Graph 1: All Packets - Count
t1, y1 = get_data(packets, None, 'packets')
axes[0, 0].plot(t1, y1, color='blue', linewidth=1.5)
axes[0, 0].set_title('All Packets (Packets/s)')
axes[0, 0].fill_between(t1, y1, color='blue', alpha=0.1)

# Graph 2: All Packets - Bytes
t2, y2 = get_data(packets, None, 'bytes')
axes[0, 1].plot(t2, y2, color='green', linewidth=1.5)
axes[0, 1].set_title('All Packets (Bytes/s)')
axes[0, 1].fill_between(t2, y2, color='green', alpha=0.1)

# Graph 3: TCP Errors - Packets
t3, y3 = get_data(packets, 'tcp_error', 'packets')
axes[0, 2].plot(t3, y3, color='red', linewidth=1.5)
axes[0, 2].set_title('TCP Errors (Packets/s)')
axes[0, 2].set_ylabel('RST / Retransmissions')

# Graph 4: UDP - Packets
t4, y4 = get_data(packets, 'udp', 'packets')
axes[1, 0].plot(t4, y4, color='orange', linewidth=1.5)
axes[1, 0].set_title('UDP Traffic (Packets/s)')

# Graph 5: ARP - Packets
t5, y5 = get_data(packets, 'arp', 'packets')
axes[1, 1].plot(t5, y5, color='purple', linewidth=1.5)
axes[1, 1].set_title('ARP Requests/Replies')

# Graph 6: Summary Table (Bonus for your Lab report)
axes[1, 2].axis('off')
stats_text = (
    f"Total Packets: {len(packets)}\n"
    f"Total Capture Time: {round(max(t1), 2)}s\n"
    f"Avg Throughput: {round(sum(y2)/max(t1), 2) if max(t1)>0 else 0} Bytes/s"
)
axes[1, 2].text(0.1, 0.5, stats_text, fontsize=12, fontweight='bold', bbox={'facecolor':'white', 'alpha':0.5, 'pad':10})

plt.tight_layout(rect=[0, 0.03, 1, 0.95])
plt.savefig('scapy_final_grid.png')
plt.show()
