from scapy.all import rdpcap, IP

pkts = rdpcap('24bce5508_wireshark.pcapng')
src_ips = set()
dst_ips = set()
protocols = {}

for pkt in pkts:
    if pkt.haslayer(IP):
        src_ips.add(pkt[IP].src)
        dst_ips.add(pkt[IP].dst)
        proto_name = pkt[IP].sprintf('%IP.proto%')
        protocols[proto_name] = protocols.get(proto_name, 0) + 1

print(f"--- PCAP Analysis Results ---")
print(f"Total Number of Packets: {len(pkts)}")
print(f"Number of Unique Source IPs: {len(src_ips)}")
print(f"Number of Unique Dest IPs: {len(dst_ips)}")
print(f"Number of Protocols Used: {len(protocols)}")
print("\n--- Packets per Protocol ---")
for proto, count in protocols.items():
    print(f"{proto}: {count}")
