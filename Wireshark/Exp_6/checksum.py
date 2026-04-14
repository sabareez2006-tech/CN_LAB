import struct
import socket
from scapy.all import *

# --- Core Manual Checksum Function ---
def calculate_manual_checksum(data):
    """
    Performs 16-bit One's Complement Sum (Manual Calculation).
    """
    # Padding: If data length is odd, add a zero byte
    if len(data) % 2 == 1:
        data += b'\x00'

    s = 0
    # Summing 16-bit words
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i+1]
        s += word

    # Handling Overflow (Wrap around)
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    
    # One's Complement (Bitwise NOT)
    s = ~s & 0xffff
    return s

def validate_packets(pcap_file):
    print(f"[*] Loading capture file: {pcap_file}...")
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(f"[!] Error: File '{pcap_file}' not found.")
        return

    print(f"[*] Analyzing {len(packets)} packets...\n")
    print(f"{'No.':<4} | {'Ver':<4} | {'Proto':<8} | {'Original':<8} | {'Manual Calc':<11} | {'Result'}")
    print("-" * 75)

    for i, pkt in enumerate(packets):
        packet_num = i + 1
        
        try:
            # ==========================================================
            #  IPv4 TRAFFIC (IP, TCP, UDP, ICMP)
            # ==========================================================
            if IP in pkt:
                ip = pkt[IP]
                
                # --- 1. IP Header Checksum ---
                raw_ip = raw(ip)[:ip.ihl * 4]
                # Zero out IP checksum (bytes 10-11)
                raw_ip_zeroed = raw_ip[:10] + b'\x00\x00' + raw_ip[12:]
                calc_ip = calculate_manual_checksum(raw_ip_zeroed)
                
                # Check for offloaded 0x0000 checksums
                status = "OFFLOADED" if ip.chksum == 0 else ("MATCH" if calc_ip == ip.chksum else "MISMATCH")
                print(f"{packet_num:<4} | {'v4':<4} | {'IP Header':<8} | {hex(ip.chksum):<8} | {hex(calc_ip):<11} | {status}")

                # Prepare for Layer 4 (Pseudo-Header helper)
                src_ip = inet_aton(ip.src)
                dst_ip = inet_aton(ip.dst)

                # --- 2. TCP & TLS ---
                if TCP in pkt:
                    tcp = pkt[TCP]
                    label = "TLS" if (tcp.sport == 443 or tcp.dport == 443) else "TCP"
                    
                    # Fix for Offloading: Get real length from raw bytes
                    tcp_len = len(raw(tcp))
                    if tcp_len > 65535: continue # Skip jumbo frames

                    # Pseudo-Header: Src(4), Dst(4), Zero(1), Proto(1), Len(2)
                    pseudo = struct.pack("!4s4sBBH", src_ip, dst_ip, 0, 6, tcp_len)
                    
                    # Zero out TCP Checksum (bytes 16-17)
                    raw_tcp_zeroed = raw(tcp)[:16] + b'\x00\x00' + raw(tcp)[18:]
                    
                    calc_tcp = calculate_manual_checksum(pseudo + raw_tcp_zeroed)
                    status = "MATCH" if calc_tcp == tcp.chksum else "MISMATCH"
                    print(f"{packet_num:<4} | {'v4':<4} | {label:<8} | {hex(tcp.chksum):<8} | {hex(calc_tcp):<11} | {status}")

                # --- 3. UDP ---
                elif UDP in pkt:
                    udp = pkt[UDP]
                    udp_len = len(raw(udp))
                    
                    # Pseudo-Header: Src(4), Dst(4), Zero(1), Proto(17), Len(2)
                    pseudo = struct.pack("!4s4sBBH", src_ip, dst_ip, 0, 17, udp_len)
                    
                    # Zero out UDP Checksum (bytes 6-7)
                    raw_udp_zeroed = raw(udp)[:6] + b'\x00\x00' + raw(udp)[8:]
                    
                    calc_udp = calculate_manual_checksum(pseudo + raw_udp_zeroed)
                    
                    if udp.chksum == 0:
                        status = "OFFLOADED"
                    else:
                        status = "MATCH" if calc_udp == udp.chksum else "MISMATCH"
                    print(f"{packet_num:<4} | {'v4':<4} | {'UDP':<8} | {hex(udp.chksum):<8} | {hex(calc_udp):<11} | {status}")

                # --- 4. ICMP ---
                elif ICMP in pkt:
                    icmp = pkt[ICMP]
                    # ICMPv4 uses NO pseudo-header
                    raw_icmp_zeroed = raw(icmp)[:2] + b'\x00\x00' + raw(icmp)[4:]
                    calc_icmp = calculate_manual_checksum(raw_icmp_zeroed)
                    status = "MATCH" if calc_icmp == icmp.chksum else "MISMATCH"
                    print(f"{packet_num:<4} | {'v4':<4} | {'ICMP':<8} | {hex(icmp.chksum):<8} | {hex(calc_icmp):<11} | {status}")

            # ==========================================================
            #  IPv6 TRAFFIC (Only ICMPv6)
            # ==========================================================
            elif IPv6 in pkt:
                
                if pkt[IPv6].nh == 58: # 58 is ICMPv6
                    ip6 = pkt[IPv6]
                    icmpv6 = ip6.payload
                    
                    if hasattr(icmpv6, "cksum"):
                        # Build IPv6 Pseudo-Header
                        src_ip6 = inet_pton(socket.AF_INET6, ip6.src)
                        dst_ip6 = inet_pton(socket.AF_INET6, ip6.dst)
                        icmpv6_len = len(raw(icmpv6))
                        
                        # Pseudo-Header: Src(16), Dst(16), Len(4), Zero(3), NextHdr(1)
                        pseudo = struct.pack("!16s16sI3xB", src_ip6, dst_ip6, icmpv6_len, 58)
                        
                        # Zero out checksum (bytes 2-3 of ICMPv6 header)
                        raw_icmp = raw(icmpv6)
                        raw_icmp_zeroed = raw_icmp[:2] + b'\x00\x00' + raw_icmp[4:]
                        
                        calc_icmp = calculate_manual_checksum(pseudo + raw_icmp_zeroed)
                        status = "MATCH" if calc_icmp == icmpv6.cksum else "MISMATCH"
                        print(f"{packet_num:<4} | {'v6':<4} | {'ICMPv6':<8} | {hex(icmpv6.cksum):<8} | {hex(calc_icmp):<11} | {status}")

        except Exception as e:
            pass

if __name__ == "__main__":
    validate_packets("sample1.pcap")
