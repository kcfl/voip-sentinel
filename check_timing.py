import scapy.all as scapy
from collections import defaultdict

packets = scapy.rdpcap('sample_call.pcapng')
local_ip = '192.168.1.17'

print(f"Finding the real VoIP stream in the PCAP...\n")

streams = defaultdict(list)
voip_matches = defaultdict(int)
prev_time = {}

for pkt in packets:
    if scapy.IP in pkt and scapy.UDP in pkt:
        src = pkt[scapy.IP].src
        dst = pkt[scapy.IP].dst
        
        # Group by communication pair
        pair = tuple(sorted([src, dst]))
        
        now = float(pkt.time)
        streams[pair].append(now)
        
        if pair in prev_time:
            gap = now - prev_time[pair]
            if 0.015 <= gap <= 0.035:
                voip_matches[pair] += 1
        
        prev_time[pair] = now

print("--- Top Streams by VoIP Pattern Matches (0.015s - 0.035s gap) ---")
for pair, matches in sorted(voip_matches.items(), key=lambda x: x[1], reverse=True)[:5]:
    total_pkts = len(streams[pair])
    print(f"{pair[0]} <-> {pair[1]} | {matches} matches out of {total_pkts} total packets")

