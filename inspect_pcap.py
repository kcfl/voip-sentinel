import scapy.all as scapy
from collections import Counter

packets = scapy.rdpcap('sample_call.pcapng')
print(f"Total packets in pcap: {len(packets)}")

summary = Counter()
dns_packets = []
other_packets = []

for pkt in packets:
    if scapy.IP in pkt and scapy.UDP in pkt:
        src = pkt[scapy.IP].src
        dst = pkt[scapy.IP].dst
        sport = pkt[scapy.UDP].sport
        dport = pkt[scapy.UDP].dport
        summary[(src, dst, sport, dport)] += 1
        
        if dst == '8.8.4.4' or src == '8.8.4.4':
            if sport == 53 or dport == 53:
                dns_packets.append(pkt)
            else:
                other_packets.append(pkt)

print("\n--- Top UDP Traffic in PCAP ---")
for (src, dst, sport, dport), count in summary.most_common(10):
    print(f"{src}:{sport} -> {dst}:{dport} | {count} packets")

print(f"\nTotal DNS (port 53) packets involving 8.8.4.4: {len(dns_packets)}")
print(f"Total OTHER UDP packets involving 8.8.4.4: {len(other_packets)}")

if other_packets:
    print("\n--- Sample of NON-DNS traffic involving 8.8.4.4 ---")
    for i, p in enumerate(other_packets[:5]):
        print(f"Packet {i+1}: {p[scapy.IP].src}:{p[scapy.UDP].sport} -> {p[scapy.IP].dst}:{p[scapy.UDP].dport} | Length: {len(p)}")
        if scapy.Raw in p:
            try:
                payload = p[scapy.Raw].load.decode('utf-8', errors='ignore')
                print(f"Payload snippet: {payload[:100]!r}")
            except:
                print(f"Raw payload bytes: {p[scapy.Raw].load[:50]}")
