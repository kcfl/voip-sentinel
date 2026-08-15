import scapy.all as scapy
from datetime import datetime
import time

detected_packets = []
last_voip_time = None
recording = False
recording_flow = None
prev_time = {}

def process_packet(pkt):
    global recording, recording_flow, last_voip_time, detected_packets

    if scapy.UDP in pkt and scapy.IP in pkt:
        src, dst = pkt[scapy.IP].src, pkt[scapy.IP].dst
        sport, dport = pkt[scapy.UDP].sport, pkt[scapy.UDP].dport
        
        # Ignore DNS, QUIC, SSDP, mDNS
        if sport in (53, 443, 1900, 5353) or dport in (53, 443, 1900, 5353):
            return

        key = (src, dst)
        now = time.time()

        if recording and key == recording_flow:
            detected_packets.append(pkt)

        if key in prev_time:
            gap = now - prev_time[key]
            if 0.015 <= gap <= 0.035:
                if not recording:
                    print(f"[VOIP DETECTED] {src} -> {dst} | Recording started...")
                    recording = True
                    recording_flow = key
                    detected_packets.clear()
                    detected_packets.append(pkt)
                last_voip_time = now

        prev_time[key] = now

    # If recording and 15 seconds of silence pass, save and stop
    if recording and last_voip_time and (time.time() - last_voip_time > 15):
        filename = f"call_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        scapy.wrpcap(filename, detected_packets)
        print(f"[CALL ENDED] Saved {len(detected_packets)} packets to {filename}")
        recording = False
        recording_flow = None
        import os
        os.system(f"python main.py {filename}")

target_iface = "Wi-Fi 3"
try:
    iface_ip = scapy.get_if_addr(target_iface)
except Exception as e:
    iface_ip = f"Unknown (Error: {e})"

print(f"[STARTUP] Interface: '{target_iface}' | IP: {iface_ip}")
print("[LISTENING] Watching for VoIP traffic... (Ctrl+C to stop)")
scapy.sniff(prn=process_packet, store=False, iface=target_iface)
