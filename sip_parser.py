import ipaddress
import re
from collections import defaultdict

import scapy.all as scapy

TIMING_GAP_MIN = 0.015
TIMING_GAP_MAX = 0.035
MIN_TIMING_MATCHES = 6
MIN_TIMING_PACKETS = 15
MIN_STREAM_DURATION = 1.0
IGNORED_UDP_PORTS = {53, 1900, 5353}


def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return ip in ("Unknown", "")


def parse_sip_pcap(pcap_file):
    packets = scapy.rdpcap(pcap_file)

    call_id = "Unknown"
    caller_ip = "Unknown"
    callee_ip = "Unknown"
    user_agent = "Unknown"

    first_time = None
    last_time = None

    voip_matches = defaultdict(int)
    pair_counts = defaultdict(int)
    prev_time = {}

    for pkt in packets:
        if first_time is None:
            first_time = float(pkt.time)
        last_time = float(pkt.time)

        if scapy.IP in pkt and scapy.UDP in pkt:
            sport, dport = pkt[scapy.UDP].sport, pkt[scapy.UDP].dport
            if sport in IGNORED_UDP_PORTS or dport in IGNORED_UDP_PORTS:
                continue

            src = pkt[scapy.IP].src
            dst = pkt[scapy.IP].dst
            pair = tuple(sorted((src, dst)))
            pair_counts[pair] += 1

            now = float(pkt.time)
            if pair in prev_time:
                gap = now - prev_time[pair]
                if TIMING_GAP_MIN <= gap <= TIMING_GAP_MAX:
                    voip_matches[pair] += 1
            prev_time[pair] = now

        if scapy.UDP in pkt and scapy.Raw in pkt:
            payload = pkt[scapy.Raw].load.decode('utf-8', errors='ignore')
            if payload.startswith("INVITE sip:") or payload.startswith("SIP/2.0 "):
                if scapy.IP in pkt:
                    if "Call-ID:" in payload or "Call-Id:" in payload or "i:" in payload:
                        match = re.search(r'(?i)Call-ID:\s*(.+?)\r?\n', payload)
                        if match and call_id == "Unknown":
                            call_id = match.group(1).strip()

                    if "User-Agent:" in payload:
                        match = re.search(r'User-Agent:\s*(.+?)\r?\n', payload)
                        if match and user_agent == "Unknown":
                            user_agent = match.group(1).strip()

                    if payload.startswith("INVITE sip:") and caller_ip == "Unknown":
                        caller_ip = pkt[scapy.IP].src
                        callee_ip = pkt[scapy.IP].dst

    duration = 0.0
    if first_time is not None and last_time is not None:
        duration = last_time - first_time

    source_ip = "Unknown"
    destination_ip = "Unknown"
    sip_confirmed = False
    detection_valid = False
    detection_reason = "No SIP or strong timing evidence found"
    timing_match_count = 0
    best_pair_packet_count = 0

    if caller_ip != "Unknown" or callee_ip != "Unknown":
        sip_confirmed = True
        detection_valid = True
        detection_reason = "SIP signaling confirmed"
        source_ip = caller_ip
        destination_ip = callee_ip
    elif voip_matches:
        ranked_pairs = sorted(
            voip_matches.items(),
            key=lambda item: (item[1], pair_counts[item[0]]),
            reverse=True
        )
        public_pairs = [
            item for item in ranked_pairs
            if not (is_private_ip(item[0][0]) and is_private_ip(item[0][1]))
        ]
        best_pair, timing_match_count = public_pairs[0] if public_pairs else ranked_pairs[0]
        best_pair_packet_count = pair_counts[best_pair]

        if (
            timing_match_count >= MIN_TIMING_MATCHES
            and best_pair_packet_count >= MIN_TIMING_PACKETS
            and duration >= MIN_STREAM_DURATION
        ):
            detection_valid = True
            detection_reason = "Confirmed by repeated RTP-like timing pattern"
            source_ip = best_pair[0]
            destination_ip = best_pair[1]
        else:
            detection_reason = (
                "Weak non-SIP timing evidence "
                f"({timing_match_count} matches, {best_pair_packet_count} packets, {round(duration, 2)}s)"
            )

    return {
        "call_id": call_id,
        "sip_confirmed": sip_confirmed,
        "detection_valid": detection_valid,
        "detection_reason": detection_reason,
        "timing_match_count": timing_match_count,
        "best_pair_packet_count": best_pair_packet_count,
        "caller_ip": caller_ip if sip_confirmed else None,
        "callee_ip": callee_ip if sip_confirmed else None,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "user_agent": user_agent,
        "duration_sec": round(duration, 2),
        "packet_count": len(packets)
    }

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        result = parse_sip_pcap(sys.argv[1])
        print("Parsed SIP Result:")
        for k, v in result.items():
            print(f"  {k}: {v}")
    else:
        print("Usage: python sip_parser.py <pcap_file>")
