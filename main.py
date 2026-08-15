import sys
import os
import csv
from datetime import datetime
from sip_parser import parse_sip_pcap
from enrich import enrich_ip
from risk_score import calculate_risk

CSV_FILE = "calls_log.csv"
DUPLICATE_WINDOW_SECONDS = 10
DUPLICATE_DURATION_TOLERANCE = 0.5

def get_call_count_last_hour(ip, csv_file):
    count = 0
    if not os.path.exists(csv_file):
        return count
        
    now = datetime.now()
    with open(csv_file, 'r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get('source_ip') == ip or row.get('destination_ip') == ip:
                try:
                    # timestamp format: 2026-07-03 12:34:56
                    row_time = datetime.strptime(row['timestamp'], "%Y-%m-%d %H:%M:%S")
                    if (now - row_time).total_seconds() <= 3600:
                        count += 1
                except Exception:
                    pass
    return count

def is_recent_duplicate_call(
    row_data,
    csv_file,
    window_seconds=DUPLICATE_WINDOW_SECONDS,
    duration_tolerance=DUPLICATE_DURATION_TOLERANCE
):
    if not os.path.exists(csv_file):
        return False

    try:
        new_duration = float(row_data.get("duration_sec", 0))
    except (TypeError, ValueError):
        new_duration = None

    new_source = row_data.get("source_ip")
    new_destination = row_data.get("destination_ip")
    new_timestamp_raw = row_data.get("timestamp")

    try:
        new_timestamp = datetime.strptime(new_timestamp_raw, "%Y-%m-%d %H:%M:%S")
    except Exception:
        new_timestamp = datetime.now()

    with open(csv_file, 'r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for existing_row in reader:
            if existing_row.get("source_ip") != new_source:
                continue
            if existing_row.get("destination_ip") != new_destination:
                continue

            try:
                existing_duration = float(existing_row.get("duration_sec", 0))
            except (TypeError, ValueError):
                continue

            if new_duration is None or abs(existing_duration - new_duration) > duration_tolerance:
                continue

            try:
                existing_timestamp = datetime.strptime(existing_row["timestamp"], "%Y-%m-%d %H:%M:%S")
            except Exception:
                continue

            if abs((new_timestamp - existing_timestamp).total_seconds()) <= window_seconds:
                return True

    return False

def process_call(pcap_file):
    print(f"\n[MAIN] Processing new call capture: {pcap_file}")
    
    # 1. Parse SIP
    sip_data = parse_sip_pcap(pcap_file)

    if not sip_data.get('detection_valid', True):
        print(f"[MAIN] Skipping weak detection: {sip_data.get('detection_reason', 'Unconfirmed traffic')}")
        try:
            if os.path.exists(pcap_file):
                # os.remove(pcap_file)
                print(f"[MAIN] Deleted weak capture: {pcap_file}")
        except Exception as e:
            print(f"[MAIN] Failed to delete weak capture {pcap_file}: {e}")
        return False
    
    if sip_data.get('sip_confirmed'):
        print(f"[MAIN] Parsed SIP: Caller={sip_data['caller_ip']}, Callee={sip_data['callee_ip']}, Duration={sip_data['duration_sec']}s")
    else:
        print(
            "[MAIN] Detected Stream (Non-SIP): "
            f"Source={sip_data['source_ip']}, Destination={sip_data['destination_ip']}, "
            f"Duration={sip_data['duration_sec']}s, TimingMatches={sip_data.get('timing_match_count', 0)}"
        )
    
    # 2. Enrich IP
    # We want to enrich the public IP (not our local 192.168.x.x)
    target_ip = sip_data['source_ip']
    def is_private(ip):
        return ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.") or ip == "Unknown"
        
    if is_private(target_ip) and not is_private(sip_data['destination_ip']):
        target_ip = sip_data['destination_ip']
        
    enrich_data = enrich_ip(target_ip)
    print(f"[MAIN] Enriched IP {target_ip}: ISP={enrich_data['isp_org']}, Country={enrich_data['country']}")
    
    # 3. Frequency Check (Still useful for GUI info)
    freq = get_call_count_last_hour(target_ip, CSV_FILE)

    # 4. Calculate Risk Score
    risk_data = calculate_risk(sip_data['duration_sec'], enrich_data['country'], enrich_data['isp_org'])
    
    # 5. Save to CSV or send to GUI
    file_exists = os.path.isfile(CSV_FILE)
    
    row_data = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "call_id": sip_data['call_id'],
        "source_ip": sip_data['source_ip'],
        "destination_ip": sip_data['destination_ip'],
        "isp_org": enrich_data['isp_org'],
        "country": enrich_data['country'],
        "protocol": "SIP" if sip_data.get('sip_confirmed') else "Timing-Pattern (Non-SIP)",
        "duration_sec": sip_data['duration_sec'],
        "packet_count": sip_data['packet_count'],
        "risk_score": risk_data['risk_score'],
        "risk_level": risk_data['risk_level'],
        "risk_reason": risk_data['risk_reason']
    }

    if os.environ.get("GUI_MODE") == "1":
        import json
        payload = {"row": row_data, "pcap_file": pcap_file, "freq": freq}
        print(f"__GUI_REVIEW_DATA__:{json.dumps(payload)}")
        print(f"[MAIN] Sent analysis to GUI for review")
    else:
        if is_recent_duplicate_call(row_data, CSV_FILE):
            print(
                "[MAIN] Skipping duplicate save: "
                f"{row_data['source_ip']} -> {row_data['destination_ip']} ({row_data['duration_sec']}s)"
            )
            return False

        with open(CSV_FILE, 'a', newline='', encoding='utf-8') as f:
            headers = [
                "timestamp", "call_id", "source_ip", "destination_ip", 
                "isp_org", "country", "protocol", "duration_sec", 
                "packet_count", "risk_score", "risk_level", "risk_reason"
            ]
            writer = csv.DictWriter(f, fieldnames=headers)
            
            if not file_exists:
                writer.writeheader()
                
            writer.writerow(row_data)
        print(f"[MAIN] Saved analysis to {CSV_FILE}")

    return True

if __name__ == "__main__":
    if len(sys.argv) > 1:
        process_call(sys.argv[1])
    else:
        print("Usage: python main.py <pcap_file>")
