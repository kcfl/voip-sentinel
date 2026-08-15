import scapy.all as scapy
import re
from datetime import datetime

def analyze_sip_pcap(pcap_filename):
    print(f"\n[+] Loading capture file: {pcap_filename}...")
    
    try:
        # Load the capture file
        packets = scapy.rdpcap(pcap_filename)
    except FileNotFoundError:
        print(f"[-] Error: Could not find '{pcap_filename}'.")
        return

    # A dictionary to group all our call data by their unique Call-ID
    calls = {}

    print("[+] Extracting SIP Metadata...\n")
    print("=" * 70)

    # Loop through every single packet
    for pkt in packets:
        # We only care about packets that have an IP layer AND a Raw data payload
        if pkt.haslayer(scapy.IP) and pkt.haslayer(scapy.Raw):
            
            # Extract the raw text inside the packet, ignoring weird characters
            try:
                payload = pkt[scapy.Raw].load.decode('utf-8', errors='ignore')
            except:
                continue
            
            # Check if this payload actually contains SIP data
            if "SIP/2.0" in payload:
                
                # Use Regex (text searching) to find the Call-ID and User-Agent
                call_id_match = re.search(r'Call-ID:\s*(.+)', payload, re.IGNORECASE)
                user_agent_match = re.search(r'User-Agent:\s*(.+)', payload, re.IGNORECASE)
                
                if call_id_match:
                    call_id = call_id_match.group(1).strip()
                    
                    # If this is a new Call-ID we haven't seen before, create a blank record for it
                    if call_id not in calls:
                        calls[call_id] = {
                            "Caller IP": pkt[scapy.IP].src,
                            "Callee IP": pkt[scapy.IP].dst,
                            "User-Agent": user_agent_match.group(1).strip() if user_agent_match else "Unknown",
                            "INVITE_time": None,
                            "200_OK_time": None,
                            "BYE_time": None,
                            "rtp_ip": None,
                            "rtp_port": None
                        }
                    
                    # Get the exact readable timestamp of this packet
                    packet_time = datetime.fromtimestamp(float(pkt.time))
                    
                    # Log the timestamp based on what kind of SIP message this is
                    if payload.startswith("INVITE"):
                        if calls[call_id]["INVITE_time"] is None:
                            calls[call_id]["INVITE_time"] = packet_time
                            
                    elif payload.startswith("SIP/2.0 200 OK"):
                        # Only record the first 200 OK (which means the call was answered)
                        if calls[call_id]["200_OK_time"] is None:
                            calls[call_id]["200_OK_time"] = packet_time
                            
                    elif payload.startswith("BYE"):
                        if calls[call_id]["BYE_time"] is None:
                            calls[call_id]["BYE_time"] = packet_time

                    # Extract SDP Media parameters (IP and Port for the RTP voice stream)
                    c_match = re.search(r'c=IN IP4\s+([\d\.]+)', payload, re.IGNORECASE)
                    m_match = re.search(r'm=audio\s+(\d+)\s+RTP', payload, re.IGNORECASE)
                    
                    if c_match:
                        calls[call_id]["rtp_ip"] = c_match.group(1).strip()
                    if m_match:
                        calls[call_id]["rtp_port"] = int(m_match.group(1).strip())

    print("[+] Analyzing Media (RTP) Streams based on SDP negotiation...")
    
    # Second pass: Look for the actual voice packets (RTP) using the port we just extracted
    for call_id, data in calls.items():
        rtp_port = data["rtp_port"]
        if not rtp_port:
            data["rtp_count"] = 0
            continue
            
        rtp_timestamps = []
        for pkt in packets:
            if pkt.haslayer(scapy.UDP) and pkt.haslayer(scapy.IP):
                # If the UDP port matches the SDP audio port, it is our voice stream!
                if pkt[scapy.UDP].sport == rtp_port or pkt[scapy.UDP].dport == rtp_port:
                    rtp_timestamps.append(float(pkt.time))
                    
        data["rtp_count"] = len(rtp_timestamps)
        
        # Calculate the average time gap between voice packets to prove it's real-time media
        if len(rtp_timestamps) > 1:
            total_time = rtp_timestamps[-1] - rtp_timestamps[0]
            data["rtp_avg_gap"] = total_time / (len(rtp_timestamps) - 1)
        else:
            data["rtp_avg_gap"] = 0.0

    # --- Print the Final Clean Summary ---
    for call_id, data in calls.items():
        print(f"CALL-ID      : {call_id}")
        print(f"CALLER IP    : {data['Caller IP']}")
        print(f"SERVER/DEST  : {data['Callee IP']}")
        print(f"USER-AGENT   : {data['User-Agent']}")
        
        # Format the timestamps to look nice (Hour:Minute:Second)
        invite_str = data['INVITE_time'].strftime('%H:%M:%S') if data['INVITE_time'] else "Not Captured"
        ok_str = data['200_OK_time'].strftime('%H:%M:%S') if data['200_OK_time'] else "Not Captured"
        bye_str = data['BYE_time'].strftime('%H:%M:%S') if data['BYE_time'] else "Not Captured"
        
        print(f"CALL INITIATED (INVITE)  : {invite_str}")
        print(f"CALL ANSWERED  (200 OK)  : {ok_str}")
        print(f"CALL ENDED     (BYE)     : {bye_str}")
        
        # Calculate the exact duration if we have both the Answered and Ended times
        if data['200_OK_time'] and data['BYE_time']:
            duration = (data['BYE_time'] - data['200_OK_time']).total_seconds()
            print(f"TOTAL DURATION           : {duration:.2f} seconds")
        else:
            print("TOTAL DURATION           : Could not calculate (Missing Start or End packet)")
            
        print("-" * 70)
        print(f"SDP NEGOTIATED IP        : {data['rtp_ip'] if data['rtp_ip'] else 'Not Found'}")
        print(f"SDP NEGOTIATED PORT      : {data['rtp_port'] if data['rtp_port'] else 'Not Found'}")
        print(f"TOTAL VOICE PACKETS (RTP): {data.get('rtp_count', 0)}")
        if data.get('rtp_count', 0) > 0:
            print(f"VOICE PACKET INTERVAL    : {data.get('rtp_avg_gap', 0):.4f} seconds")
            
        print("=" * 70)

# Run the analyzer!
# Make sure this matches the exact name of your capture file
analyze_sip_pcap("sip_test_call.pcapng")