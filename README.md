# VoIP Sentinel

🏆 *This project placed 1st at the Safe Click 2.0 Hackathon, organized by M.P. Police.*

**Real-time VoIP call detection and metadata intelligence for network investigation.**

VoIP Sentinel detects, analyzes, and logs VoIP calls in real time by capturing and
analyzing network traffic metadata — without decrypting call content. It identifies
calls made through common VoIP/messaging apps by recognizing the packet timing
signature of real-time voice streams, even when the underlying traffic is fully
encrypted.

## Overview

Modern VoIP applications encrypt call content end-to-end, making traditional deep
packet inspection ineffective. VoIP Sentinel takes a different approach: it analyzes
**metadata and timing patterns** rather than payload content — detecting calls,
identifying the service/infrastructure used, and flagging anomalous behavior, while
never accessing or attempting to decrypt the actual conversation.

## How It Works

1. **Capture** — Live packet sniffing on a monitored network interface (Scapy)
2. **Detect** — Identifies VoIP calls via SIP signaling analysis or, when SIP
   signaling isn't available, real-time timing-pattern analysis (consistent
   ~15–35ms packet intervals characteristic of live voice/RTP streams)
3. **Enrich** — Resolves destination IPs to ISP/organization and country
4. **Assess** — Applies rule-based risk scoring based on call duration, frequency,
   and infrastructure type, with a plain-language reason for every score
5. **Review** — Every detected call is presented to the operator for confirmation
   (Keep/Discard) before being logged — nothing is recorded automatically
6. **Report** — Generates a browsable investigation dashboard summarizing all
   logged calls, risk levels, and metadata

## Design Principles

- **Metadata only, never content** — the tool analyzes packet timing, size, and
  header information; it does not decrypt or access call audio
- **Human-in-the-loop** — every logged record requires explicit operator
  confirmation, supporting accountable and auditable use
- **Explainable scoring** — risk assessments are rule-based and always paired
  with a stated reason, not a black-box output

## Tech Stack

| Component | Technology |
|---|---|
| Packet capture | Python, Scapy |
| Protocol parsing | Custom SIP/timing-pattern parser |
| IP enrichment | ipinfo.io API |
| Interface | Tkinter (desktop GUI) |
| Reporting | Auto-generated HTML dashboard |

## Getting Started

### Prerequisites

- Python 3.10+
- [Npcap](https://npcap.com/) (Windows) or equivalent packet capture driver for
  your OS
- Administrator/root privileges (required for live packet capture)

### Installation

```bash
git clone https://github.com/kcfl/voip-sentinel.git
cd voip-sentinel
pip install -r requirements.txt
```

### Configuration

Open `sniffer.py` and set your network interface name near the top of the file
before running — this must match an active adapter on your machine (used for live
packet capture).

If using the optional identity-lookup feature, add your own API token directly
where indicated in the relevant script. Never commit real credentials to version
control.

### Running

```bash
python voip_gui.py
```

Click **Start** to begin monitoring. Detected calls will appear for review before
being added to the log. Use **Open Dashboard** to view the generated report.

## Limitations

This tool is intentionally scoped and does not attempt to overstate its
capabilities:

- Does not decrypt call content — analysis is limited to metadata and timing
- Cannot unmask VPN-routed traffic beyond flagging suspicious infrastructure
  patterns
- Cannot reliably distinguish real-time voice calls from other continuous
  real-time UDP audio streams (e.g., music/media streaming) on timing alone
- Cannot resolve anonymous or frequently-changed account identities without a
  formal request to the relevant service provider
- Identifying the other party on a call requires platform cooperation through
  proper legal process — this tool builds the evidentiary trail that supports
  such a request, it does not substitute for it

## Project Structure

```
voip-sentinel/
├── sniffer.py              # Live packet capture and call detection
├── sip_parser.py           # SIP/timing-based call analysis
├── enrich.py                # IP-to-ISP/geolocation enrichment
├── risk_score.py           # Rule-based risk scoring
├── main.py                  # Pipeline orchestration
├── voip_gui.py              # Desktop interface
├── generate_dashboard.py    # HTML report generation
├── voip_analyzer.py         # Standalone SIP/RTP capture analyzer
├── check_interfaces.py      # Network interface diagnostic utility
├── check_timing.py          # Packet timing diagnostic utility
├── inspect_pcap.py          # Raw packet capture inspection utility
└── requirements.txt
```

## Disclaimer

This project is intended for authorized network analysis and lawful investigative
use only. It operates strictly on network metadata and does not decrypt, intercept,
or store call content. Users are responsible for ensuring their use complies with
applicable laws and organizational policy.
