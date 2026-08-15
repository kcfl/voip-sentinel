def calculate_risk(duration_sec, country, isp_org=""):
    vpn_or_hosting_providers = [
        "ovh", "digitalocean", "amazon", "aws", "hetzner", "linode", "choopa", "vultr",
        "proton", "nordvpn", "expressvpn", "surfshark", "mullvad", "private internet access"
    ]
    org_lower = isp_org.lower() if isp_org else ""
    is_vpn_or_hosting = any(provider in org_lower for provider in vpn_or_hosting_providers)

    if is_vpn_or_hosting:
        return {
            "risk_score": 90,
            "risk_level": "High",
            "risk_reason": "Suspicious routing / Potential VPN"
        }
    elif duration_sec < 5:
        return {
            "risk_score": 65,
            "risk_level": "Medium",
            "risk_reason": "Micro-duration ping / Burner anomaly"
        }
    else:
        return {
            "risk_score": 15,
            "risk_level": "Low",
            "risk_reason": "Standard civilian traffic profile"
        }

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 3:
        dur = float(sys.argv[1])
        cntry = sys.argv[2]
        isp = sys.argv[3]
        res = calculate_risk(dur, cntry, isp)
        print(f"Score: {res['risk_score']} | Level: {res['risk_level']} | Reason: {res['risk_reason']}")
    else:
        print("Usage: python risk_score.py <duration_sec> <country> <isp_org>")
