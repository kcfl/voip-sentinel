import requests

def enrich_ip(ip):
    # Default response for private IPs or failures
    result = {
        "isp_org": "Unknown",
        "country": "Unknown"
    }
    
    # Skip private IPs
    if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.") or ip == "Unknown":
        return result
        
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if response.status_code == 200:
            data = response.json()
            org = data.get("org", "Unknown")
            # Sometimes org includes the AS number like "AS12345 Name", let's keep it as is
            result["isp_org"] = org
            result["country"] = data.get("country", "Unknown")
    except Exception as e:
        print(f"Error enriching IP {ip}: {e}")
        
    return result

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        test_ip = sys.argv[1]
        res = enrich_ip(test_ip)
        print(f"Enrichment for {test_ip}:")
        print(f"  ISP/Org: {res['isp_org']}")
        print(f"  Country: {res['country']}")
    else:
        print("Usage: python enrich.py <ip_address>")
