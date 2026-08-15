import scapy.all as scapy

print("=== scapy.get_if_list() ===")
try:
    ifaces = scapy.get_if_list()
    for iface in ifaces:
        print(iface)
except Exception as e:
    print(f"Error getting interface list: {e}")

print("\n=== scapy.show_interfaces() ===")
try:
    scapy.show_interfaces()
except Exception as e:
    print(f"Error showing interfaces: {e}")
