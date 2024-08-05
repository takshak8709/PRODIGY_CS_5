from scapy.all import sniff, IP, TCP, UDP, Raw, get_if_list

def list_interfaces():
    interfaces = get_if_list()
    print("Available interfaces:")
    for i, interface in enumerate(interfaces):
        print(f"{i}: {interface}")
    return interfaces

def packet_handler(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"[+] New Packet: {ip_layer.src} -> {ip_layer.dst}")

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print(f"TCP Packet: {tcp_layer.sport} -> {tcp_layer.dport}")
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            print(f"UDP Packet: {udp_layer.sport} -> {udp_layer.dport}")

        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"Payload: {payload}")

def start_sniffing(interface):
    print(f"Starting packet capture on {interface}...")
    sniff(iface=interface, prn=packet_handler, store=False)

if __name__ == "__main__":
    interfaces = list_interfaces()
    interface_index = int(input("Enter the interface index to sniff on: "))
    interface = interfaces[interface_index]
    start_sniffing(interface)
