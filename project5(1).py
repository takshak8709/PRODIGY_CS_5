from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto

        if packet.haslayer(TCP):
            transport_layer = packet.getlayer(TCP)
            sport = transport_layer.sport
            dport = transport_layer.dport
            payload = packet.load if packet.haslayer(Raw) else b'No Payload'
        elif packet.haslayer(UDP):
            transport_layer = packet.getlayer(UDP)
            sport = transport_layer.sport
            dport = transport_layer.dport
            payload = packet.load if packet.haslayer(Raw) else b'No Payload'
        elif packet.haslayer(ICMP):
            transport_layer = packet.getlayer(ICMP)
            sport = 'N/A'
            dport = 'N/A'
            payload = packet.load if packet.haslayer(Raw) else b'No Payload'
        else:
            sport = 'N/A'
            dport = 'N/A'
            payload = packet.load if packet.haslayer(Raw) else b'No Payload'

        # Protocol name mapping
        protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        protocol_name = protocol_map.get(protocol, 'Unknown')

        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print(f"Protocol: {protocol_name}")
        print(f"Source Port: {sport}")
        print(f"Destination Port: {dport}")
        print(f"Payload Data: {payload[:50]}")  # Display only the first 50 bytes of payload
        print('-' * 40)

if __name__ == "__main__":  # Corrected main guard
    print("Starting packet capture. Press Ctrl+C to stop.")
    try:
        sniff(prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("Packet capture stopped.")
