from scapy.all import sniff, IP, TCP, UDP

def process_packet(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        
        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"
        else:
            protocol = str(proto)

        print(f"Source IP: {ip_src} --> Destination IP: {ip_dst} | Protocol: {protocol}")

        if packet.haslayer(TCP) and packet[TCP].payload:
            payload = bytes(packet[TCP].payload)
            print(f"Payload: {payload[:50]}...\n")
        elif packet.haslayer(UDP) and packet[UDP].payload:
            payload = bytes(packet[UDP].payload)
            print(f"Payload: {payload[:50]}...\n")

print("Starting packet capture... Press Ctrl+C to stop.")
sniff(prn=process_packet, store=False)