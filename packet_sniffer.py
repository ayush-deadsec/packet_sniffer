from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        print(f"Source IP: {src_ip} --> Destination IP: {dst_ip} | Protocol: {protocol}")

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"TCP Source Port: {src_port} --> Destination Port: {dst_port}")

        if UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"UDP Source Port: {src_port} --> Destination Port: {dst_port}")

        print("-" * 50)

# Start sniffing packets
print("Starting packet sniffer...")
sniff(prn=packet_callback, count=10)  # Capture 10 packets


