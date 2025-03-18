from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def packet_callback(packet):
    print("\nPacket Captured:")
    if packet.haslayer(IP):
        print(f"Source IP: {packet[IP].src}")
        print(f"Destination IP: {packet[IP].dst}")
        print(f"Protocol: {packet[IP].proto}")
    
    if packet.haslayer(TCP):
        print(f"TCP | Source Port: {packet[TCP].sport} | Destination Port: {packet[TCP].dport}")
    elif packet.haslayer(UDP):
        print(f"UDP | Source Port: {packet[UDP].sport} | Destination Port: {packet[UDP].dport}")
    elif packet.haslayer(ICMP):
        print("Protocol: ICMP")
    
    if packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode('utf-8', 'ignore')
            print(f"Payload: {payload}")
        except (AttributeError, UnicodeDecodeError):
            print("Unable to decode payload.")

if __name__ == "__main__":
    print("Starting packet sniffer...")
    sniff(prn=packet_callback, store=False)
