from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

# Function to handle incoming packets
def packet_callback(packet):
    print("\nPacket Captured:")

    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        print(f"Source IP: {packet[IP].src}")
        print(f"Destination IP: {packet[IP].dst}")
        print(f"Protocol: {packet[IP].proto}")

    # Check for TCP, UDP, or ICMP
    if packet.haslayer(TCP):
        print(f"TCP | Src Port: {packet[TCP].sport} | Dst Port: {packet[TCP].dport}")
    elif packet.haslayer(UDP):
        print(f"UDP | Src Port: {packet[UDP].sport} | Dst Port: {packet[UDP].dport}")
    elif packet.haslayer(ICMP):
        print(f"ICMP | Type: {packet[ICMP].type} | Code: {packet[ICMP].code}")

    # If there's raw data, try to decode it
    if packet.haslayer(Raw):
        try:
            print(f"Payload: {packet[Raw].load.decode('utf-8', 'ignore')}")
        except Exception:
            print("Payload could not be decoded.")

# Start sniffing packets
if __name__ == "__main__":
    print("Sniffing started... Press Ctrl+C to stop.")
    try:
        sniff(prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\nSniffing stopped.")
