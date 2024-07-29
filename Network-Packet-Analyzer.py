from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP

# Function to analyze packets
def analyze_packet(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto

        # Determine the protocol
        if proto == 6:
            protocol = "TCP"
        elif proto == 17:
            protocol = "UDP"
        elif proto == 1:
            protocol = "ICMP"
        else:
            protocol = "Other"

        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print(f"Protocol: {protocol}")

        # Check if the packet has a TCP/UDP/ICMP layer and display payload data
        if TCP in packet and protocol == "TCP":
            tcp_layer = packet[TCP]
            print(f"Source Port: {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")
            print(f"Payload: {bytes(tcp_layer.payload)}")
        elif UDP in packet and protocol == "UDP":
            udp_layer = packet[UDP]
            print(f"Source Port: {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")
            print(f"Payload: {bytes(udp_layer.payload)}")
        elif ICMP in packet and protocol == "ICMP":
            icmp_layer = packet[ICMP]
            print(f"Type: {icmp_layer.type}")
            print(f"Code: {icmp_layer.code}")
            print(f"Payload: {bytes(icmp_layer.payload)}")

        print("-" * 80)

# Function to start sniffing
def start_sniffing(interface):
    print(f"Starting packet sniffing on {interface}...")
    sniff(iface=interface, prn=analyze_packet, store=False)

if __name__ == "__main__":
    # Replace 'eth0' with the network interface you want to sniff
    # You can find the interface name using the 'ifconfig' command on Unix-based systems or 'ipconfig' on Windows
    interface = "eth0"
    start_sniffing(interface)
