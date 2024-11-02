# from scapy.all import sniff, IP, TCP

# # Define the target IP and port
# target_ip = "61.80.52.142"
# target_port = 54321

# def packet_callback(packet):
#     # Check if the packet has IP and TCP layers
#     if IP in packet and TCP in packet:
#         # Check if the destination IP and port match the target
#         if packet[IP].dst == target_ip and packet[TCP].dport == target_port:
#             # Print packet summary
#             print(packet.summary())
#             # Optionally, save the packet to a file or process it further

# # Start sniffing with a filter for TCP packets
# sniff(prn=packet_callback, filter="tcp", store=0)
from scapy.all import sniff, IP

# Define the target IP
target_ip = "61.80.52.142"

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        # Check if the destination IP matches the target
        if packet[IP].dst == target_ip:
            # Print packet summary
            print(packet.summary())

# Start sniffing
sniff(prn=packet_callback, store=0)
