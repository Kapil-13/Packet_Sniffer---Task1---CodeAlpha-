from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import time

def analyze_packets(packets):
    print("\n================ PRINT =================")
    print("Time :", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    for packet in packets:
        if IP in packet:
            ip = packet[IP]
            print("\nSource IP      :", ip.src)
            print("Destination IP :", ip.dst)
            print("TTL            :", ip.ttl)

            if packet.haslayer(TCP):
                print("Protocol       : TCP",
                      " | Ports:", packet[TCP].sport, "→", packet[TCP].dport)

            elif packet.haslayer(UDP):
                print("Protocol       : UDP",
                      " | Ports:", packet[UDP].sport, "→", packet[UDP].dport)

            elif packet.haslayer(ICMP):
                print("Protocol       : ICMP")

    print("=======================================")


while True:
    packets = sniff(timeout=2, store=True)   
    analyze_packets(packets)                
    time.sleep(2)                            
