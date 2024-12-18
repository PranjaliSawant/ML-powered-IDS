from scapy.all import sniff, IP, TCP, UDP #Provides packet capture and packet-level protocols
import logging

# Configure logging
logging.basicConfig(filename='signature_ids.log', level=logging.INFO) #to store detected intrusions

#DEFINING SIGNATURES 
#signatures are predefined pattern of malicious or suspicious network traffic
signatures = [
    {"src_ip": "192.168.1.100", "dst_ip": "192.168.1.101", "src_port": 12345, "dst_port": 80, "protocol": "TCP", "content": "malicious"},
    {"src_ip": "0.0.0.0", "dst_ip": "255.255.255.255", "src_port": 68, "dst_port": 67, "protocol": "UDP", "content": "DHCP Discover"},
 
]

def extract_features(packet):
    features = {}
    if IP in packet: #Extracts information (features) from a network packet
        features['src_ip'] = packet[IP].src
        features['dst_ip'] = packet[IP].dst
    if TCP in packet:
        features['src_port'] = packet[TCP].sport
        features['dst_port'] = packet[TCP].dport
        features['protocol'] = "TCP"
        features['content'] = bytes(packet[TCP].payload).decode(errors='ignore')  #packet payload is the content
    elif UDP in packet:
        features['src_port'] = packet[UDP].sport
        features['dst_port'] = packet[UDP].dport
        features['protocol'] = "UDP"
        features['content'] = bytes(packet[UDP].payload).decode(errors='ignore')
    return features

def match_signature(packet_features, signature): #Match features of packet and signature
    for key in signature:
        if key in packet_features and packet_features[key] != signature[key]:
            return False
    return True

def log_intrusion(packet_features, signature): #logs intrusion and displays alert in the console
    logging.info(f"Intrusion detected: {packet_features} matched {signature}")
    print(f"Intrusion detected: {packet_features} matched {signature}")

def analyze_packet(packet):   #analyzes packet features and if they match with signatures
    features = extract_features(packet)
    for signature in signatures:
        if match_signature(features, signature):
            log_intrusion(features, signature)

def packet_handler(packet):
    analyze_packet(packet)

if __name__ == "__main__":  #initiates packet capturing
    print("Starting signature-based IDS...")
    sniff(prn=packet_handler, store=0)  # 'store=0' to avoid storing packets in memory
