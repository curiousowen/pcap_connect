import pyshark
import requests
import re
import matplotlib.pyplot as plt
from collections import defaultdict
from datetime import datetime


API_KEY = 'your_api_key'


def load_pcap(file_path):
    print(f"Loading PCAP file: {file_path}")
    return pyshark.FileCapture(file_path, only_summaries=False)


def check_ip_threat(ip):
    url = f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip}'
    headers = {'Key': API_KEY, 'Accept': 'application/json'}
    
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json().get('data', {})
        if data.get('abuseConfidenceScore', 0) > 50:
            print(f"Suspicious IP Detected: {ip}")
            return True
    return False

def analyze_traffic(packets):
    suspicious_ips = []
    beacon_intervals = defaultdict(list)
    dns_queries = []
    
    domain_regex = re.compile(r"^(.*\.)?([a-z0-9-]{1,63}\.){1,2}(com|net|org|info|biz|ru)$")
    
    for packet in packets:
        try:
            if hasattr(packet, 'ip'):
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                packet_time = datetime.strptime(packet.sniff_time.isoformat(), "%Y-%m-%dT%H:%M:%S.%f")
                
                # Check if the IP is suspicious
                if check_ip_threat(src_ip) or check_ip_threat(dst_ip):
                    suspicious_ips.append({'src': src_ip, 'dst': dst_ip, 'time': packet.sniff_time})

                # Track beaconing activity (time differences between packets from same IP)
                beacon_intervals[src_ip].append(packet_time.timestamp())
            
            
            if hasattr(packet, 'dns') and hasattr(packet.dns, 'qry_name'):
                domain_name = packet.dns.qry_name
                if not domain_regex.match(domain_name):
                    dns_queries.append({'domain': domain_name, 'time': packet.sniff_time})
                    
        except AttributeError:
            continue

    return suspicious_ips, dns_queries, beacon_intervals


def visualize_beaconing(beacon_intervals):
    for ip, times in beacon_intervals.items():
        intervals = [times[i] - times[i - 1] for i in range(1, len(times))]
        if intervals:
            plt.plot(intervals, label=f"Beaconing from {ip}")
    
    plt.title("Beaconing Activity (Time Intervals)")
    plt.xlabel("Packet Index")
    plt.ylabel("Time Interval (s)")
    plt.legend()
    plt.show()


def run_pcap_connect(file_path):
    print("Starting PCAP Analysis...")
    packets = load_pcap(file_path)
    
    print("Analyzing traffic for suspicious behavior...")
    suspicious_ips, dns_queries, beacon_intervals = analyze_traffic(packets)
    
    
    print(f"\nSuspicious IP Addresses ({len(suspicious_ips)} detected):")
    for entry in suspicious_ips:
        print(f"Source: {entry['src']} -> Destination: {entry['dst']} at {entry['time']}")
    
    print(f"\nSuspicious DNS Queries ({len(dns_queries)} detected):")
    for entry in dns_queries:
        print(f"Domain: {entry['domain']} at {entry['time']}")
    
    print("\nVisualizing beaconing patterns...")
    visualize_beaconing(beacon_intervals)

if __name__ == "__main__":
    # Example: replace 'sample.pcap' with your actual file path
    pcap_file = 'sample.pcap'
    run_pcap_connect(pcap_file)
