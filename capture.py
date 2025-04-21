#!/usr/bin/env python3
import time
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP

# A dictionary to track per-flow statistics:
# Key: (srcIP, dstIP, srcPort, dstPort, protocol)
flow_stats = defaultdict(lambda: {
    "count": 0,        # number of packets in this flow
    "bytes": 0,        # total bytes in this flow
    "start_time": time.time(),  # when we first saw this flow
    "tcp_flags": set(),         # keep track of different TCP flags seen
    # ...
})

def map_protocol(proto_num):
    """Convert numeric protocol to the string expected by your model (e.g., 'tcp', 'udp', 'icmp')."""
    if proto_num == 6:
        return "tcp"
    elif proto_num == 17:
        return "udp"
    elif proto_num == 1:
        return "icmp"
    else:
        return "other"

def map_port_to_service(port):
    """Dummy service detection based on port. Expand this as needed."""
    if port == 80:
        return "http"
    elif port == 21:
        return "ftp"
    elif port == 23:
        return "telnet"
    elif port == 25:
        return "smtp"
    # ...
    return "private"

def map_tcp_flags_to_flag(tcp_flags):
    """
    Convert raw TCP flag bits to something akin to NSL-KDD's 'SF', 'S0', etc.
    For example:
      0x02 = SYN only
      0x12 = SYN+ACK
      0x04 = RST
      0x10 = ACK
    This is simplistic; real logic might track connection states over time.
    """
    # logic:
    if tcp_flags & 0x02 and not (tcp_flags & 0x10):
        return "S0"  # SYN sent, no ACK
    elif (tcp_flags & 0x02) and (tcp_flags & 0x10):
        return "SF"  # SYN+ACK, etc.
    elif tcp_flags & 0x04:
        return "REJ" # RST
    return "OTH"

def extract_features(packet):
    """Extract or update flow-level stats, then build a 41-column vector (if NSL-KDD style)."""

    if not packet.haslayer(IP):
        return None

    ip_layer = packet[IP]
    src = ip_layer.src
    dst = ip_layer.dst
    proto_num = ip_layer.proto  # e.g., 6=TCP, 17=UDP, 1=ICMP

    # Determine ports and flags for TCP/UDP
    if proto_num == 6 and packet.haslayer(TCP):
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        tcp_flags = packet[TCP].flags
    elif proto_num == 17 and packet.haslayer(UDP):
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        tcp_flags = 0
    else:
        sport = 0
        dport = 0
        tcp_flags = 0

    # Identify the flow
    flow_key = (src, dst, sport, dport, proto_num)
    stats = flow_stats[flow_key]

    # Update stats
    stats["count"] += 1
    stats["bytes"] += len(packet)

    if proto_num == 6 and tcp_flags:
        stats["tcp_flags"].add(tcp_flags)

    duration = time.time() - stats["start_time"]
    protocol_type = map_protocol(proto_num)
    service = map_port_to_service(dport) if protocol_type == "tcp" else "other"
    # For a single packet, pick the first TCP flags we see in this flow:
    if stats["tcp_flags"]:
        any_flags = next(iter(stats["tcp_flags"]))
        flag = map_tcp_flags_to_flag(any_flags)
    else:
        flag = "OTH"

    src_bytes = stats["bytes"]  # total bytes from this flow
    dst_bytes = 0  #reverse-flow tracking to do this properly
    land = 0       # set to 1 if srcIP == dstIP and srcPort == dstPort, etc.

    # Now, build a 41-column list matching your model’s schema
    # For demonstration, we'll fill the rest with zeros or placeholders.
    features = [
        duration,                # duration
        protocol_type,          # protocol_type (string)
        service,                # service (string)
        flag,                   # flag (string)
        src_bytes,              # src_bytes
        dst_bytes,              # dst_bytes
        land,                   # land
        0,                      # wrong_fragment
        0,                      # urgent
        0,                      # hot
        0,                      # num_failed_logins
        0,                      # logged_in
        0,                      # num_compromised
        0,                      # root_shell
        0,                      # su_attempted
        0,                      # num_root
        0,                      # num_file_creations
        0,                      # num_shells
        0,                      # num_access_files
        0,                      # num_outbound_cmds
        0,                      # is_host_login
        0,                      # is_guest_login
        stats["count"],         # count (packets in this flow)
        0,                      # srv_count
        0,                      # serror_rate
        0,                      # srv_serror_rate
        0,                      # rerror_rate
        0,                      # srv_rerror_rate
        0,                      # same_srv_rate
        0,                      # diff_srv_rate
        0,                      # srv_diff_host_rate
        0,                      # dst_host_count
        0,                      # dst_host_srv_count
        0,                      # dst_host_same_srv_rate
        0,                      # dst_host_diff_srv_rate
        0,                      # dst_host_same_src_port_rate
        0,                      # dst_host_srv_diff_host_rate
        0,                      # dst_host_serror_rate
        0,                      # dst_host_srv_serror_rate
        0,                      # dst_host_rerror_rate
        0,                      # dst_host_srv_rerror_rate
    ]
    return features

def packet_callback(packet):
    features = extract_features(packet)
    if features is None:
        return

    print("Extracted Features:", features)  #debugging

    try:
        import requests
        response = requests.post("http://127.0.0.1:5000/predict", json={"features": features})
        print("Prediction:", response.json())
    except Exception as e:
        print("Error sending request:", e)


if __name__ == '__main__':
    from scapy.all import sniff
    sniff(iface="h1-eth0", prn=packet_callback, store=False, filter="tcp or udp")

