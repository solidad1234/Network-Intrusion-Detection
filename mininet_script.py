from scapy.all import sniff
import requests

def extract_features(packet):
    """
    This function should extract and compute features from the packet.
    For demonstration, we are using a hardcoded list.
    """
    features = [0, "tcp", "http", "SF", 232, 8153, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 5, 0.20, 0.20, 0.00, 0.00, 1.00, 0.00, 0.00, 30, 255, 1.00, 0.00, 0.03, 0.04, 0.03, 0.01, 0.00]
    return features

def packet_callback(packet):
    features = extract_features(packet)
    url = "http://localhost:5000/predict"
    try:
        response = requests.post(url, json={"features": features})
        result = response.json()
        print("Packet prediction:", result)
    except Exception as e:
        print("Error sending request:", e)

sniff(prn=packet_callback, count=10)
