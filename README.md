# 🚀 Network Attack Detection System

## **📖 Project Overview**
This project is an **AI-powered intrusion detection system (IDS)** designed to detect **port scanning and DDoS attacks** in network traffic. It uses **machine learning (ML)** to classify network activities as **normal or malicious** based on features extracted from network packets.

### **🔍 How It Works**
1. **Network Traffic Generation**  
   - The system can use **Mininet** to simulate network traffic.  
   - In real-world deployment, it captures packets from **live network interfaces** such as Wireshark.

2. **Packet Capture & Feature Extraction**  
   - `capture.py` captures real-time network traffic using **tcpdump** or other packet capture tools.  
   - It extracts relevant features similar to **NSL-KDD dataset** for ML classification.

3. **Machine Learning Model**  
   - `data.py` trains a **Random Forest model** using pre-labeled network traffic data.  
   - It preprocesses the data, applies **feature scaling & encoding**, and trains the model.

4. **Attack Detection**  
   - The trained model analyzes new network traffic to classify potential attacks.  
   - It can detect **port scanning, DDoS attacks, and other anomalies**.
   - 
5. **Analysis Dashboard**  
   - dashboard.html is a simple dashboard to display features from the captured packets.
---
