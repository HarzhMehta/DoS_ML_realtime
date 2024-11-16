import pandas as pd
import numpy as np
import time
import socket
import struct
from sklearn.preprocessing import StandardScaler
import joblib
import threading
import sys
from scapy.all import sniff
from flask import Flask, request, render_template

# Load the pre-trained model
model = joblib.load('logistic_DDoS.pkl')  # Your pre-trained model

# Flask app initialization
app = Flask(__name__)

# Define constants and global variables
TIME_WINDOW = 10  # Time window in seconds
PACKET_THRESHOLD = 200  # Threshold for packets per second
packet_count = 0
byte_count = 0
pkt_size_list = []
timestamps = []
attack_result = "No Attack Detected"  # Default state
logs = []  # Store network logs
stop_sniffer = False  # Flag to stop the packet sniffer thread

# Helper function to convert IP to integer
def ip_to_int(ip):
    return struct.unpack("!I", socket.inet_aton(ip))[0]

# Function to encode packet type manually
def encode_pkt_type(pkt_type):
    if pkt_type == 6:  # TCP protocol
        return 3
    elif pkt_type == 0:  # ACK
        return 0
    elif pkt_type == 1:  # CBR
        return 1
    elif pkt_type == 2:  # Ping
        return 2
    else:
        return -1  # Unknown type

# Function to print logs every 10 seconds
def print_logs():
    global logs
    while True:
        time.sleep(TIME_WINDOW)
        if logs:
            print("\n=== Network Logs ===")
            for log in logs:
                print(log)
            logs = []  # Clear logs after printing
        else:
            print("\nNo packets captured in the last 10 seconds.")

# Packet processing function
def packet_sniffer():
    global packet_count, byte_count, pkt_size_list, timestamps, attack_result, logs, stop_sniffer

    def process_packet(packet):
        global packet_count, byte_count, pkt_size_list, timestamps, attack_result, logs, stop_sniffer

        try:
            # Extract features from the packet
            src_ip = ip_to_int(packet[1].src)
            dst_ip = ip_to_int(packet[1].dst)
            pkt_size = len(packet)
            pkt_type = packet[1].proto  # Protocol type (e.g., TCP=6, UDP=17)

            # Encode PKT_TYPE manually
            pkt_type_encoded = encode_pkt_type(pkt_type)

            # Update packet stats
            packet_count += 1
            byte_count += pkt_size

            # Track packet sizes and timestamps
            pkt_size_list.append(pkt_size)
            timestamps.append(time.time())

            # Remove old packets outside the time window
            while timestamps and timestamps[0] < time.time() - TIME_WINDOW:
                timestamps.pop(0)
                pkt_size_list.pop(0)

            # Check for DDoS condition: packets exceed 200 per second
            if len(timestamps) > PACKET_THRESHOLD:
                attack_result = "DDoS Attack Detected: THRESHOLD EXCEEDED !"
                print(attack_result)
                sys.exit()  # Stop the code execution when threshold is exceeded

            # Calculate derived features
            pkt_rate = len(timestamps) / TIME_WINDOW
            byte_rate = sum(pkt_size_list) / TIME_WINDOW
            pkt_avg_size = byte_count / packet_count if packet_count > 0 else 0
            utilization = packet_count / 100  # Example calculation

            # Feature vector for prediction
            features = pd.DataFrame([{
                'SRC_ADD': src_ip,
                'DES_ADD': dst_ip,
                'PKT_SIZE': pkt_size,
                'NUMBER_OF_PKT': packet_count,
                'NUMBER_OF_BYTE': byte_count,
                'PKT_DELAY_NODE': 0,  # Placeholder
                'PKT_RATE': pkt_rate,
                'BYTE_RATE': byte_rate,
                'PKT_AVG_SIZE': pkt_avg_size,
                'UTILIZATION': utilization,
                'PKT_TYPE_ENCODED': pkt_type_encoded
            }])

            # Columns to scale
            feature_columns = [
                'PKT_SIZE', 'NUMBER_OF_PKT', 'NUMBER_OF_BYTE', 'PKT_DELAY_NODE',
                'PKT_RATE', 'BYTE_RATE', 'PKT_AVG_SIZE', 'UTILIZATION', 'PKT_TYPE_ENCODED'
            ]

            # Scale features
            scaler = StandardScaler()
            features[feature_columns] = scaler.fit_transform(features[feature_columns])

            # Predict using the model
            prediction = model.predict(features)

            # Update attack result based on prediction
            if prediction[0] == 1:  # Attack detected
                attack_result = "DDoS Attack Detected"
            else:
                attack_result = "No Attack Detected"

            # Add log entry
            logs.append({
                "SRC_ADD": packet[1].src,
                "DES_ADD": packet[1].dst,
                "PKT_SIZE": pkt_size,
                "PKT_TYPE": pkt_type_encoded,  # Log encoded value
                "RESULT": attack_result
            })

        except Exception as e:
            print(f"Error processing packet: {e}")

    # Sniff packets
    sniff(filter="ip", prn=process_packet, store=False)
    if stop_sniffer:
        print("Packet sniffer stopped due to threshold exceeded.")
        return

# Run the packet sniffer in a background thread
sniffer_thread = threading.Thread(target=packet_sniffer, daemon=True)
sniffer_thread.start()

# Run the log printer in a background thread
log_printer_thread = threading.Thread(target=print_logs, daemon=True)
log_printer_thread.start()

# Flask route for the web interface
@app.route('/')
def home():
    global attack_result
    return render_template('index.html', attack_result=attack_result)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
