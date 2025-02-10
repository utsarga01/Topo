import subprocess
import os
import pandas as pd
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.topo import Topo
import joblib  # To load the trained model
import time
import signal
import sys
from threading import Thread

# Load trained model
MODEL_PATH = "./knn_model.joblib"
model = joblib.load(MODEL_PATH)

SCALER_PATH = './scaler.joblib'
scaler = joblib.load(SCALER_PATH)

# Global variables
count = 1

class CustomSwitch(OVSSwitch):
    """Custom Switch class with DoS detection and intrusion monitoring using ML."""
    def __init__(self, *args, **kwargs):
        super(CustomSwitch, self).__init__(*args, **kwargs)
        self.last_time = time.time()

    def monitor_traffic(self, packet):
        """Test model using predefined features."""
        pre_features = [3, 2, 12, 6, 6, 0.0, 0.0, 0.0, 20]
        prediction = model.predict([pre_features])[0]
        if prediction in ["DoS", "DDoS", "Benign"]:
            info(f"\n[!] {prediction} attack detected!\n")
            log_attack("Unknown", "Unknown", prediction)

class CustomTopo(Topo):
    """Defines a simple topology with two switches and four hosts."""
    def build(self):
        switch1 = self.addSwitch('s1', cls=CustomSwitch)
        switch2 = self.addSwitch('s2', cls=CustomSwitch)
        
        # Hosts: h1 (Victim for DoS), h2 (Attacker for DoS), h3 (Victim for DDoS), h4, h5, h6, h7 (Attackers for DDoS)
        h1 = self.addHost('h1')  # DoS victim
        h2 = self.addHost('h2')  # DoS attacker
        h3 = self.addHost('h3')  # DDoS victim
        h4 = self.addHost('h4')  # DDoS attacker
        h5 = self.addHost('h5')  # DDoS attacker
        h6 = self.addHost('h6')  # DDoS attacker
        h7 = self.addHost('h7')  # DDoS attacker

        # Link hosts to switches
        self.addLink(switch1, h1)
        self.addLink(switch1, h2)
        self.addLink(switch2, h3)
        self.addLink(switch2, h4)
        self.addLink(switch2, h5)
        self.addLink(switch2, h6)
        self.addLink(switch2, h7)
        
        # Link switches to each other
        self.addLink(switch1, switch2)

def cleanup_mininet():
    """Ensures Mininet is cleaned up before starting a new instance."""
    info("\n[!] Cleaning up previous Mininet instances...\n")
    os.system('sudo mn -c')

def log_attack(source_ip, target_ip, attack_type):
    global count
    with open('attack_log.txt', 'a') as f:
        f.write(f"ALERT: {count} - {attack_type} attack detected from {source_ip} to {target_ip}\n")
    count += 1

def extract_features_with_cicflowmeter(pcap_file='/tmp/capture.pcap', output_csv='/tmp/flow_features.csv'):
    """
    Extracts features from pcap file using CICFlowMeter and saves them in a CSV file.
    """
    # Path to the CICFlowMeter executable
    cicflowmeter_path = '/path/to/CICFlowMeter.exe'  # Modify the path accordingly

    # Check if CICFlowMeter is available
    if not os.path.exists(cicflowmeter_path):
        raise FileNotFoundError(f"CICFlowMeter executable not found at {cicflowmeter_path}")
    
    # Command to run CICFlowMeter
    command = [
        cicflowmeter_path,
        '-r', pcap_file,          # pcap file to extract features from
        '-w', output_csv         # Output CSV file
    ]

    # Run the command
    try:
        subprocess.run(command, check=True)
        info(f"\n[+] Features extracted and saved to {output_csv}\n")
    except subprocess.CalledProcessError as e:
        info(f"[X] Error while running CICFlowMeter: {e}\n")

def load_and_process_csv(csv_file='/tmp/flow_features.csv'):
    """
    Loads the extracted flow features from the CSV file and processes them for prediction.
    """
    try:
        # Load the CSV into a DataFrame
        flow_df = pd.read_csv(csv_file)

        # Extract specific features (the ones needed for prediction)
        feature_columns = [
            'Flow Duration', 
            'Total Fwd Packets', 
            'Fwd Packets Length Total', 
            'Fwd Packet Length Max', 
            'Fwd Packet Length Min', 
            'Active Mean', 
            'Active Std', 
            'Idle Std', 
            'Fwd Seg Size Min'
        ]

        # Select the required columns
        feature_data = flow_df[feature_columns]
        
        # Normalize the features using the scaler
        normalized_features = scaler.transform(feature_data)

        return normalized_features
    except FileNotFoundError as e:
        info(f"[X] Error: {e}")
        return None

def start_intrusion_detection():
    """Starts an intrusion detection system (IDS) using CICFlowMeter for feature extraction."""
    info("\n[*] Starting feature extraction with CICFlowMeter...\n")
    
    # Path to the pcap file captured by tshark
    pcap_file = '/tmp/capture.pcap'
    output_csv = '/tmp/flow_features.csv'

    # Extract features and save to CSV using CICFlowMeter
    extract_features_with_cicflowmeter(pcap_file=pcap_file, output_csv=output_csv)
    
    # Load and process the extracted features
    features = load_and_process_csv(csv_file=output_csv)
    
    if features is not None:
        # Use the machine learning model to predict attack types (e.g., KNN model)
        predictions = model.predict(features)
        
        # Output predictions for the flows
        for i, prediction in enumerate(predictions):
            info(f"Flow {i+1} - Prediction: {prediction}")
            log_attack("Unknown", "Unknown", prediction)
    
    else:
        info("[X] No features extracted, cannot make predictions.")

def start_tshark_capture(interface='any', output_file='/tmp/capture.pcap'):
    info(f"\n[*] Starting tshark capture on interface {interface}...\n")
    command = ['sudo', 'tshark', '-i', interface, '-w', output_file]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(2)
    return process

def stop_tshark_capture(process):
    info("\n[*] Stopping tshark capture...\n")
    process.terminate()
    process.wait()

def open_wireshark(pcap_file='/tmp/capture.pcap'):
    """Function to open Wireshark with the captured pcap file."""
    info(f"\n[*] Opening Wireshark to analyze the captured packets...\n")
    command = ['sudo', 'wireshark', pcap_file]
    subprocess.Popen(command)

def signal_handler(sig, frame):
    info("\n[*] Keyboard interrupt received. Exiting...\n")
    stop_tshark_capture(tshark_process)
    sys.exit(0)

if __name__ == '__main__':
    setLogLevel('info')
    signal.signal(signal.SIGINT, signal_handler)
    cleanup_mininet()
    time.sleep(1)
    topo = CustomTopo()
    net = Mininet(
        topo=topo,
        switch=CustomSwitch,
        controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6633)
    )
    net.start()
    info("\n*** Network is running. Testing connectivity...\n")
    net.pingAll()
    intrusion_thread = Thread(target=start_intrusion_detection, daemon=True)
    intrusion_thread.start()
    tshark_process = start_tshark_capture(interface='any')
    info("\n*** Starting Mininet CLI...\n")
    CLI(net)
    info("\n*** Stopping network...\n")
    net.stop()
    stop_tshark_capture(tshark_process)
    open_wireshark(pcap_file='/tmp/capture.pcap')  # Open Wireshark with the captured file
