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

# Load trained model and scaler
MODEL_PATH = "knn_model.joblib"
model = joblib.load(MODEL_PATH)

SCALER_PATH = './scaler.joblib'
scaler = joblib.load(SCALER_PATH)

# Global variable for logging attack count
count = 1

def start_tshark_capture(interface='any', output_file='/tmp/capture.pcap', capture_duration=3):
    """
    Start tshark capture, filtering only TCP packets.
    """
    command = [
         'sudo', 'timeout', str(capture_duration),
    'tshark', '-i', interface, '-w', output_file, '-F', 'pcap',
    '-f', 'tcp and ip and not (tcp port 6633 or tcp port 6653)'
    ]
    process = subprocess.Popen(command)
    info(f"[+] Capturing TCP packets on {interface} for {capture_duration} seconds...\n")
    return process


def log_attack(source_ip, target_ip, attack_type):
    """Log the detected attack to a file."""
    global count
    with open('attack_log.txt', 'a') as f:
        f.write(f"ALERT: {count} - {attack_type} attack detected from {source_ip} to {target_ip}\n")
    count += 1

def extract_features_with_ntlflowlyzer(pcap_file='/tmp/capture.pcap', output_csv='/tmp/flow_features.csv', config_file='/home/utsarga/Desktop/topo4/config.json'):
    """Convert pcap to csv using NTLFlowLyzer."""
    if not os.path.exists(pcap_file) or os.path.getsize(pcap_file) == 0:
        info(f"[X] Error: {pcap_file} is missing or empty.\n")
        return
    command = ['ntlflowlyzer', '-c', config_file]
    subprocess.run(command, check=True)
    info(f"\n[+] Features extracted and saved to {output_csv}\n")

def load_and_process_csv(csv_file='/tmp/flow_features.csv'):
    """Load features from CSV and normalize them."""
    try:
        df = pd.read_csv(csv_file)
        feature_columns = [
            'Flow Duration', 'Total Fwd Packets', 'Fwd Packets Length Total', 
            'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Active Mean', 
            'Active Std', 'Idle Std', 'Fwd Seg Size Min'
        ]
        data = df[feature_columns]
        normalized_features = scaler.transform(data)
        return normalized_features
    except Exception as e:
        info(f"[X] Error loading CSV: {e}\n")
        return None

def start_intrusion_detection():
    """Extract features and run ML model for attack prediction."""
    pcap_file = '/tmp/capture.pcap'
    output_csv = '/tmp/flow_features.csv'
    
    # 10-second delay before converting PCAP to CSV
    info("\n[+] Waiting 10 seconds before converting PCAP to CSV...\n")
    time.sleep(10)
    
    # Extract features with ntlflowlyzer
    extract_features_with_ntlflowlyzer(pcap_file, output_csv)
    
    features = load_and_process_csv(output_csv)
    if features is not None:
        predictions = model.predict(features)
        for i, prediction in enumerate(predictions):
            info(f"Flow {i+1} - Prediction: {prediction}\n")
            log_attack("Unknown", "Unknown", prediction)

def dos_attack(net, duration=5):
    """Simulate a DoS attack from h2 to h1, sending 200 TCP packets."""
    h2 = net.get('h2')
    h1 = net.get('h1')
    info(f"\n[!] Starting DoS attack from h2 to h1, sending 25 TCP packets...\n")
    h2.cmd(f'hping3 -c 25 -S -p 80 {h1.IP()} &')

def ddos_attack(net, duration=5):
    """Simulate a DDoS attack from multiple hosts to h3, each sending 100 TCP packets."""
    h3 = net.get('h3')
    attackers = ['h4', 'h5', 'h6', 'h7']
    info(f"\n[!] Starting DDoS attack from multiple hosts to h3, each sending 25 TCP packets...\n")
    for attacker in attackers:
        h = net.get(attacker)
        h.cmd(f'hping3 -c 25 -S -p 80 {h3.IP()} &')

class CustomTopo(Topo):
    """Defines a simple topology with two switches and seven hosts."""
    def build(self):
        switch1 = self.addSwitch('s1', cls=OVSSwitch)
        switch2 = self.addSwitch('s2', cls=OVSSwitch)
        
        hosts = [self.addHost(f'h{i}') for i in range(1, 8)]
        
        for i, host in enumerate(hosts):
            if i < 2:
                self.addLink(switch1, host)
            else:
                self.addLink(switch2, host)
        
        self.addLink(switch1, switch2)

if __name__ == '__main__':
    setLogLevel('info')
    os.system('sudo mn -c')
    time.sleep(1)
    
    topo = CustomTopo()
    net = Mininet(topo=topo, switch=OVSSwitch, 
                  controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6633))
    net.start()
    info("\n*** Network is running. Testing connectivity...\n")
    net.pingAll()
    
    # Update DNS resolver and install hping3 on all hosts
    for host in net.hosts:
        host.cmd("sed -i 's/nameserver 127\\.0\\.0\\.53/nameserver 8.8.8.8/' /etc/resolv.conf")
        host.cmd("apt update -y")
        host.cmd("apt install -y hping3")
    
    tshark_process = start_tshark_capture(interface='any', output_file='/tmp/capture.pcap', capture_duration=15)
    time.sleep(1)
    
    dos_attack(net, duration=5)
    ddos_attack(net, duration=5)
    
    tshark_process.wait()
    info("\n*** Tshark capture has stopped. Starting intrusion detection...\n")
    
    start_intrusion_detection()
    
    CLI(net)
    net.stop()
