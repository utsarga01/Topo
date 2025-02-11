import subprocess
import os
import pandas as pd
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch, Host
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.topo import Topo
import joblib  # To load the trained model
import time
import threading

# Load trained model
MODEL_PATH = "./knn_model.joblib"
model = joblib.load()

SCALER_PATH = './scaler.joblib'
scaler = joblib.load(SCALER_PATH)

# Global variables
count = 1

def start_tshark_capture(interface='any', output_file='/tmp/capture.pcap'):
    """Start tshark packet capture."""
    command = ['sudo', 'tshark', '-i', interface, '-w', output_file]
    process = subprocess.Popen(command)
    return process

def log_attack(source_ip, target_ip, attack_type):
    global count
    with open('attack_log.txt', 'a') as f:
        f.write(f"ALERT: {count} - {attack_type} attack detected from {source_ip} to {target_ip}\n")
    count += 1

def extract_features_with_cicflowmeter(pcap_file='/tmp/capture.pcap', output_csv='/tmp/flow_features.csv'):
    """Convert pcap to csv using CICFlowMeter."""
    cicflowmeter_path = '/home/utsarga/Desktop/CICFlowMeter/target/CICFlowMeterV3-0.0.4-SNAPSHOT.jar'
    
    if not os.path.exists(cicflowmeter_path):
        raise FileNotFoundError(f"CICFlowMeter not found at {cicflowmeter_path}")
    
    command = ['java', '-jar', cicflowmeter_path, '-r', pcap_file, '-w', output_csv]
    subprocess.run(command, check=True)
    info(f"\n[+] Features extracted and saved to {output_csv}\n")

def load_and_process_csv(csv_file='/tmp/flow_features.csv'):
    """Load features and normalize them."""
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
        info(f"[X] Error: {e}\n")
        return None

def start_intrusion_detection():
    """Extract features and run ML model for attack prediction."""
    pcap_file = '/tmp/capture.pcap'
    output_csv = '/tmp/flow_features.csv'
    extract_features_with_cicflowmeter(pcap_file, output_csv)
    features = load_and_process_csv(output_csv)
    if features is not None:
        predictions = model.predict(features)
        for i, prediction in enumerate(predictions):
            info(f"Flow {i+1} - Prediction: {prediction}\n")
            log_attack("Unknown", "Unknown", prediction)

def dos_attack(net):
    """Simulate a DoS attack from h2 to h1."""
    h2 = net.get('h2')
    h1 = net.get('h1')
    info("\n[!] Starting DoS attack from h2 to h1...\n")
    h2.cmd(f'hping3 -c 10000 -d 120 -S -w 64 -p 80 --flood {h1.IP()} &')

def ddos_attack(net):
    """Simulate a DDoS attack from h4, h5, h6, h7 to h3."""
    h3 = net.get('h3')
    attackers = ['h4', 'h5', 'h6', 'h7']
    info("\n[!] Starting DDoS attack from multiple hosts to h3...\n")
    for attacker in attackers:
        h = net.get(attacker)
        h.cmd(f'hping3 -c 5000 -d 120 -S -w 64 -p 80 --flood {h3.IP()} &')

class CustomTopo(Topo):
    """Defines a simple topology with two switches and seven hosts."""
    def build(self):
        switch1 = self.addSwitch('s1', cls=OVSSwitch)
        switch2 = self.addSwitch('s2', cls=OVSSwitch)
        
        # Hosts: h1 (Victim for DoS), h2 (Attacker for DoS), h3 (Victim for DDoS), h4-h7 (Attackers for DDoS)
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

if __name__ == '__main__':
    setLogLevel('info')
    os.system('sudo mn -c')
    time.sleep(1)
    
    topo = CustomTopo()
    net = Mininet(topo=topo, switch=OVSSwitch, controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6633))
    net.start()
    info("\n*** Network is running. Testing connectivity...\n")
    net.pingAll()
    
    # Start capturing packets
    tshark_process = start_tshark_capture(interface='any')
    info("\n*** Capturing traffic with Wireshark (tshark)...\n")
    
    # Start DoS and DDoS attacks
    threading.Thread(target=dos_attack, args=(net,), daemon=True).start()
    threading.Thread(target=ddos_attack, args=(net,), daemon=True).start()
    
    # Start intrusion detection
    threading.Thread(target=start_intrusion_detection, daemon=True).start()
    
    # Run Mininet CLI
    CLI(net)
    
    # Cleanup
    net.stop()
    tshark_process.terminate()
    tshark_process.wait()
