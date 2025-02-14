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
import json



CONFIG_TEMPLATE={
    "pcap_file_address": "/path/to/pcap",
    "output_file_address": "/path/to/csv",
    "number_of_threads": 4,
    "feature_extractor_min_flows": 2500,
    "writer_min_rows": 1000,
    "read_packets_count_value_log_info": 1000000,
    "check_flows_ending_min_flows": 20000,
    "capturer_updating_flows_min_value": 5000,
    "max_flow_duration": 120000,
    "activity_timeout": 300,
    "floating_point_unit": ".4f",
    "max_rows_number": 800000,
    "features_ignore_list": ['payload_bytes_median', 'bwd_syn_flag_counts', 'fwd_segment_size_max', 'bwd_payload_bytes_min', 'max_bwd_payload_bytes_delta_len', 'median_header_bytes_delta_len', 'mean_header_bytes_delta_len', 'label', 'bwd_mode_header_bytes', 'segment_size_std', 'fwd_std_header_bytes', 'fwd_cov_header_bytes', 'max_fwd_packets_delta_time', 'cov_bwd_packets_delta_time', 'packet_IAT_max', 'cov_fwd_packets_delta_time', 'fwd_min_header_bytes', 'mean_fwd_packets_delta_len', 'active_max', 'fwd_cwr_flag_percentage_in_fwd_packets', 'bwd_segment_size_max', 'bwd_packets_IAT_variance', 'idle_std', 'packets_IAT_median', 'mean_packets_delta_time', 'cov_header_bytes_delta_len', 'median_header_bytes', 'bwd_urg_flag_percentage_in_total', 'skewness_header_bytes_delta_len', 'delta_start', 'mode_header_bytes_delta_len', 'bwd_bulk_total_size', 'min_bwd_header_bytes_delta_len', 'median_fwd_packets_delta_time', 'bwd_packets_IAT_median', 'bwd_ack_flag_counts', 'skewness_fwd_payload_bytes_delta_len', 'bwd_cwr_flag_percentage_in_total', 'ack_flag_counts', 'bwd_psh_flag_percentage_in_total', 'max_packets_delta_len', 'mode_header_bytes', 'min_header_bytes_delta_len', 'bwd_syn_flag_percentage_in_total', 'segment_size_cov', 'variance_bwd_header_bytes_delta_len', 'bwd_total_header_bytes', 'fwd_segment_size_cov', 'bwd_ece_flag_percentage_in_total', 'std_fwd_payload_bytes_delta_len', 'idle_skewness', 'protocol', 'fwd_psh_flag_percentage_in_total', 'active_cov', 'bwd_urg_flag_percentage_in_bwd_packets', 'max_bwd_header_bytes_delta_len', 'bwd_payload_bytes_median', 'skewness_bwd_packets_delta_time', 'fwd_cwr_flag_counts', 'segment_size_variance', 'fwd_segment_size_mean', 'subflow_fwd_bytes', 'variance_fwd_packets_delta_len', 'fwd_mode_header_bytes', 'psh_flag_counts', 'cov_bwd_payload_bytes_delta_len', 'cwr_flag_counts', 'handshake_state', 'bwd_ece_flag_counts', 'fwd_packets_IAT_median', 'bwd_packets_count', 'fwd_rst_flag_counts', 'bwd_segment_size_median', 'fwd_segment_size_median', 'syn_flag_percentage_in_total', 'bwd_packets_IAT_mode', 'fwd_fin_flag_percentage_in_fwd_packets', 'bwd_packets_IAT_total', 'fwd_cwr_flag_percentage_in_total', 'fwd_variance_header_bytes', 'cov_fwd_header_bytes_delta_len', 'idle_cov', 'timestamp', 'min_header_bytes', 'segment_size_skewness', 'packets_IAT_mean', 'fwd_payload_bytes_min', 'payload_bytes_cov', 'fwd_syn_flag_percentage_in_fwd_packets', 'std_payload_bytes_delta_len', 'bwd_median_header_bytes', 'fwd_fin_flag_percentage_in_total', 'fwd_packets_rate', 'segment_size_max', 'fwd_bulk_per_packet', 'cov_fwd_packets_delta_len', 'active_mode', 'ece_flag_counts', 'std_header_bytes_delta_len', 'src_ip', 'fwd_urg_flag_percentage_in_fwd_packets', 'variance_fwd_packets_delta_time', 'packet_IAT_std', 'std_bwd_packets_delta_len', 'min_fwd_payload_bytes_delta_len', 'active_median', 'idle_median', 'mode_fwd_packets_delta_time', 'median_payload_bytes_delta_len', 'bwd_payload_bytes_max', 'bwd_fin_flag_percentage_in_bwd_packets', 'packet_IAT_min', 'fwd_mean_header_bytes', 'bwd_segment_size_skewness', 'fwd_packets_IAT_mode', 'subflow_bwd_bytes', 'min_bwd_payload_bytes_delta_len', 'skewness_payload_bytes_delta_len', 'bwd_min_header_bytes', 'skewness_bwd_packets_delta_len', 'payload_bytes_std', 'fwd_bulk_duration', 'variance_bwd_packets_delta_time', 'min_payload_bytes_delta_len', 'skewness_bwd_header_bytes_delta_len', 'packets_IAT_skewness', 'cov_payload_bytes_delta_len', 'fwd_ece_flag_percentage_in_total', 'min_packets_delta_len', 'bwd_payload_bytes_skewness', 'segment_size_median', 'active_mean', 'bwd_packets_IAT_mean', 'cov_packets_delta_len', 'bytes_rate', 'max_payload_bytes_delta_len', 'fwd_segment_size_std', 'rst_flag_counts', 'mode_packets_delta_time', 'fwd_packets_count', 'avg_fwd_bytes_per_bulk', 'bwd_bulk_per_packet', 'bwd_psh_flag_counts', 'bwd_psh_flag_percentage_in_bwd_packets', 'mean_bwd_payload_bytes_delta_len', 'skewness_bwd_payload_bytes_delta_len', 'bwd_packets_IAT_std', 'fwd_fin_flag_counts', 'packets_count', 'min_fwd_packets_delta_len', 'fwd_ack_flag_counts', 'mode_packets_delta_len', 'fwd_urg_flag_percentage_in_total', 'fin_flag_percentage_in_total', 'segment_size_min', 'bwd_fin_flag_percentage_in_total', 'bwd_ack_flag_percentage_in_total', 'max_fwd_payload_bytes_delta_len', 'max_header_bytes', 'min_bwd_packets_delta_time', 'bwd_ece_flag_percentage_in_bwd_packets', 'fwd_packets_IAT_max', 'bwd_payload_bytes_cov', 'fwd_rst_flag_percentage_in_total', 'fin_flag_counts', 'fwd_segment_size_mode', 'payload_bytes_skewness', 'fwd_ack_flag_percentage_in_total', 'max_bwd_packets_delta_time', 'fwd_urg_flag_counts', 'max_fwd_packets_delta_len', 'total_header_bytes', 'rst_flag_percentage_in_total', 'ece_flag_percentage_in_total', 'fwd_payload_bytes_mode', 'active_skewness', 'mean_fwd_header_bytes_delta_len', 'down_up_rate', 'variance_payload_bytes_delta_len', 'std_packets_delta_len', 'active_min', 'bwd_packets_IAT_skewness', 'dst_ip', 'median_fwd_payload_bytes_delta_len', 'payload_bytes_min', 'fwd_packets_IAT_min', 'fwd_payload_bytes_cov', 'bwd_bytes_rate', 'cwr_flag_percentage_in_total', 'bwd_rst_flag_percentage_in_bwd_packets', 'std_bwd_payload_bytes_delta_len', 'variance_header_bytes_delta_len', 'std_packets_delta_time', 'bwd_cwr_flag_counts', 'max_fwd_header_bytes_delta_len', 'bwd_cwr_flag_percentage_in_bwd_packets', 'dst_port', 'bwd_packets_IAT_min', 'mode_bwd_packets_delta_len', 'mean_payload_bytes_delta_len', 'fwd_total_header_bytes', 'bwd_payload_bytes_mode', 'packet_IAT_total', 'min_bwd_packets_delta_len', 'bwd_rst_flag_percentage_in_total', 'median_fwd_header_bytes_delta_len', 'std_fwd_packets_delta_time', 'bwd_skewness_header_bytes', 'mean_fwd_packets_delta_time', 'fwd_ack_flag_percentage_in_fwd_packets', 'variance_bwd_payload_bytes_delta_len', 'bwd_ack_flag_percentage_in_bwd_packets', 'fwd_psh_flag_percentage_in_fwd_packets', 'bwd_segment_size_mode', 'mean_bwd_header_bytes_delta_len', 'fwd_max_header_bytes', 'mean_fwd_payload_bytes_delta_len', 'urg_flag_counts', 'std_fwd_header_bytes_delta_len', 'idle_variance', 'fwd_median_header_bytes', 'max_bwd_packets_delta_len', 'fwd_packets_IAT_std', 'bwd_payload_bytes_std', 'bwd_cov_header_bytes', 'fwd_payload_bytes_variance', 'mode_fwd_payload_bytes_delta_len', 'fwd_segment_size_skewness', 'variance_header_bytes', 'bwd_segment_size_std', 'fwd_packets_IAT_cov', 'mean_packets_delta_len', 'skewness_fwd_packets_delta_len', 'bwd_mean_header_bytes', 'fwd_ece_flag_percentage_in_fwd_packets', 'urg_flag_percentage_in_total', 'bwd_payload_bytes_variance', 'bwd_urg_flag_counts', 'avg_bwd_bytes_per_bulk', 'fwd_skewness_header_bytes', 'min_fwd_header_bytes_delta_len', 'idle_max', 'bwd_packets_IAT_max', 'subflow_fwd_packets', 'fwd_bytes_rate', 'fwd_syn_flag_percentage_in_total', 'skewness_header_bytes', 'packets_IAT_cov', 'src_port', 'fwd_payload_bytes_mean', 'fwd_payload_bytes_skewness', 'idle_min', 'skewness_packets_delta_time', 'mode_bwd_payload_bytes_delta_len', 'bwd_bulk_state_count', 'median_bwd_packets_delta_len', 'fwd_rst_flag_percentage_in_fwd_packets', 'fwd_bulk_state_count', 'segment_size_mode', 'bwd_segment_size_cov', 'bwd_max_header_bytes', 'median_bwd_header_bytes_delta_len', 'min_fwd_packets_delta_time', 'fwd_psh_flag_counts', 'mode_fwd_header_bytes_delta_len', 'payload_bytes_variance', 'flow_id', 'bwd_segment_size_variance', 'skewness_fwd_packets_delta_time', 'cov_fwd_payload_bytes_delta_len', 'bwd_segment_size_min', 'syn_flag_counts', 'std_header_bytes', 'fwd_payload_bytes_median', 'bwd_std_header_bytes', 'fwd_packets_IAT_total', 'median_packets_delta_len', 'median_fwd_packets_delta_len', 'cov_packets_delta_time', 'mean_header_bytes', 'cov_bwd_header_bytes_delta_len', 'bwd_rst_flag_counts', 'psh_flag_percentage_in_total', 'median_bwd_packets_delta_time', 'std_bwd_header_bytes_delta_len', 'packets_IAT_mode', 'mean_bwd_packets_delta_len', 'handshake_duration', 'variance_packets_delta_len', 'segment_size_mean', 'ack_flag_percentage_in_total', 'payload_bytes_mode', 'avg_fwd_bulk_rate', 'subflow_bwd_packets', 'skewness_packets_delta_len', 'idle_mode', 'active_std', 'mode_payload_bytes_delta_len', 'fwd_syn_flag_counts', 'fwd_ece_flag_counts', 'median_packets_delta_time', 'payload_bytes_mean', 'std_fwd_packets_delta_len', 'avg_bwd_packets_bulk_rate', 'mean_bwd_packets_delta_time', 'total_payload_bytes', 'variance_packets_delta_time', 'variance_fwd_header_bytes_delta_len', 'bwd_payload_bytes_mean', 'packets_IAT_variance', 'variance_bwd_packets_delta_len', 'variance_fwd_payload_bytes_delta_len', 'skewness_fwd_header_bytes_delta_len', 'fwd_packets_IAT_variance', 'fwd_payload_bytes_std', 'active_variance', 'fwd_bulk_total_size', 'cov_header_bytes', 'cov_bwd_packets_delta_len', 'fwd_segment_size_min', 'bwd_packets_IAT_cov', 'bwd_variance_header_bytes', 'avg_bwd_bulk_rate', 'fwd_packets_IAT_skewness', 'payload_bytes_max', 'median_bwd_payload_bytes_delta_len', 'mode_bwd_header_bytes_delta_len', 'bwd_fin_flag_counts', 'mode_bwd_packets_delta_time', 'bwd_syn_flag_percentage_in_bwd_packets', 'max_header_bytes_delta_len', 'std_bwd_packets_delta_time', 'bwd_bulk_duration', 'mode_fwd_packets_delta_len', 'fwd_segment_size_variance', 'avg_fwd_packets_per_bulk','label']

}


# Load trained model and scaler
MODEL_PATH = "./knn_model1.joblib"
model = joblib.load(MODEL_PATH)

SCALER_PATH = './min_max_scaler.pkl'
scaler = joblib.load(SCALER_PATH)

prediction_out_file = open("result",'w',1)

# Global variable for logging attack count
count = 1

def make_config_file(interface):
    config = CONFIG_TEMPLATE.copy() 
    config["pcap_file_address"] = f"/tmp/capture_{interface}.pcap"
    config["output_file_address"] = f"/tmp/output_{interface}.csv"
    out_file = f"/tmp/config_{interface}.json"
    with open(out_file, 'w') as f:
        json.dump(config, f, indent=4) 
    print(f"Config file created: {out_file}")
    return out_file # Config for NTLFlowlyzer
    

def find_valid_interfaces():
    cmd = 'ip -br a | grep -E "s1-eth|s2-eth" | grep -v nat | awk -F@ \'{print $1}\''
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    # Convert output to a list (split by newline and remove empty lines)
    interfaces = result.stdout.strip().split("\n")

    print(interfaces)
    return interfaces

def start_tcpdump_capture(interface, output_file, capture_duration):
    """
    Start tcpdump capture, filtering only TCP packets and excluding malformed packets.
    """
    if os.path.exists(output_file):
        print(f"File {output_file} already exists. Deleting and creating new one.")
        subprocess.run(f'sudo rm -rf {output_file}',shell=True)
    command = [
    'sudo', 'timeout', str(capture_duration),
    'tcpdump', '-i', interface,'port','8123', '-w', output_file
    ]
    process = subprocess.Popen(command)
    info(f"[+] Capturing TCP packets on {interface} for {capture_duration} seconds...\n")
    return process

def verify_pcap_file(pcap_file):
    """Check if PCAP file is valid and contains enough packets."""
    if not os.path.exists(pcap_file) or os.path.getsize(pcap_file) == 0:
        info(f"[X] Error: {pcap_file} is missing or empty.\n")
        return False

    # Check the number of packets
    command = ['tshark', '-r', pcap_file, '-T', 'fields', '-e', 'frame.number']
    result = subprocess.run(command, capture_output=True, text=True)
    packet_count = len(result.stdout.splitlines())

    if packet_count < 50:  # Adjust this threshold based on your needs
        info(f"[X] Warning: PCAP file contains only {packet_count} packets. Might not be sufficient.\n")
        return False
    
    return True

def extract_features_with_ntlflowlyzer(pcap_file, output_csv, config_file):
    """Convert pcap to csv using NTLFlowLyzer."""
    if not verify_pcap_file(pcap_file):
        return
    
    if os.path.exists(output_csv):
        print(f"File {output_csv} already exists. Deleting and creating new one.")
        subprocess.run(f'sudo rm -rf {output_csv}',shell=True)

    try:
        command = ['ntlflowlyzer', '-c', config_file]
        subprocess.run(command, check=True)
        info(f"\n[+] Features extracted and saved to {output_csv}\n")
    except subprocess.CalledProcessError as e:
        info(f"[X] NTLFlowLyzer failed: {e}\n")

def load_and_process_csv(csv_file):
    """Load features from CSV and normalize them."""
    try:
        df = pd.read_csv(csv_file)
        feature_columns = [
            'bwd_segment_size_mean', 'bwd_total_payload_bytes', 'fwd_total_payload_bytes',
            'fwd_payload_bytes_max', 'bwd_packets_rate', 'idle_mean', 'packets_rate',
            'bwd_init_win_bytes', 'fwd_init_win_bytes', 'fwd_packets_IAT_mean'
        ]
        if df.empty:
            info(f"[X] Error: Extracted feature CSV is empty.\n")
            return None

        data = df[feature_columns]
        normalized_features = scaler.transform(data)
        return normalized_features
    except Exception as e:
        info(f"[X] Error loading CSV: {e}\n")
        return None

def start_intrusion_detection(pcap_file,output_csv,config_file_name):
    """Extract features and run ML model for attack prediction."""
    
    # Extract features with ntlflowlyzer
    extract_features_with_ntlflowlyzer(pcap_file, output_csv,config_file_name)
    
    features = load_and_process_csv(output_csv)
    if features is not None:
        predictions = model.predict(features)
        for i, prediction in enumerate(predictions):
            info(f"Flow {i+1} - Prediction: {prediction}\n")
            prediction_out_file.write(f"Flow {i+1} - Prediction: {prediction}\n")

def dos_attack(net, duration=5):
    """Simulate a DoS attack from h2 to h1, sending 200 TCP packets."""
    h2 = net.get('h2')
    h1 = net.get('h1')
    info(f"\n[!] Starting DoS attack from h2 to h1, sending 200 TCP packets...\n")
    h2.cmd(f'for i in {{1..1000000}}; do echo "Hello from nc!"; sleep 0.005; done | timeout 15 nc {h1.IP()} 8123 &')

def ddos_attack(net, duration=5):
    """Simulate a DDoS attack from multiple hosts to h3, each sending 100 TCP packets."""
    h3 = net.get('h3')
    attackers = ['h4', 'h5', 'h6', 'h7']
    info(f"\n[!] Starting DDoS attack from multiple hosts to h3, each sending 100 TCP packets...\n")
    for attacker in attackers:
        h = net.get(attacker)
        h.cmd(f'for i in {{1..1000000}}; do echo "Hello from nc!"; sleep 0.005; done | timeout 15 nc {h3.IP()} 8123 &')

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
    net.addNAT().configDefault()  
    net.start()
    info("\n*** Network is running. Testing connectivity...\n")
    net.pingAll()
    
    # Update DNS resolver and install hping3 on all hosts
    for host in net.hosts:
        # host.cmd("sed -i 's/nameserver 127\\.0\\.0\\.53/nameserver 8.8.8.8/' /etc/resolv.conf")
        # host.cmd("apt update -y")
        # host.cmd("apt install -y hping3")
        host.cmd("nc -lk -p 8123 &")

    interfaces_to_capture = find_valid_interfaces()

    all_tcpdump_processs = []
    for interface in interfaces_to_capture:
        tcpdump_process = start_tcpdump_capture(interface=interface, output_file=f'/tmp/capture_{interface}.pcap', capture_duration=10)
        all_tcpdump_processs.append(tcpdump_process)

    time.sleep(1)
    
    dos_attack(net,duration=5)
    ddos_attack(net,duration=5)

    for tcpdump_process in all_tcpdump_processs:
        tcpdump_process.wait()

    info("\n*** tcpdump capture has stopped. Starting intrusion detection...\n")


    info("\n[+] Waiting 15 seconds before converting PCAP to CSV...\n")
    time.sleep(15)

    for interface in interfaces_to_capture:
        config_file_name = make_config_file(interface)
        start_intrusion_detection(pcap_file=f'/tmp/capture_{interface}.pcap',
        output_csv=f'/tmp/output_{interface}.csv', config_file_name=config_file_name)
    
    prediction_out_file.close()
    # CLI(net)
    net.stop()

