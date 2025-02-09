from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.topo import Topo
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import os
from threading import Thread
import socket
import struct
import time

class CustomTopo(Topo):
    """Defines a simple custom topology with two switches and four hosts."""
    def build(self):
        switch1 = self.addSwitch('s1')
        switch2 = self.addSwitch('s2')

        host1 = self.addHost('h1')
        host2 = self.addHost('h2')
        host3 = self.addHost('h3')
        host4 = self.addHost('h4')

        # Connecting hosts to switches
        self.addLink(switch1, host1)
        self.addLink(switch1, host2)
        self.addLink(switch2, host3)
        self.addLink(switch2, host4)

        # Connecting switches together
        self.addLink(switch1, switch2)

def cleanup_mininet():
    """Ensures Mininet is cleaned up before starting a new instance."""
    info("\n[!] Cleaning up previous Mininet instances...\n")
    os.system('sudo mn -c')

def simulate_dos_attack(net):
    """Simulates a DoS attack using hping3 from h1 to h2."""
    h1 = net.get('h1')
    h2 = net.get('h2')
    info(f"\n[!] Starting DoS attack: h1 flooding h2 ({h2.IP()})...\n")
    h1.cmd(f'hping3 -c 1000 -d 120 -S -w 64 -p 80 --flood {h2.IP()} &')

def log_attack(source_ip, target_ip, attack_type):
    """Logs detected attacks into a file."""
    with open('attack_log.txt', 'a') as f:
        f.write(f"ALERT: {attack_type} attack detected from {source_ip} to {target_ip}\n")

def detect_attack(packet):
    """Detects SYN flood attack by analyzing TCP flags in captured packets."""
    try:
        ip_header = packet[:20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

        tcp_header = packet[20:40]
        tcph = struct.unpack('!HHLLBBHHH', tcp_header)

        flags = tcph[5]
        if flags & 0x02:  # SYN flag
            src_ip = socket.inet_ntoa(iph[8])
            dst_ip = socket.inet_ntoa(iph[9])
            print(f"[!] SYN packet detected from {src_ip} to {dst_ip}")
            log_attack(src_ip, dst_ip, 'DoS')
            return True
    except Exception as e:
        print(f"[X] Error parsing packet: {e}")
    return False

def start_intrusion_detection():
    """Starts an intrusion detection system (IDS) using raw sockets."""
    info("\n[*] Starting intrusion detection...\n")
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    try:
        while True:
            packet = sock.recvfrom(65565)[0]
            detect_attack(packet)
    except KeyboardInterrupt:
        info("\n[*] Stopping intrusion detection...\n")
    finally:
        sock.close()

if __name__ == '__main__':
    setLogLevel('info')

    # Cleanup Mininet before starting
    cleanup_mininet()
    time.sleep(1)  # Ensure cleanup finishes before starting

    # Define network topology
    topo = CustomTopo()

    # Initialize Mininet with RemoteController (POX should be running)
    net = Mininet(
        topo=topo,
        switch=OVSSwitch,
        controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6633)
    )

    # Start the network
    net.start()
    info("\n*** Network is running. Testing connectivity...\n")
    net.pingAll()

    # Start intrusion detection in a separate daemon thread
    intrusion_thread = Thread(target=start_intrusion_detection, daemon=True)
    intrusion_thread.start()

    # Simulate DoS attack
    simulate_dos_attack(net)

    # Open Mininet CLI
    info("\n*** Starting Mininet CLI...\n")
    CLI(net)

    # Stop the network
    info("\n*** Stopping network...\n")
    net.stop()
