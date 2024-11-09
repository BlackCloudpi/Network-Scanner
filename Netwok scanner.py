import socket
import threading
from scapy.all import *
from queue import Queue
import argparse
from time import time

# Parsing command-line arguments
parser = argparse.ArgumentParser(
    description="Advanced Network Scanner with Aggressive Mode, Ping Detection, and Verbose Output",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter
)

# Arguments for network scanning features
parser.add_argument(
    "-t", "--target", type=str, required=True,
    help="Target IP address or subnet (e.g., 192.168.1.1 or 192.168.1.0/24)"
)
parser.add_argument(
    "-p", "--ports", type=str, default="1-1024",
    help="Port range to scan (e.g., 1-1024). Specify as 'start-end'"
)
parser.add_argument(
    "-th", "--threads", type=int, default=100,
    help="Number of threads to use for scanning. Higher threads increase speed but require more system resources."
)
parser.add_argument(
    "-A", "--aggressive", action="store_true",
    help="Enable aggressive scanning mode. Includes service and version detection on open ports, as well as OS detection."
)
parser.add_argument(
    "-T", "--timeout", type=float, default=0.3,
    help="Timeout between requests for aggressive mode. Lower values make scanning faster but may reduce reliability."
)
parser.add_argument(
    "-v", "--verbose", action="store_true",
    help="Enable verbose mode for detailed output, providing real-time information on each scanning action."
)
parser.add_argument(
    "--ping", action="store_true",
    help="Enable ping detection to check if each host is online before scanning. Skips hosts that do not respond to ping."
)

args = parser.parse_args()

# Target and ports to scan
target = args.target
port_range = args.ports.split('-')
start_port = int(port_range[0])
end_port = int(port_range[1])
threads = args.threads
aggressive_mode = args.aggressive
timeout = args.timeout
verbose = args.verbose
enable_ping = args.ping

# Queue for multithreading
queue = Queue()
open_ports = []

# Ping Detection to check if host is online
def ping_host(ip):
    try:
        pkt = IP(dst=ip)/ICMP()
        resp = sr1(pkt, timeout=1, verbose=0)
        if resp is None:
            if verbose:
                print(f"[INFO] Host {ip} is down or not responding to ping.")
            return False
        else:
            if verbose:
                print(f"[INFO] Host {ip} is up (Ping response received).")
            return True
    except Exception as e:
        if verbose:
            print(f"[ERROR] Error during ping: {e}")
        return False

# Service and Version Detection
def detect_service_version(port, sock):
    try:
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        response = sock.recv(1024).decode().strip()
        return response if response else "Unknown service/version"
    except:
        return "Unknown service/version"

# Function to perform port scanning
def scan_port(port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        
        if result == 0:
            if aggressive_mode:
                service_version = detect_service_version(port, sock)
                open_ports.append((port, service_version))
                if verbose:
                    print(f"[INFO] Port {port} is open - Service/Version: {service_version}")
            else:
                open_ports.append((port, "Unknown service"))
                if verbose:
                    print(f"[INFO] Port {port} is open")
        sock.close()
    except Exception as e:
        if verbose:
            print(f"[ERROR] Error scanning port {port}: {e}")

# Thread worker for faster scanning
def threader():
    while True:
        worker = queue.get()
        scan_port(worker)
        queue.task_done()

# Aggressive OS Detection (SYN Packet Analysis with Scapy)
def os_detection(ip):
    try:
        pkt = IP(dst=ip) / TCP(dport=80, flags="S")
        resp = sr1(pkt, timeout=timeout, verbose=0)

        if resp is None:
            print("No response from target.")
        elif resp.haslayer(TCP):
            tcp_layer = resp.getlayer(TCP)
            ttl = resp.ttl
            window = tcp_layer.window
            
            if ttl <= 64:
                os = "Linux/Unix based OS (probable)"
            elif ttl > 64 and ttl <= 128:
                os = "Windows based OS (probable)"
            elif ttl > 128:
                os = "Cisco Router or unusual setup (probable)"
            else:
                os = "Unknown OS"
            
            print(f"Detected OS: {os} - TTL: {ttl}, Window size: {window}")
        else:
            print("Unable to detect OS.")
    except Exception as e:
        if verbose:
            print(f"[ERROR] Error in OS detection: {e}")

# Network Sweep (Multiple IPs Scanning in a Subnet)
def network_sweep():
    ip_list = []
    try:
        ip_network = IPNetwork(target)
        for ip in ip_network:
            ip_list.append(str(ip))
        return ip_list
    except Exception as e:
        if verbose:
            print(f"[ERROR] Error in network sweep: {e}")
        return [target]

# Execute scan on multiple IPs if subnet is specified
targets = network_sweep()
start_time = time()

for ip in targets:
    target = ip
    if enable_ping and not ping_host(ip):
        if verbose:
            print(f"[INFO] Skipping further scan on {ip} as it's down.")
        continue
    
    print(f"\nStarting scan on target: {target}")
    
    # Running multiple threads for efficiency
    for _ in range(threads):
        t = threading.Thread(target=threader)
        t.daemon = True
        t.start()
    
    # Adding jobs to the queue
    for port in range(start_port, end_port + 1):
        queue.put(port)

    queue.join()

    if aggressive_mode:
        print(f"\nAttempting OS Detection on {target}...")
        os_detection(target)

print("\nScanning completed in:", round(time() - start_time, 2), "seconds")
print("\nOpen ports:", open_ports)
