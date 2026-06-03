from flask import Flask, jsonify, send_from_directory, request
import nmap
import subprocess
import threading
import os
import requests
import json
from datetime import datetime
from collections import defaultdict

# Scapy
from scapy.all import sniff, IP

app = Flask(__name__, static_folder='static')

devices = []
known_macs = set()
last_scan = None
history = []
bandwidth_usage = defaultdict(int)
packet_log = []
packet_log_lock = threading.Lock()
suspicious_ips = {}  # Track suspicious activity by IP
packet_counts_by_ip = defaultdict(int)  # Track packet frequency
device_overrides = {}

sniffer_thread = None
sniffer_running = False

# ==================== HISTORY ====================
def load_history():
    global history
    try:
        if os.path.exists('history.json'):
            with open('history.json', 'r') as f:
                history = json.load(f)
    except:
        history = []

def save_history():
    try:
        with open('history.json', 'w') as f:
            json.dump(history[-500:], f)
    except:
        pass


def load_overrides():
    global device_overrides
    try:
        if os.path.exists('device_overrides.json'):
            with open('device_overrides.json', 'r') as f:
                device_overrides = json.load(f)
    except:
        device_overrides = {}


def save_overrides():
    try:
        with open('device_overrides.json', 'w') as f:
            json.dump(device_overrides, f)
    except:
        pass


def add_history(event, ip="", details=""):
    history.append({
        "timestamp": datetime.now().isoformat(),
        "event": event,
        "ip": ip,
        "details": details
    })
    save_history()

load_history()
load_overrides()

# ==================== BANDWIDTH SNIFFER ====================
def is_suspicious_vendor(vendor):
    """Check if vendor name indicates a scanning/hacking tool."""
    if not vendor or 'unknown' in vendor.lower():
        return False
    v = vendor.lower()
    suspicious_keywords = ['kali', 'metasploit', 'parrot', 'blackarch', 'sniffing', 'wireshark', 'tcpdump', 'nmap', 'scanning', 'attack', 'penetration']
    return any(keyword in v for keyword in suspicious_keywords)

def detect_nmap_scan_pattern(src_ip, dst_ip, port=None):
    """Detect if this packet pattern looks like nmap activity."""
    # Track rapid sequential connections from same source (typical of nmap)
    if src_ip not in packet_counts_by_ip:
        packet_counts_by_ip[src_ip] = 0
    packet_counts_by_ip[src_ip] += 1
    # If source is making more than 30 packets very quickly, it might be scanning
    if packet_counts_by_ip[src_ip] > 30:
        return True
    return False

def packet_callback(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        length = len(packet)
        bandwidth_usage[src] += length
        bandwidth_usage[dst] += length
        
        # Detect suspicious activity
        if detect_nmap_scan_pattern(src, dst):
            if src not in suspicious_ips:
                suspicious_ips[src] = {"reason": "High packet frequency (potential network scan)", "count": 1}
            else:
                suspicious_ips[src]["count"] += 1
        
        packet_entry = {
            "timestamp": datetime.now().isoformat(),
            "src": src,
            "dst": dst,
            "length": length,
            "summary": packet.summary()
        }
        with packet_log_lock:
            packet_log.append(packet_entry)
            if len(packet_log) > 100:
                packet_log.pop(0)

def start_sniffer():
    global sniffer_thread, sniffer_running
    if sniffer_running:
        return
    sniffer_running = True
    print("[NetScar] Starting Scapy bandwidth sniffer.")
    try:
        sniff(prn=packet_callback, store=False, promisc=True, timeout=None)
    except Exception as e:
        print(f"[Scapy Error]: {e}")
        sniffer_running = False

def stop_sniffer():
    global sniffer_running
    sniffer_running = False
    print("[NetScar] Bandwidth sniffer stopped.")

# ==================== CORE FUNCTIONS ====================
def get_local_subnet():
    try:
        if os.name == 'nt':
            output = subprocess.check_output("ipconfig", shell=True).decode()
            for line in output.splitlines():
                if "IPv4 Address" in line:
                    ip = line.split(":")[1].strip()
                    return ip.rsplit('.', 1)[0] + '.0/24'
    except:
        pass
    return "192.168.1.0/24"

OUI_VENDOR_MAP = {
    '00:1A:2B': 'Apple, Inc.',
    'F4:5C:89': 'Google, Inc.',
    '74:DA:38': 'Amazon Technologies',
    '3C:5A:B4': 'Amazon Technologies',
    'B8:27:EB': 'Raspberry Pi Trading',
    'FC:DB:B3': 'TP-LINK TECHNOLOGIES CO.,LTD.',
    'CC:2D:E0': 'NETGEAR, Inc.',
    'D8:9E:6F': 'Google, Inc.',
    'A4:5E:60': 'Apple, Inc.',
    '00:1B:63': 'Cisco Systems, Inc.',
    '00:1E:C2': 'Belkin International, Inc.',
    '98:5E:0C': 'LG Electronics',
    'F0:D1:A9': 'Samsung Electronics',
    'A8:5E:45': 'Microsoft Corporation',
    '00:1C:BF': 'Dell Inc.',
    '00:23:AE': 'Hewlett Packard',
    '00:50:56': 'VMware, Inc.',
    '00:0C:29': 'VMware, Inc.',
    '08:00:27': 'Oracle VirtualBox',
    '30:83:98': 'Samsung Electronics',
    '44:65:0D': 'Samsung Electronics',
    '34:BE:0B': 'Xiaomi Communications Co Ltd',
    'A0:0B:BA': 'Philips Lighting BV',
    '00:25:9C': 'Intel Corporate',
    '7C:49:EB': 'Huawei Technologies Co., Ltd.',
    '64:16:66': 'Cisco Systems, Inc.',
    '5C:AA:FD': 'Sony Mobile Communications AB',
    '48:5B:39': 'ASUSTek COMPUTER INC.',
}

def normalize_mac(mac):
    if not mac:
        return None
    mac = mac.strip().upper().replace('-', ':')
    if ':' in mac:
        parts = mac.split(':')
        if len(parts) == 6 and all(len(part) == 2 for part in parts):
            return ':'.join(parts)
    cleaned = ''.join(ch for ch in mac if ch.isalnum())
    if len(cleaned) == 12:
        return ':'.join(cleaned[i:i+2] for i in range(0, 12, 2))
    return mac

def get_oui_vendor(mac):
    mac = normalize_mac(mac)
    if not mac or len(mac) < 8:
        return None
    prefix = mac[:8]
    return OUI_VENDOR_MAP.get(prefix)

def get_vendor_from_mac(mac, nmap_vendor=None):
    if nmap_vendor and isinstance(nmap_vendor, str) and nmap_vendor.strip() and 'unknown' not in nmap_vendor.lower():
        return nmap_vendor.strip()[:45]

    normalized_mac = normalize_mac(mac)
    if not normalized_mac or normalized_mac == 'UNKNOWN' or normalized_mac == '00:00:00:00:00:00':
        return "Unknown Vendor"

    local_vendor = get_oui_vendor(normalized_mac)
    if local_vendor:
        return local_vendor

    try:
        r = requests.get(f"https://api.macvendors.com/{normalized_mac}", timeout=2)
        if r.status_code == 200:
            value = r.text.strip()
            if value and 'not found' not in value.lower() and 'unknown' not in value.lower():
                return value[:45]
    except:
        pass

    return "Unknown Vendor"

def get_device_type(vendor):
    if not vendor or 'unknown' in vendor.lower():
        return "Unknown Device"
    v = vendor.lower()
    if any(x in v for x in ['apple', 'iphone', 'macbook', 'ipad', 'airpods', 'imac', 'mac mini']):
        return "Apple Device"
    if any(x in v for x in ['samsung', 'huawei', 'xiaomi', 'oppo', 'oneplus', 'sony', 'google', 'motorola', 'lg', 'htc', 'xiaomi']):
        return "Android / Mobile Device"
    if any(x in v for x in ['tp-link', 'tplink', 'netgear', 'asus', 'linksys', 'cisco', 'd-link', 'dlink', 'zyxel', 'tenda', 'belkin', 'trendnet', 'ubiquiti', 'mikrotik', 'aruba', 'netis', 'comtrend', 'huawei']):
        return "Router / AP"
    if any(x in v for x in ['amazon', 'roku', 'google', 'philips', 'honeywell', 'bosch', 'sonos', 'nest', 'ecobee', 'ring', 'smart', 'home', 'xiaomi', 'simba', 'hikvision']):
        return "Smart Home / IoT Device"
    if any(x in v for x in ['intel', 'dell', 'hp', 'hewlett packard', 'lenovo', 'acer', 'asus', 'msi', 'microsoft', 'gigabyte', 'evga']):
        return "Computer"
    if any(x in v for x in ['raspberry', 'raspberry pi', 'arduino', 'adtran', 'espressif', 'broadcom']):
        return "Single-board Computer"
    return "Unknown Device"

def scan_network():
    global devices, last_scan, known_macs
    nm = nmap.PortScanner()
    subnet = get_local_subnet()
    print(f"[NetScar] Scanning {subnet}...")
    add_history("scan_started", details=f"Scanning {subnet}")
    try:
        nm.scan(hosts=subnet, arguments='-sn -T4')
        new_devices = []
        for host_ip in nm.all_hosts():
            host_data = nm[host_ip]
            if host_data.state() != 'up':
                continue

            mac = host_data['addresses'].get('mac', 'Unknown')
            nmap_vendor = None
            if 'vendor' in host_data and isinstance(host_data['vendor'], dict):
                nmap_vendor = next(iter(host_data['vendor'].values()), None)

            vendor = get_vendor_from_mac(mac, nmap_vendor)
            override = device_overrides.get(host_ip, {})
            if override.get('vendor'):
                vendor = override['vendor']
            device_type = override.get('type') or get_device_type(vendor)
            is_new = mac != "Unknown" and mac not in known_macs
            is_suspicious = is_suspicious_vendor(vendor) or host_ip in suspicious_ips
            suspicious_reason = ""
            
            if is_suspicious_vendor(vendor):
                suspicious_reason = "Suspicious vendor detected"
            if host_ip in suspicious_ips:
                suspicious_reason = suspicious_ips[host_ip].get("reason", "Suspicious activity detected")

            if is_new and mac != "Unknown":
                known_macs.add(mac)
                history.append({
                    "timestamp": datetime.now().isoformat(),
                    "event": "new_device",
                    "ip": host_ip,
                    "vendor": vendor
                })
                save_history()
                if is_suspicious:
                    add_history("suspicious_device", host_ip, suspicious_reason)

            new_devices.append({
                "ip": host_ip,
                "mac": mac,
                "vendor": vendor,
                "type": device_type,
                "status": "online",
                "is_new": is_new,
                "is_suspicious": is_suspicious,
                "suspicious_reason": suspicious_reason,
                "last_seen": datetime.now().strftime("%H:%M:%S")
            })

        devices = new_devices
        last_scan = datetime.now()
        add_history("scan_complete", details=f"{len(devices)} devices found")
        print(f"[NetScar] Scan complete → {len(devices)} devices")
    except Exception as e:
        print(f"[Scan Error]: {e}")

# ==================== ROUTES ====================

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/api/devices')
def get_devices():
    return jsonify({
        "devices": devices,
        "last_scan": last_scan.strftime("%H:%M:%S") if last_scan else "Never"
    })

@app.route('/api/device-override', methods=['POST'])
def set_device_override():
    data = request.get_json(force=True, silent=True) or {}
    ip = data.get('ip')
    vendor = data.get('vendor', '').strip()
    device_type = data.get('type', '').strip()

    if not ip or not vendor or not device_type:
        return jsonify({"status": "error", "error": "IP, vendor, and type are required."}), 400

    device_overrides[ip] = {
        "vendor": vendor,
        "type": device_type
    }
    for device in devices:
        if device.get('ip') == ip:
            device['vendor'] = vendor
            device['type'] = device_type
            break
    save_overrides()
    add_history("device_override", ip, f"Vendor={vendor}, Type={device_type}")
    return jsonify({"status": "ok", "override": device_overrides[ip]})

@app.route('/api/history')
def get_history():
    return jsonify({
        "history": history[-100:]
    })

@app.route('/api/bandwidth')
def get_bandwidth():
    top = sorted(bandwidth_usage.items(), key=lambda x: x[1], reverse=True)[:8]
    result = []
    for ip, bytes_count in top:
        mb = round(bytes_count / (1024*1024), 2)
        result.append({"ip": ip, "usage_mb": mb, "usage_str": f"{mb} MB"})
    return jsonify(result)

@app.route('/api/speed-test')
def speed_test():
    result = {
        "ping_ms": None,
        "download_mbps": None,
        "upload_mbps": None,
        "status": "error"
    }

    try:
        start = datetime.now()
        r = requests.get('https://api.ipify.org?format=json', timeout=10)
        if r.ok:
            result["ping_ms"] = int((datetime.now() - start).total_seconds() * 1000)
        else:
            result["ping_ms"] = None
    except Exception:
        result["ping_ms"] = None

    try:
        download_url = 'https://speed.hetzner.de/10MB.bin'
        start = datetime.now()
        r = requests.get(download_url, stream=True, timeout=30)
        total_bytes = 0
        if r.ok:
            for chunk in r.iter_content(chunk_size=32768):
                if chunk:
                    total_bytes += len(chunk)
            duration = (datetime.now() - start).total_seconds()
            if duration > 0:
                result["download_mbps"] = round((total_bytes * 8) / (1024*1024) / duration, 1)
    except Exception:
        result["download_mbps"] = None

    try:
        upload_payload = b'0' * (1024 * 1024)
        start = datetime.now()
        r = requests.post('https://httpbin.org/post', data=upload_payload, timeout=30)
        if r.ok:
            duration = (datetime.now() - start).total_seconds()
            if duration > 0:
                result["upload_mbps"] = round((len(upload_payload) * 8) / (1024*1024) / duration, 1)
    except Exception:
        result["upload_mbps"] = None

    result["status"] = "ok"
    return jsonify(result)

@app.route('/api/packets')
def get_packets():
    with packet_log_lock:
        return jsonify({"packets": list(packet_log[-50:])})

@app.route('/api/scan', methods=['POST'])
def trigger_scan():
    threading.Thread(target=scan_network, daemon=True).start()
    return jsonify({"status": "scanning"})

@app.route('/api/ping/<ip>')
def ping_device(ip):
    """OS Fingerprinting endpoint using nmap"""
    try:
        nm = nmap.PortScanner()
        # Run nmap with OS detection (normal scan)
        nm.scan(hosts=ip, arguments='-O -sV --max-retries=1 -T4')
        
        result = {
            "success": False,
            "ip": ip,
            "os_guesses": [],
            "services": [],
            "status": "unknown"
        }
        
        if ip in nm.all_hosts():
            host = nm[ip]
            result["status"] = host.state()
            
            # Extract OS detection
            if 'osmatch' in host:
                for osmatch in host['osmatch']:
                    result["os_guesses"].append({
                        "name": osmatch['name'],
                        "accuracy": osmatch['accuracy'],
                        "cpe": osmatch.get('cpe', [])
                    })
            
            # Extract services if port scan was successful
            if 'tcp' in host:
                for port in host['tcp'].keys():
                    port_info = host['tcp'][port]
                    result["services"].append({
                        "port": port,
                        "state": port_info['state'],
                        "name": port_info.get('name', 'unknown'),
                        "product": port_info.get('product', ''),
                        "version": port_info.get('version', '')
                    })
            
            result["success"] = True
            add_history("os_fingerprint", ip, f"Detected: {result['os_guesses'][0]['name'] if result['os_guesses'] else 'Unknown'}")
        else:
            add_history("os_fingerprint_failed", ip, "Host unreachable")
        
        return jsonify(result)
    except Exception as e:
        print(f"[Fingerprint Error]: {e}")
        add_history("os_fingerprint_error", ip, str(e))
        return jsonify({
            "success": False,
            "ip": ip,
            "error": str(e),
            "os_guesses": [],
            "services": []
        })

@app.route('/api/sniffer', methods=['POST'])
def control_sniffer():
    global sniffer_thread
    action = request.json.get('action') if request.json else None
    
    if action == 'start':
        if not sniffer_running:
            sniffer_thread = threading.Thread(target=start_sniffer, daemon=True)
            sniffer_thread.start()
            add_history("sniffer_started", details="Packet capture enabled")
        return jsonify({"status": "started"})
    elif action == 'stop':
        stop_sniffer()
        add_history("sniffer_stopped", details="Packet capture disabled")
        return jsonify({"status": "stopped"})
    return jsonify({"status": "error"})

# ==================== STARTING THE DAMN SHI ====================
if __name__ == '__main__':
    print("="*70)
    print("NetScar v0.1.1 Starting...")
    print("Scapy Sniffer Control Enabled")
    print("Run as Administrator for MAC GD")
    print("="*70)
    
    scan_network()
    
    from waitress import serve
    serve(app, host='0.0.0.0', port=5000)