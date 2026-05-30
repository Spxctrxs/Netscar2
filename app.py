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


def add_history(event, ip="", details=""):
    history.append({
        "timestamp": datetime.now().isoformat(),
        "event": event,
        "ip": ip,
        "details": details
    })
    save_history()

load_history()

# ==================== BANDWIDTH SNIFFER ====================
def packet_callback(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        length = len(packet)
        bandwidth_usage[src] += length
        bandwidth_usage[dst] += length

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

def get_vendor_from_mac(mac):
    if mac == "Unknown" or not mac:
        return "Unknown"
    try:
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
        if r.status_code == 200:
            return r.text.strip()[:45]
    except:
        pass
    return "Unknown Vendor"

def get_device_type(vendor):
    if not vendor or vendor == "Unknown":
        return "Unknown Device"
    v = vendor.lower()
    if any(x in v for x in ['apple','iphone','macbook','ipad']): return "Apple Device"
    if any(x in v for x in ['samsung','huawei','xiaomi','oppo']): return "Android Device"
    if any(x in v for x in ['tp-link','tplink','netgear','asus','linksys','cisco','d-link','dlink','zyxel','tenda','belkin','trendnet','ubiquiti','ubiquiti networks','mikrotik','aruba','netis']): return "Router / AP"
    if any(x in v for x in ['intel','dell','hp','lenovo']): return "Computer"
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
        for host in nm.all_hosts():
            if nm[host].state() != 'up': continue
            mac = nm[host]['addresses'].get('mac', 'Unknown')
            vendor = get_vendor_from_mac(mac)
            device_type = get_device_type(vendor)
            is_new = mac != "Unknown" and mac not in known_macs

            if is_new and mac != "Unknown":
                known_macs.add(mac)
                history.append({
                    "timestamp": datetime.now().isoformat(),
                    "event": "new_device",
                    "ip": host,
                    "vendor": vendor
                })
                save_history()

            new_devices.append({
                "ip": host,
                "mac": mac,
                "vendor": vendor,
                "type": device_type,
                "status": "online",
                "is_new": is_new,
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