NetScar v0.1.1

**A Real-ish-Time Local Network Scanner**

NetScar is a network monitoring tool that scans your local WiFi network, detects connected devices, identifies device types, and alerts you when new devices join the network.

## Features

- **Real Network Scanning** — Detects all devices on your local network (IP + MAC + Vendor)
- **New Device Detection** — Automatically highlights and alerts when unknown devices connect
- **Smart Device Identification** — Recognizes Apple, Android, Routers, PCs, etc. (Not on all networks BTW)
- **Internet Speed Test** — Download, Upload & Ping with real measurements (Will fix the ping issue one day)
- **Live Ping** — Test connectivity to any device
- **Auto Refresh** — Dashboard updates every few seconds (7 seconds to be exact)
- **Production Server** — Runs with Waitress (stable & fast(Hopefully))
- **Suspecious Device Scanners Detection** — Detects unauthorised network scanners on the wifi and automatically disconnects from network if network is compromised

## How to Install & Run

Open your browser and go to:
http://localhost:5000

### 1. Install Requirements

```powershell
cd netscar
pip install flask python-nmap waitress
```
### 2. Run NetScar
```
PowerShellpython app.py
```
Open your browser and go to:
```
http://localhost:5000
```
Keyboard Shortcuts

S → Start Network Scan

Project Structure
```
netscar/
├── app.py                 # Main backend
├── static/
│   └── index.html         # Frontend Dashboard
└── requirements.txt
README.md
```
Technologies Used

Backend: Flask + Python-nmap + Waitress
Frontend: HTML, CSS, JavaScript
Scanning: Nmap

To install this, Run the command below
```
pip install -r requirements.txt
```

Important Notes

You need Nmap installed on your system for device scanning.
Run the program with administrator privileges for best results (recommended on Windows or Kali).
This tool is for educational and personal network monitoring only.


Made by Spectres
