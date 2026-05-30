// NetScar v0.1.1 - Frontend Script
let devices = [];

// Clock
function updateClock() {
    const clock = document.getElementById('clock');
    if (clock) {
        clock.textContent = new Date().toTimeString().slice(0, 8);
    }
}

// Load devices from backend (If it wants to work)
async function loadDevices() {
    try {
        const response = await fetch('/api/devices');
        if (!response.ok) throw new Error('Failed to fetch');
        
        const data = await response.json();
        
        // Update device count and last scan
        document.getElementById('device-count').textContent = `${data.devices.length} DEVICES`;
        document.getElementById('last-scan').textContent = data.last_scan || "Never";

        // Render table
        const tbody = document.getElementById('device-tbody');
        tbody.innerHTML = '';

        if (data.devices.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="5" style="text-align:center; color:var(--green-dim); padding:20px;">
                        No devices found. Click SCAN NETWORK
                    </td>
                </tr>`;
            return;
        }

        data.devices.forEach(dev => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td><strong>${dev.ip}</strong></td>
                <td style="color:var(--green-dim); font-size:11px;">${dev.mac}</td>
                <td style="color:var(--amber); font-size:11px;">${dev.vendor || 'Unknown'}</td>
                <td><span class="device-status trusted">ONLINE</span></td>
                <td>
                    <button class="action-btn" onclick="pingDevice('${dev.ip}')" style="margin-right:5px;">
                        PING
                    </button>
                </td>
            `;
            tbody.appendChild(row);
        });

    } catch (error) {
        console.error('Error loading devices:', error);
        const tbody = document.getElementById('device-tbody');
        tbody.innerHTML = `
            <tr>
                <td colspan="5" style="text-align:center; color:var(--red); padding:20px;">
                    Cannot connect to NetScar backend
                </td>
            </tr>`;
    }
}

// Start Network Scan
async function startScan() {
    const statusEl = document.getElementById('scan-status');
    statusEl.textContent = "SCANNING NETWORK...";
    statusEl.style.color = "var(--amber)";

    try {
        await fetch('/api/scan', { method: 'POST' });
        
        // Show progress
        setTimeout(() => {
            statusEl.textContent = "PROCESSING RESULTS...";
        }, 1500);

        // Refresh data after scan
        setTimeout(() => {
            loadDevices();
            statusEl.textContent = "SCAN COMPLETE";
            statusEl.style.color = "var(--green)";
        }, 4000);

    } catch (error) {
        console.error(error);
        statusEl.textContent = "SCAN FAILED - Backend not running?";
        statusEl.style.color = "var(--red)";
    }
}

// Ping a specific device
async function pingDevice(ip) {
    try {
        const response = await fetch(`/api/ping/${ip}`);
        const result = await response.json();

        if (result.success) {
            alert(`${ip} is responding\nResponse: ${result.response}`);
        } else {
            alert(`${ip} did not respond`);
        }
    } catch (error) {
        alert(`Ping to ${ip} failed. Is the backend running?`);
    }
}

// Auto-refresh
function startAutoRefresh() {
    loadDevices();
    setInterval(loadDevices, 2000);   // Refresh every 2 seconds
}

// Initialize everything
window.onload = function() {
    updateClock();
    setInterval(updateClock, 1000);
    
    startAutoRefresh();

    // Keyboard shortcut: Press "S" to scan
    document.addEventListener('keydown', (e) => {
        if (e.key.toLowerCase() === 's') {
            startScan();
        }
    });

    console.log("%cNetScar v0.1 initialized successfully", "color:#00ff41; font-family:monospace;");
};