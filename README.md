WeDDOS Guard v3.3
WeDDOS Guard is a Python-based script designed to protect Minecraft servers (optimized for 100+ players) from Distributed Denial of Service (DDoS) attacks. It uses Linux iptables and ipset to monitor and block malicious IPs, brute-force attempts, and suspicious traffic patterns while keeping server performance efficient. The script is lightweight, with features like batch processing, local caching, and automatic attack escalation.
Purpose
Minecraft servers, especially those with many players, are common targets for DDoS attacks, which flood the server with traffic to disrupt gameplay. WeDDOS Guard mitigates these by:

Blocking IPs with excessive connections.
Stopping SSH brute-force attacks.
Filtering out known malicious IPs (e.g., datacenters).
Applying rate limits and protections to key ports.
Escalating defenses during high traffic.

Note: This script is tuned for Minecraft but can be adapted for other services. Always test in a staging environment before production use, as misconfiguration may block legitimate users.
Features

Dynamic Blocking: Monitors SYN (new) connections using ss and blocks IPs exceeding connection limits after repeated offenses.
Static Blocklists: Loads lists of known bad IPs (e.g., datacenters) from online sources for proactive blocking.
SSH Brute-Force Protection: Scans /var/log/auth.log for failed SSH login attempts and blocks IPs after too many failures.
Port-Specific Rules: Applies connection limits, rate limits, and hashlimits to protect ports like 22 (SSH), 80/443 (web), and 25565 (Minecraft).
Global Escalation: During detected attacks (high new connections), it throttles new connections and relaxes when safe.
Port Scan Detection: Blocks IPs attempting to scan multiple ports.
Raw Filters: Drops invalid packets, bad TCP flags, and reserved IP ranges early in the network stack.
Kernel Hardening: Enables SYN cookies and strict connection tracking.
Discord Notifications: Sends alerts for blocked IPs and attack events (optional).
Learn Mode: Observes traffic without blocking for the first 24 hours to help tune thresholds.
Efficiency: Uses batch IP blocking, local cache, and optimized checks to reduce CPU usage.

Requirements

Operating System: Linux with iptables, ipset, and ss (from iproute2).
Python: Version 3.6 or higher.
Python Library: requests for fetching blocklists and sending Discord alerts (pip install requests).
Privileges: Must run as root to modify firewall rules and access logs.
Log Access: /var/log/auth.log for brute-force detection (adjust if your system uses a different log).
Network: Internet for initial blocklist fetch; optional for Discord.

Installation
Follow these steps to set up WeDDOS Guard:

Download the Script:Save the provided script as weddos_guard.py in a directory of your choice (e.g., /opt/weddos/).

Install Dependencies:On Debian/Ubuntu:
sudo apt update
sudo apt install iptables ipset iproute2 python3 python3-requests

For CentOS/RHEL:
sudo yum install iptables ipset iproute python3 python3-requests

Verify iptables, ipset, and ss are installed:
iptables -V
ipset -V
ss --version


Configure the Script:Open weddos_guard.py in a text editor and adjust the CONFIG section:

CHECK_INTERVAL (default: 4 seconds): How often the script checks traffic. Increase for lower CPU usage.
BLOCK_TIME (default: 600 seconds): How long blocked IPs stay blocked.
CONN_THRESHOLD (default: 200): Max simultaneous connections per IP before flagging as suspicious.
REPEAT_HITCOUNT (default: 3): Number of checks an IP must exceed CONN_THRESHOLD before blocking.
BATCH_ADD_LIMIT (default: 10): Max IPs blocked per cycle to avoid overwhelming the system.
WHITELIST_PORTS (default: {22, 53, 80, 443, 25565}): Ports to protect. Add/remove based on your server’s needs (e.g., custom Minecraft port).
MAX_CONN_PER_IP (default: 30): Limits connections per IP per port.
HASHLIMIT_RATE (default: 20/min), HASHLIMIT_BURST (default: 10): Rate limits for new connections per port.
ICMP_RATE (default: 10/s), ICMP_BURST (default: 20): Limits for ICMP (ping) traffic.
SYN_RATE (default: 200/s), SYN_BURST (default: 500): Limits for TCP SYN packets.
UDP_RATE (default: 2000/s), UDP_BURST (default: 1000): Limits for UDP packets (common in Minecraft).
GLOBAL_NEW_CONN_WARNING (default: 1500): Triggers escalation if new connections exceed this.
PORT_SCAN_THRESHOLD (default: 5): Blocks IPs after this many port scan attempts.
DISCORD_WEBHOOK (default: ""): Set to your Discord webhook URL for alerts (leave empty to disable).
LEARN_MODE (default: False): Set to True to observe traffic without blocking for LEARN_DURATION (default: 24 hours).
DATACENTER_IP_LIST_URL, GENERIC_BAD_IP_LIST_URL: URLs for blocklists. Defaults fetch datacenter and known bad IPs.


Make Executable:
chmod +x /path/to/weddos_guard.py



Usage
Run the script as root:
sudo /path/to/weddos_guard.py


What It Does:
Detects the external network interface (e.g., eth0).
Loads blocklists and sets up iptables/ipset.
Applies kernel hardening (e.g., SYN cookies).
Monitors traffic every CHECK_INTERVAL seconds.
Logs actions to the terminal (e.g., blocked IPs, attack start/end).


Stop the Script: Press Ctrl+C. Firewall rules remain active for safety.
Log to File: Redirect output:sudo /path/to/weddos_guard.py > /var/log/weddos.log 2>&1



Running as a System Service
To run automatically on boot:

Create a systemd service file at /etc/systemd/system/weddos-guard.service:[Unit]
Description=WeDDOS Guard DDoS Protection
After=network.target

[Service]
ExecStart=/path/to/weddos_guard.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target


Enable and start:sudo systemctl daemon-reload
sudo systemctl start weddos-guard
sudo systemctl enable weddos-guard


Check status:sudo systemctl status weddos-guard



How It Works

Initialization:

Applies kernel tweaks (e.g., enables SYN cookies).
Creates three ipset sets: weddos_block (dynamic blocks), datacenter_block (datacenter IPs), bad_list_block (known bad IPs).
Fetches and loads blocklists from configured URLs.
Sets up iptables chains (WEDDOS-PORT, WEDDOS-RAW) for filtering.
Adds raw filters to drop invalid packets (e.g., bad TCP flags, reserved IPs).
Adds global filters for fragments, ICMP, and port scans.


Monitoring Loop:

Checks /var/log/auth.log for SSH brute-force attempts (blocks after BRUTE_FORCE_FAILS).
Scans listening ports with ss and applies protections (connection limits, rate limits) to non-whitelisted ports.
Counts SYN connections to detect high-connection IPs.
Blocks IPs after REPEAT_HITCOUNT violations of CONN_THRESHOLD (batched to BATCH_ADD_LIMIT).
Escalates during high traffic (GLOBAL_NEW_CONN_WARNING), limiting new connections to 50/s.
Relaxes when traffic drops, sending a summary of blocked IPs via Discord.


Blocking Mechanism:

Uses ipset for efficient, temporary blocks (timeout: BLOCK_TIME).
Maintains a local cache to avoid duplicate blocks.
Skips blocking in learn mode for initial tuning.



Troubleshooting

No IPs Blocked: Check if LEARN_MODE is True or if CONN_THRESHOLD/REPEAT_HITCOUNT is too high.
High CPU Usage: Increase CHECK_INTERVAL or lower BATCH_ADD_LIMIT.
Wrong Interface: Set EXTERNAL_IFACE manually in the script.
Discord Not Working: Verify webhook URL and internet access.
Firewall Errors: Ensure iptables/ipset modules are loaded:sudo modprobe ip_set xt_set


Remove Rules: To clear all WeDDOS rules and sets:sudo iptables -D INPUT -j WEDDOS-PORT
sudo iptables -F WEDDOS-PORT
sudo iptables -X WEDDOS-PORT
sudo iptables -t raw -D PREROUTING -j WEDDOS-RAW
sudo iptables -t raw -F WEDDOS-RAW
sudo iptables -t raw -X WEDDOS-RAW
sudo ipset destroy weddos_block
sudo ipset destroy datacenter_block
sudo ipset destroy bad_list_block



Important Notes

Test Thoroughly: Misconfigured thresholds can block legitimate players. Use learn mode to observe traffic first.
Minecraft Tuning: Optimized for port 25565 and high-player servers. Adjust for other ports/services.
No Persistence: Blocklists and rules reset on reboot unless scripted.
Legal: Ensure blocklists comply with local laws.
Logs: Check /var/log/weddos.log (if redirected) or terminal for blocked IPs and errors.
License: MIT License—free to use and modify.
