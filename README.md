# WeDDOS Guard v3.3

A lightweight, Python-based DDoS protection script optimized for Minecraft servers handling 100+ concurrent players. It uses iptables, ipset, and connection monitoring to detect and block suspicious IPs, brute-force attempts, and common attack patterns. The script focuses on low overhead, batch processing, and automatic escalation during high traffic.

**Key Improvements in v3.3:**
- Automatic external interface detection.
- Reduced subprocess overhead for better performance.
- Local blocked IP cache to avoid redundant operations.
- Batching of IP blocks to prevent churn.
- Learn mode for initial observation without blocking.
- Discord webhook notifications for alerts.

**NOTE:** This script is intended for Linux systems with iptables and ipset. Always test on a staging environment before production. Run as root.

## Features

- **Dynamic IP Blocking:** Monitors SYN connections via `ss` and blocks IPs exceeding connection thresholds after repeated offenses.
- **Static Blocklists:** Fetches and blocks IPs from datacenter ranges and generic bad IP lists.
- **Brute-Force Detection:** Scans `/var/log/auth.log` for SSH failed logins and blocks repeat offenders.
- **Per-Port Protections:** Applies connection limits, hashlimits, and rate limits to whitelisted ports (e.g., 22, 53, 80, 443, 25565 for Minecraft).
- **Global Escalation:** Temporarily throttles new connections during detected attacks and relaxes when traffic normalizes.
- **Raw and Global Filters:** Drops invalid packets, fragments, bogus TCP flags, and more using raw and filter tables.
- **Port Scan Detection:** Blocks IPs attempting port scans.
- **Kernel Hardening:** Applies sysctl tweaks for SYN cookies and strict conntrack.
- **Notifications:** Optional Discord webhook for block events and attack summaries.
- **Learn Mode:** Observes traffic for the first 24 hours without blocking (configurable).

## Requirements

- Python 3.6+ (tested on 3.x).
- Linux with:
  - iptables (including conntrack, limit, hashlimit, recent, set, ttl modules).
  - ipset.
  - ss (from iproute2).
- Root privileges.
- Optional: requests library (for Discord and blocklist fetching; install via `pip install requests`).
- Access to `/var/log/auth.log` for brute-force monitoring.

No internet access is required after initial blocklist fetch, but it's needed for updates.

## Installation

1. **Download the Script:**
   Save the script as `weddos_guard.py` (or similar).

2. **Install Dependencies:**
   ```
   sudo apt update
   sudo apt install iptables ipset iproute2 python3-requests
   ```
   (Adjust for your distro, e.g., yum on CentOS.)

3. **Configure the Script:**
   Edit the script's CONFIG section:
   - `CHECK_INTERVAL`: Loop delay (default: 4 seconds).
   - `BLOCK_TIME`: Block duration (default: 600 seconds).
   - `CONN_THRESHOLD`: Per-IP connection limit before flagging (default: 200).
   - `REPEAT_HITCOUNT`: Loops an IP must exceed threshold before blocking (default: 3).
   - `BATCH_ADD_LIMIT`: Max blocks per loop (default: 10).
   - `WHITELIST_PORTS`: Ports to protect (default: {22, 53, 80, 443, 25565}).
   - `MAX_CONN_PER_IP`: Per-IP connlimit (default: 30).
   - `HASHLIMIT_RATE`, `HASHLIMIT_BURST`: New connection rate limits.
   - `ICMP_RATE`, `ICMP_BURST`: ICMP limits.
   - `SYN_RATE`, `SYN_BURST`: SYN packet limits.
   - `UDP_RATE`, `UDP_BURST`: UDP limits.
   - `GLOBAL_NEW_CONN_WARNING`: Trigger escalation if new connections exceed this (default: 1500).
   - `PORT_SCAN_THRESHOLD`: Hits for port scan block (default: 5).
   - `DISCORD_WEBHOOK`: Your Discord webhook URL (leave empty to disable).
   - `LEARN_MODE`: Set to True for observation-only mode (default: False).
   - `LEARN_DURATION`: Learn mode duration (default: 24 hours).
   - Blocklist URLs: Customize `DATACENTER_IP_LIST_URL` and `GENERIC_BAD_IP_LIST_URL`.

4. **Make Executable:**
   ```
   chmod +x weddos_guard.py
   ```

## Usage

Run the script as root:
```
sudo ./weddos_guard.py
```

- It will auto-detect the external interface (e.g., eth0).
- Fetches blocklists on startup.
- Applies iptables rules and ipsets.
- Runs in an infinite loop, monitoring every `CHECK_INTERVAL` seconds.
- Logs to stdout (redirect to a file if needed, e.g., `sudo ./weddos_guard.py > /var/log/weddos.log`).

To stop: Use Ctrl+C or kill the process. Rules remain intact for safety—manually clean up if needed (e.g., `iptables -F WEDDOS-PORT; ipset destroy weddos_block`).

### Running as a Service

Create a systemd unit file `/etc/systemd/system/weddos-guard.service`:
```
[Unit]
Description=WeDDOS Guard
After=network.target

[Service]
ExecStart=/path/to/weddos_guard.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
```

Then:
```
sudo systemctl daemon-reload
sudo systemctl start weddos-guard
sudo systemctl enable weddos-guard
```

## How It Works

1. **Initialization:**
   - Applies sysctl hardening.
   - Creates ipsets for dynamic, datacenter, and bad IP blocks.
   - Fetches and loads static blocklists.
   - Sets up iptables chains (WEDDOS-PORT, WEDDOS-RAW).
   - Applies raw filters (e.g., drop invalid sources, states).
   - Applies global filters (e.g., drop fragments, bogus flags, ICMP limits).

2. **Monitoring Loop:**
   - Checks auth.log for SSH brute-force.
   - Dynamically detects listening ports and applies protections (connlimit, hashlimit, rate limits).
   - Uses `ss` to count SYN connections; flags high-connection IPs.
   - Blocks after repeated thresholds (with batching).
   - Escalates globally if total new connections spike (throttles to 50/s).
   - Relaxes when traffic normalizes and sends attack summary.

3. **Blocking Logic:**
   - Uses ipset with timeouts for efficient blocking.
   - Local cache to avoid duplicates.
   - Learn mode skips blocks for initial period.

## Troubleshooting

- **No Blocks Happening:** Check if in learn mode or thresholds are too high.
- **High CPU:** Increase `CHECK_INTERVAL` or reduce `BATCH_ADD_LIMIT`.
- **Interface Detection Fails:** Hardcode `EXTERNAL_IFACE` in the script.
- **Discord Fails:** Ensure webhook URL is correct and network access.
- **Errors on Startup:** Verify iptables/ipset modules are loaded (`modprobe ip_set xt_set`).
- **Clean Up Rules:** To remove all:
  ```
  iptables -D INPUT -j WEDDOS-PORT
  iptables -F WEDDOS-PORT
  iptables -X WEDDOS-PORT
  iptables -t raw -D PREROUTING -j WEDDOS-RAW
  iptables -t raw -F WEDDOS-RAW
  iptables -t raw -X WEDDOS-RAW
  ipset destroy weddos_block
  ipset destroy datacenter_block
  ipset destroy bad_list_block
  ```

## Warnings

- **Production Use:** Test thoroughly—misconfiguration can block legitimate traffic.
- **Minecraft-Specific:** Tuned for high-player servers; adjust thresholds for other uses.
- **No Persistence:** Blocklists refresh on restart; rules don't survive reboots unless scripted.
- **Legal/Compliance:** Ensure blocklists comply with your jurisdiction.

## License

This script is provided as-is, without warranty. Feel free to modify and use under MIT License. Contributions welcome!
