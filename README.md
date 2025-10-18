# 🛡️ WeDDOS Guard v1.7 — Adaptive Defense Against Real-World DDoS Threats

**Author:** WeThink
**Version:** v1.7  
**Tagline:** **WeDDOS Guard — Adaptive Defense Against Real-World DDoS Threats.**  
**Language:** Python 3  
**License:** MIT

> Lightweight, adaptive Layer-4 flood protection for VPS and dedicated servers — automated mitigation, ipset blacklisting, and Discord alerts.

---

# Table of Contents
1. [Overview](#overview)  
2. [Features](#features)  
3. [Prerequisites](#prerequisites)  
4. [Installation](#installation)  
5. [Configuration](#configuration)  
6. [Run & Host (manual)](#run--host-manual)  
7. [Run & Host (systemd service)](#run--host-systemd-service)  
8. [Optional: Docker (advanced)](#optional-docker-advanced)  
9. [How it works (high level)](#how-it-works-high-level)  
10. [Tuning & Hardening Tips](#tuning--hardening-tips)  
11. [Troubleshooting & FAQs](#troubleshooting--faqs)  
12. [Notes & Warnings](#notes--warnings)  
13. [License & Credits](#license--credits)

---

# Overview
**WeDDOS Guard v1.7** is a production-focused Python script that hardens kernel TCP/IP parameters, creates iptables/ipset mitigations, watches live connections (via `ss`/`netstat`) and dynamically blocks abusive IPs. It targets TCP/UDP/ICMP floods, SYN/ACK/RST/FIN abuses, port scanning, spoofing and performs escalation/relaxation automatically.

---

# Features
- Kernel hardening (`sysctl`) for anti-spoofing & strict TCP state  
- iptables rules for malformed packets, TCP-flag abuse, FIN/RST limits  
- Per-port protections (connlimit, hashlimit, syn limits)  
- ipset timed blacklisting for repeat offenders  
- Adaptive global throttling when new-connection flood detected  
- Port-scan detection and automated blocking  
- Discord webhook notifications on blocks/escalation/relaxation  
- Lightweight — uses `ss` or `netstat` only; no heavy dependencies

---

# Prerequisites
- Root access on a Linux VPS or dedicated server. (You **must** run as root.)  
- Python 3.6+ installed.  
- `iptables`, `ipset`, `ss` / `iproute2` (or `net-tools` for `netstat`).  
- `pip` and the `requests` package if you want Discord alerts (`pip3 install requests`).

Install required packages (Debian/Ubuntu example):

```bash
sudo apt update
sudo apt install -y python3 python3-pip iptables ipset iproute2
pip3 install requests
```

CentOS/RHEL example:

```bash
sudo yum install -y python3 python3-pip iptables ipset iproute
pip3 install requests
```

---

# Installation

1. Place the script on the server (example filename `weddos_guard.py`):

```bash
sudo mkdir -p /opt/weddos
sudo chown $USER:$USER /opt/weddos
# on your workstation:
scp weddos_guard.py root@your-server:/opt/weddos/
```

2. Make it executable:

```bash
sudo chmod +x /opt/weddos/weddos_guard.py
```

3. Install Python dependency:

```bash
sudo pip3 install requests
```

---

# Configuration

Open the script `/opt/weddos/weddos_guard.py` and edit the top configuration block:

```python
DISCORD_WEBHOOK = ""               # <-- Add your Discord webhook URL if you want alerts
CHECK_INTERVAL = 5                 # seconds between monitoring loops
CONN_THRESHOLD = 500               # simultaneous connections threshold per IP
REPEAT_HITCOUNT = 2                # hits before ipset blocking
BLOCK_TIME = 600                   # ipset block timeout (seconds)
IPSET_NAME = "weddos_block"
CHAIN_NAME = "WEDDOS-PORT"
WHITELIST_PORTS = {22, 53, 80, 443} # add essential service ports (SSH, DNS, HTTP, HTTPS)
MAX_CONN_PER_IP = 60               # per-port simultaneous conn limit per IP
HASHLIMIT_RATE = "20/min"          # per-IP new connection rate
...
```

Important:
- Make sure `WHITELIST_PORTS` includes **SSH (22)** unless you have another SSH access method, or you'll risk locking yourself out.
- If you run services on unusual ports, add those ports to `WHITELIST_PORTS`.
- `DISCORD_WEBHOOK` is optional but useful for live alerts.

> Tip: Back up the script after editing: `cp weddos_guard.py weddos_guard.py.bak`

---

# Run & Host (manual)
To run the script interactively:

```bash
sudo python3 /opt/weddos/weddos_guard.py
```

or:

```bash
sudo /opt/weddos/weddos_guard.py
```

The script will:
1. Apply `sysctl` hardening.
2. Create and link ipsets and the custom iptables chain.
3. Apply global rules and per-port protections.
4. Enter a continuous loop monitoring connections and applying mitigation.

To stop: press `Ctrl+C` (SIGINT). Rules remain in iptables/ipset for inspection. To flush everything (careful):

```bash
# Flush iptables chain (example)
sudo iptables -D INPUT -j WEDDOS-PORT 2>/dev/null || true
sudo iptables -F WEDDOS-PORT 2>/dev/null || true
sudo iptables -X WEDDOS-PORT 2>/dev/null || true

# Clear ipsets
sudo ipset flush weddos_block
sudo ipset destroy weddos_block
```

---

# Run & Host (systemd service)

To run WeDDOS Guard automatically and reliably across reboots, create a systemd service.

1. Create the service file `/etc/systemd/system/weddos.service`:

```ini
[Unit]
Description=WeDDOS Guard v1.7 - Adaptive DDoS Mitigation
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/weddos/weddos_guard.py
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

2. Reload systemd and enable:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now weddos.service
```

3. Check status & logs:

```bash
sudo systemctl status weddos.service
sudo journalctl -u weddos.service -f
```

If you edit the script, `systemctl restart weddos.service`.

---

# Optional: Docker (advanced)

> NOTE: Docker is **not recommended** for direct packet mangling (`iptables`, `ipset`) because containers add networking complexity. Use systemd method on host. If you still want to isolate the process, run it on the host network namespace (privileged) — advanced and beyond basic guide.

Example Dockerfile (not full solution):

```dockerfile
FROM python:3.10-slim
RUN pip install requests
COPY weddos_guard.py /app/weddos_guard.py
ENTRYPOINT ["python3","/app/weddos_guard.py"]
```

Run with privileged networking (risky):

```bash
sudo docker build -t weddos .
sudo docker run --rm --privileged --net=host -v /lib/modules:/lib/modules weddos
```

Again: prefer running on host as systemd service.

---

# How it works (high level)

1. **Kernel tweaks**: Enables SYN cookies, strict conntrack, rp_filter (anti-spoof).  
2. **iptables chain** (`WEDDOS-PORT`): All non-established packets pass through it — global filters catch invalid, malformed or suspicious TCP flags, fragments, smurf/broadcasts and ICMP rate-limit.  
3. **Per-port rules**: Connlimit, hashlimit and SYN limits applied per listening port (except whitelisted ports).  
4. **Detection**: `ss`/`netstat` parsing finds IPs with excessive simultaneous connections. Repeated offenders are added to an `ipset` block (timed).  
5. **Escalation**: If system-wide new connections exceed threshold, an aggressive global throttle is inserted; it auto-relaxes when the flood subsides.  
6. **Notifications**: Discord webhook posts on blocks, escalations and relaxations.

---

# Tuning & Hardening Tips

- **Whitelist SSH (22)** or use jump/bastion host. If you lock out SSH, console access (VPS provider) may be required.  
- **Lower CONN_THRESHOLD and MAX_CONN_PER_IP** for small VPS. Example for 2–4 vCPU: `CONN_THRESHOLD = 200`, `MAX_CONN_PER_IP = 20`.  
- **Adjust CHECK_INTERVAL**: shorter interval makes mitigation faster but increases CPU. 3–10 seconds reasonable.  
- **Increase nf_conntrack_max** if your server handles many connections (in `/etc/sysctl.conf` or in the script tweaks).  
- **Monitoring**: integrate with Prometheus, Grafana or external log shipper if desired. The script currently logs to stdout; `systemd` captures it in journal.  
- **Persistent ipset on reboot**: Use `ipset save` / `ipset restore` or restore rules on boot via systemd unit with pre-start script (advanced).

---

# Troubleshooting & FAQs

Q — *I started it and got locked out of SSH.*  
A — Immediately use VPS provider console/serial access. Before running, ensure `WHITELIST_PORTS` includes SSH port, or restrict the script to test on non-production environment.

Q — *How do I see what IPs are blocked?*  
A —
```bash
sudo ipset list weddos_block
```

Q — *How to remove a single blocked IP?*  
A —
```bash
sudo ipset del weddos_block 1.2.3.4
```

Q — *Rules not present after restart?*  
A — If running as script manually, rules persist only while ipset/iptables entries exist; ensure you use the systemd service or a start-up script. If kernel modules for `ipset` or `xt_conntrack` are missing, install required kernel modules or package `iptables` extensions.

Q — *Discord notifications not sent?*  
A — Set `DISCORD_WEBHOOK` and verify `requests` is installed. Test by running simple `curl`/`requests` POST to your webhook.

Q — *I want to tune per-service rates (example Minecraft).*  
A — Add specific port to `WHITELIST_PORTS` if you want to avoid automated per-port limits. Or adjust `HASHLIMIT_RATE`, `SYN_RATE`, and `MAX_CONN_PER_IP` accordingly.

---

# Notes & Warnings

- **Root required**: This script runs privileged networking commands and **must** be run as `root`.  
- **Test first**: Try in a staging environment or during maintenance window. Mistuned rules can disrupt legitimate traffic.  
- **Compatibility**: Written against `iptables` legacy toolchain. If your environment uses `nftables` only, adapt logic to nft or install `iptables-legacy`.  
- **Not a replacement for upstream mitigation**: For large volumetric attacks (Gbit/s), use provider/anti-DDoS (Cloud provider, Cloudflare Spectrum, dedicated scrubbing centers). This script is best for low-to-medium attacks and behavior-based mitigation.  
- **Do not run multiple automated firewall scripts simultaneously** — they may conflict.

---

# Example Commands (quick reference)

```bash
# Start manually
sudo python3 /opt/weddos/weddos_guard.py

# Start via systemd
sudo systemctl enable --now weddos.service
sudo systemctl status weddos.service
sudo journalctl -u weddos.service -f

# List ipset blocks
sudo ipset list weddos_block

# Remove ipset block (single IP)
sudo ipset del weddos_block 1.2.3.4

# View WEDDOS chain rules
sudo iptables -S WEDDOS-PORT

# Flush and remove WEDDOS chain (careful):
sudo iptables -D INPUT -j WEDDOS-PORT 2>/dev/null || true
sudo iptables -F WEDDOS-PORT
sudo iptables -X WEDDOS-PORT
sudo ipset flush weddos_block
sudo ipset destroy weddos_block
```

---

# Contributing
- Improvements, PRs and issue reports are welcome. Please:
  - Keep `sysctl` changes explicit and documented.
  - Add tests for `ss/netstat` parsing using sample outputs.
  - Provide optional config-file support or environment-variable driven config (future enhancement).

---

# License & Credits
**MIT License** — see `LICENSE` file.  
Developed by **WeThink**.

---

If you want, I can:
- add a ready-to-use `weddos.service` file in the repo,  
- create a `/etc/weddos/weddos.conf` external configuration loader (so you don't edit the script directly), or  
- generate a minimal `Dockerfile` + README notes for the container approach.

Which of those would you like next?
