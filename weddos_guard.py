#!/usr/bin/env python3
"""
WeDDOS Guard v3.3 - Optimized for 100+ concurrent Minecraft players
- Improvements: interface autodetect, reduced subprocess overhead, local blocked-set, batching
- NOTE: test on staging first. Run as root.
"""

import subprocess
import time
import re
import os
import sys
import requests
import signal
from datetime import datetime

# ================= CONFIG - THRESHOLDS & TIMERS ===================
CHECK_INTERVAL = 4                 # seconds between main loop iterations (tuned for lower overhead)
BLOCK_TIME = 600                   # ipset timeout (seconds)
CONN_THRESHOLD = 200               # per-IP simultaneous connections threshold (was 500)
REPEAT_HITCOUNT = 3                # how many loops an IP must appear before block
BATCH_ADD_LIMIT = 10               # max ipset adds per loop to avoid churn

# --- IPSET NAMES ---
IPSET_DYNAMIC_BLOCK = "weddos_block"
IPSET_DATACENTER_BLOCK = "datacenter_block"
IPSET_BAD_LIST_BLOCK = "bad_list_block"
CHAIN_NAME = "WEDDOS-PORT"
RAW_CHAIN_NAME = "WEDDOS-RAW"

# --- STATIC BLOCKLIST SOURCES ---
DATACENTER_IP_LIST_URL = "https://raw.githubusercontent.com/jhassine/server-ip-addresses/master/data/datacenters.txt"
GENERIC_BAD_IP_LIST_URL = "https://lists.blocklist.de/lists/all.txt"

# --- LOG & BRUTE FORCE ---
AUTH_LOG_FILE = "/var/log/auth.log"
BRUTE_FORCE_FAILS = 5
LOG_POS_FILE = "/tmp/.weddos_auth_log_pos"

# --- PORTS & LIMITS ---
WHITELIST_PORTS = {22, 53, 80, 443, 25565}  # include Minecraft default port; adjust if yours differs
MAX_CONN_PER_IP = 30               # per-IP connlimit - lower because single players don't need many connections
HASHLIMIT_RATE = "20/min"
HASHLIMIT_BURST = 10
ICMP_RATE = "10/second"
ICMP_BURST = 20
SYN_RATE = "200/second"
SYN_BURST = 500
UDP_RATE = "2000/second"
UDP_BURST = 1000
GLOBAL_NEW_CONN_WARNING = 1500    # raise if your normal baseline traffic is higher
PORT_SCAN_THRESHOLD = 5
DISCORD_WEBHOOK = ""               # set your webhook to enable

# --- SAFETY MODE ---
LEARN_MODE = False                 # if True: no ipset adds for first 24h; script only observes
LEARN_DURATION = 24 * 60 * 60

# ===========================================
offender_counts = {}
escalated = False
blocked_ips = set()                # local cache of blocked IPs to avoid repeated ipset add
_escalation_start_ts = None
_escalation_blocked_ips = set()
start_time = time.time()

# Precompile regexes for speed
RE_SSH_FAIL = re.compile(r'Failed password for .* from (\d+\.\d+\.\d+\.\d+) port \d+ ssh2')
RE_IP = re.compile(r'(\d+\.\d+\.\d+\.\d+):\d+')

def run(cmd):
    """Execute shell command and return stdout."""
    return subprocess.getoutput(cmd)

def log(msg):
    print(f"[WeDDOS] {time.strftime('%Y-%m-%d %H:%M:%S')} {msg}", flush=True)

def send_discord(content):
    if not DISCORD_WEBHOOK:
        return
    try:
        requests.post(DISCORD_WEBHOOK, json={"content": content}, timeout=5)
    except Exception as e:
        log(f"Discord notify failed: {e}")

def detect_external_interface():
    """Try to detect the external interface name (best-effort)."""
    try:
        out = run("ip route get 1.1.1.1 2>/dev/null || true")
        m = re.search(r'dev (\S+)', out)
        if m:
            return m.group(1)
    except Exception:
        pass
    # fallback list
    for iface in ("eth0", "ens3", "ens5", "enp1s0", "eth1"):
        if os.path.exists(f"/sys/class/net/{iface}"):
            return iface
    return "eth0"

EXTERNAL_IFACE = detect_external_interface()
log(f"Detected external interface: {EXTERNAL_IFACE}")

def iptables_has(rule_fragment, chain="INPUT", table="filter"):
    try:
        out = run(f"iptables -t {table} -S {chain} 2>/dev/null || true")
        return rule_fragment in out
    except Exception:
        return False

def apply_sysctl_hardening():
    tweaks = {
        "net.ipv4.tcp_syncookies": "1",
        "net.netfilter.nf_conntrack_tcp_loose": "0",
    }
    for k, v in tweaks.items():
        run(f"sysctl -w {k}={v}")
    log("Applied sysctl kernel hardening.")

def ensure_ipset():
    run(f"ipset create {IPSET_DYNAMIC_BLOCK} hash:ip timeout {BLOCK_TIME} -exist")
    run(f"ipset create {IPSET_DATACENTER_BLOCK} hash:net family inet -exist")
    run(f"ipset create {IPSET_BAD_LIST_BLOCK} hash:ip family inet -exist")

    # link sets into INPUT
    dc_fragment = f"-m set --match-set {IPSET_DATACENTER_BLOCK} src -j DROP"
    if not iptables_has(dc_fragment, "INPUT", "filter"):
        run(f"iptables -I INPUT 2 -m set --match-set {IPSET_DATACENTER_BLOCK} src -j DROP")

    bad_fragment = f"-m set --match-set {IPSET_BAD_LIST_BLOCK} src -j DROP"
    if not iptables_has(bad_fragment, "INPUT", "filter"):
        run(f"iptables -I INPUT 3 -m set --match-set {IPSET_BAD_LIST_BLOCK} src -j DROP")

    dyn_fragment = f"-m set --match-set {IPSET_DYNAMIC_BLOCK} src -j DROP"
    if not iptables_has(dyn_fragment, "INPUT", "filter"):
        run(f"iptables -I INPUT 4 -m set --match-set {IPSET_DYNAMIC_BLOCK} src -j DROP")

    log("ipsets ensured and linked.")

def fetch_and_block_ip_lists():
    def fetch_list(url, ipset_name, description):
        if not url:
            log(f"{description} URL empty; skip.")
            return
        try:
            log(f"Fetching {description}...")
            r = requests.get(url, timeout=15)
            r.raise_for_status()
            items = r.text.splitlines()
            cnt = 0
            for item in items:
                s = item.strip()
                if not s or s.startswith('#'):
                    continue
                run(f"ipset add {ipset_name} {s} -exist 2>/dev/null || true")
                cnt += 1
            log(f"Loaded {cnt} entries to {ipset_name}.")
        except Exception as e:
            log(f"Failed to fetch {description}: {e}")

    fetch_list(DATACENTER_IP_LIST_URL, IPSET_DATACENTER_BLOCK, "datacenter IPs")
    fetch_list(GENERIC_BAD_IP_LIST_URL, IPSET_BAD_LIST_BLOCK, "generic bad IPs")

def ensure_chains():
    est_frag = "-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
    if not iptables_has(est_frag, "INPUT", "filter"):
        run(f"iptables -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")

    # create chain if missing
    existing = run("iptables -S | sed -n 's/^-N \\(.*\\)/\\1/p' || true")
    if CHAIN_NAME not in existing:
        run(f"iptables -N {CHAIN_NAME}")
    if f"-j {CHAIN_NAME}" not in run("iptables -S INPUT || true"):
        run(f"iptables -I INPUT 5 -j {CHAIN_NAME}")

    # raw chain
    raw_ch = run("iptables -t raw -S | sed -n 's/^-N \\(.*\\)/\\1/p' || true")
    if RAW_CHAIN_NAME not in raw_ch:
        run(f"iptables -t raw -N {RAW_CHAIN_NAME}")
    if f"-j {RAW_CHAIN_NAME}" not in run("iptables -t raw -S PREROUTING || true"):
        run(f"iptables -t raw -I PREROUTING 1 -j {RAW_CHAIN_NAME}")

    log("Chains ready.")

def apply_raw_filters():
    raw_rules = [
        f"-i {EXTERNAL_IFACE} -s 224.0.0.0/4 -j DROP",
        f"-i {EXTERNAL_IFACE} -s 169.254.0.0/16 -j DROP",
        f"-i {EXTERNAL_IFACE} -s 0.0.0.0/8 -j DROP",
        f"-i {EXTERNAL_IFACE} -s 240.0.0.0/5 -j DROP",
        "-p tcp -m conntrack --ctstate INVALID -j DROP",
        "-p tcp -m conntrack --ctstate NEW ! --syn -j DROP",
    ]
    for r in raw_rules:
        if not iptables_has(r, RAW_CHAIN_NAME, "raw"):
            run(f"iptables -t raw -A {RAW_CHAIN_NAME} {r}")
    if not iptables_has("-j RETURN", RAW_CHAIN_NAME, "raw"):
        run(f"iptables -t raw -A {RAW_CHAIN_NAME} -j RETURN")
    log("Applied raw filters.")

def apply_global_filters():
    ttl_frag = "-m ttl --ttl-eq 0 -j DROP"
    if not iptables_has(ttl_frag, CHAIN_NAME, "filter"):
        run(f"iptables -A {CHAIN_NAME} {ttl_frag}")

    base_rules = [
        "-f -j DROP",
        "-p tcp -m conntrack --ctstate NEW -m tcp --tcp-flags ACK ACK -j DROP",
        "-p tcp -m conntrack --ctstate NEW -m tcp ! --tcp-flags FIN,SYN,RST,PSH,ACK SYN -j DROP",
        "-p tcp -m tcp --tcp-flags ALL FIN,PSH,URG -j DROP",
        "-p tcp -m tcp --tcp-flags ALL NONE -j DROP",
        "-p tcp -m tcp --tcp-flags ALL ALL -j DROP",
        "-p tcp -m tcp --tcp-flags FIN FIN -j DROP",
    ]
    for r in base_rules:
        if not iptables_has(r, CHAIN_NAME, "filter"):
            run(f"iptables -A {CHAIN_NAME} {r}")

    syn_fin_frag = "-p tcp -m tcp --tcp-flags SYN,FIN SYN,FIN -m limit --limit 1/s --limit-burst 2 -j ACCEPT"
    if not iptables_has(syn_fin_frag, CHAIN_NAME, "filter"):
        run(f"iptables -A {CHAIN_NAME} {syn_fin_frag}")
        run(f"iptables -A {CHAIN_NAME} -p tcp -m tcp --tcp-flags SYN,FIN SYN,FIN -j DROP")

    syn_rst_frag = "-p tcp -m tcp --tcp-flags SYN,RST SYN,RST -m limit --limit 1/s --limit-burst 2 -j ACCEPT"
    if not iptables_has(syn_rst_frag, CHAIN_NAME, "filter"):
        run(f"iptables -A {CHAIN_NAME} {syn_rst_frag}")
        run(f"iptables -A {CHAIN_NAME} -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j DROP")

    syn_ack_frag = f"-p tcp --tcp-flags SYN,ACK SYN,ACK -m limit --limit {SYN_RATE} --limit-burst {SYN_BURST} -j ACCEPT"
    if not iptables_has(syn_ack_frag, CHAIN_NAME, "filter"):
        run(f"iptables -A {CHAIN_NAME} {syn_ack_frag}")

    port_scan_frag = ("-p tcp -m conntrack --ctstate NEW -m recent --name PORT_SCANNER --set --rsource "
                      f"-m recent --name PORT_SCANNER --update --seconds 60 --hitcount {PORT_SCAN_THRESHOLD} -j SET --add-set {IPSET_DYNAMIC_BLOCK} src --exist")
    if not iptables_has(port_scan_frag, CHAIN_NAME, "filter"):
        run(f"iptables -A {CHAIN_NAME} {port_scan_frag}")

    icmp_frag = f"-p icmp -m limit --limit {ICMP_RATE} --limit-burst {ICMP_BURST} -j ACCEPT"
    if not iptables_has(icmp_frag, CHAIN_NAME, "filter"):
        run(f"iptables -A {CHAIN_NAME} {icmp_frag}")
    icmp_return = "-p icmp -j RETURN"
    if not iptables_has(icmp_return, CHAIN_NAME, "filter"):
        run(f"iptables -A {CHAIN_NAME} {icmp_return}")

    log("Applied global filters.")

def check_log_for_bruteforce():
    if not os.path.exists(AUTH_LOG_FILE):
        return
    pos = 0
    if os.path.exists(LOG_POS_FILE):
        try:
            with open(LOG_POS_FILE, 'r') as f:
                pos = int(f.read().strip() or 0)
        except Exception:
            pos = 0
    try:
        current_size = int(run(f"wc -c < {AUTH_LOG_FILE}").strip())
    except Exception:
        current_size = os.path.getsize(AUTH_LOG_FILE) if os.path.exists(AUTH_LOG_FILE) else 0
    try:
        with open(AUTH_LOG_FILE, 'r') as f:
            f.seek(pos)
            lines = f.readlines()
            failed = {}
            for line in lines:
                m = RE_SSH_FAIL.search(line)
                if m:
                    ip = m.group(1)
                    failed[ip] = failed.get(ip, 0) + 1
            for ip, cnt in failed.items():
                if cnt >= BRUTE_FORCE_FAILS:
                    block_ip(ip, reason=f"SSH brute-force ({cnt} failures)")
        with open(LOG_POS_FILE, 'w') as f:
            f.write(str(current_size))
    except Exception as e:
        log(f"Auth log read error: {e}")

def get_attackers():
    """
    Efficient parsing: run ss once and scan for ip occurrences and SYN states.
    Returns attackers list [(ip, count)], total_new_conn approximation.
    """
    out = run("ss -nt state syn-recv,syn-sent || true")
    ip_counts = {}
    total_new_conn = 0
    for line in out.splitlines():
        # fast check for SYN words
        if 'SYN' in line:
            total_new_conn += 1
        m = RE_IP.search(line)
        if not m:
            continue
        ip = m.group(1)
        ip_counts[ip] = ip_counts.get(ip, 0) + 1
    attackers = [(ip, cnt) for ip, cnt in ip_counts.items() if cnt >= CONN_THRESHOLD]
    # also return top N high-connection IPs if needed
    return attackers, total_new_conn

def ipset_members(ipset_name):
    out = run(f"ipset list {ipset_name} -o save 2>/dev/null || true")
    members = []
    for l in out.splitlines():
        if l.startswith("add "):
            parts = l.split()
            if len(parts) >= 3:
                members.append(parts[2])
    return members

def block_ip_immediate(ip):
    """Actually add IP to ipset (idempotent with -exist)."""
    run(f"ipset add {IPSET_DYNAMIC_BLOCK} {ip} timeout {BLOCK_TIME} -exist 2>/dev/null || true")
    blocked_ips.add(ip)
    _escalation_blocked_ips.add(ip)
    log(f"ipset add {ip} (timeout {BLOCK_TIME}s)")

def block_ip_safe(ip, reason=None):
    """Wrap block with learn-mode and throttling."""
    if LEARN_MODE and (time.time() - start_time) < LEARN_DURATION:
        log(f"[LEARN MODE] Not blocking {ip} ({reason})")
        return
    if ip in blocked_ips:
        return
    block_ip_immediate(ip)
    # optional Discord per-IP notification
    send_discord(f"🚨 WeDDOS Guard: Blocked `{ip}` — reason: {reason or 'threshold'}")

def block_ip(ip):
    """Public wrapper to mark offender counts and block if needed (keeps repeat logic)."""
    block_ip_safe(ip, reason="auto")

def escalate_global(total_new_conn=0):
    global escalated, _escalation_start_ts, _escalation_blocked_ips
    if escalated:
        return
    escalated = True
    _escalation_start_ts = time.time()
    _escalation_blocked_ips = set()
    run(f"iptables -I {CHAIN_NAME} 1 -m conntrack --ctstate NEW -m limit --limit 50/second --limit-burst 100 -j RETURN")
    send_discord(f"🚨 **Attack Started** — observed new-connections ≈ `{total_new_conn}`. Global throttling applied.")
    log("Global escalation inserted.")

def relax_global():
    global escalated, _escalation_start_ts, _escalation_blocked_ips
    if not escalated:
        return
    escalated = False
    # remove escalation rule
    lines = run(f"iptables -S {CHAIN_NAME} || true").splitlines()
    for l in lines:
        if "--limit 50/second" in l and "--ctstate NEW" in l:
            to_del = l.replace(f"-A {CHAIN_NAME} ", "")
            run(f"iptables -D {CHAIN_NAME} {to_del} 2>/dev/null || true")
            break
    # compile summary
    members = ipset_members(IPSET_DYNAMIC_BLOCK)
    combined = sorted(list(_escalation_blocked_ips | set(members)))
    total_blocked = len(combined)
    shown = ", ".join(combined[:100]) if total_blocked else "None"
    duration = int(time.time() - (_escalation_start_ts or time.time()))
    send_discord(f"✅ **Attack Ended / Migrated** — duration: `{duration}`s — blocked IPs (first {min(100, total_blocked)}): `{shown}` — total `{total_blocked}`")
    log("Global escalation removed and summary sent.")
    _escalation_start_ts = None
    _escalation_blocked_ips = set()

def apply_port_protections(port):
    # mangle rule
    mangle_frag = f"-p tcp --dport {port} -m conntrack --ctstate NEW -j TCPMSS --clamp-mss-to-pmtu"
    if not iptables_has(mangle_frag, "PREROUTING", "mangle"):
        run(f"iptables -t mangle -I PREROUTING -p tcp --dport {port} -m conntrack --ctstate NEW -j TCPMSS --clamp-mss-to-pmtu")
    cl = f"-p tcp --dport {port} -m connlimit --connlimit-above {MAX_CONN_PER_IP} --connlimit-mask 32 -j REJECT --reject-with tcp-reset"
    if not iptables_has(cl, CHAIN_NAME, "filter"):
        run(f"iptables -A {CHAIN_NAME} {cl}")
    hl = (f"-p tcp --dport {port} -m conntrack --ctstate NEW -m hashlimit --hashlimit-name hl_new_{port} "
          f"--hashlimit-above {HASHLIMIT_RATE} --hashlimit-burst {HASHLIMIT_BURST} --hashlimit-mode srcip --hashlimit-srcmask 32 -j SET --add-set {IPSET_DYNAMIC_BLOCK} src --exist")
    if not iptables_has(hl, CHAIN_NAME, "filter"):
        run(f"iptables -A {CHAIN_NAME} {hl} 2>/dev/null || true")
    syn = f"-p tcp --dport {port} --syn -m conntrack --ctstate NEW -m limit --limit {SYN_RATE} --limit-burst {SYN_BURST} -j ACCEPT"
    if not iptables_has(syn, CHAIN_NAME, "filter"):
        run(f"iptables -A {CHAIN_NAME} {syn}")
    syn_ret = f"-p tcp --dport {port} --syn -m conntrack --ctstate NEW -j RETURN"
    if not iptables_has(syn_ret, CHAIN_NAME, "filter"):
        run(f"iptables -A {CHAIN_NAME} {syn_ret}")
    udp = f"-p udp --dport {port} -m limit --limit {UDP_RATE} --limit-burst {UDP_BURST} -j ACCEPT"
    if not iptables_has(udp, CHAIN_NAME, "filter"):
        run(f"iptables -A {CHAIN_NAME} {udp}")
    udp_ret = f"-p udp --dport {port} -j RETURN"
    if not iptables_has(udp_ret, CHAIN_NAME, "filter"):
        run(f"iptables -A {CHAIN_NAME} {udp_ret}")
    log(f"Applied protections for port {port}")

def cleanup(signum, frame):
    log("Exiting. Rules left intact.")
    sys.exit(0)

def main():
    if os.geteuid() != 0:
        print("Run as root")
        sys.exit(1)
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    apply_sysctl_hardening()
    ensure_ipset()
    fetch_and_block_ip_lists()
    ensure_chains()
    apply_raw_filters()
    apply_global_filters()
    send_discord("✅ WeDDOS Guard v3.3 started")

    while True:
        try:
            # 1) SSH brute force
            check_log_for_bruteforce()

            # 2) gather listening ports (once) and apply per-port protections
            ports = set()
            ss_out = run("ss -lntuH || true")
            for line in ss_out.splitlines():
                m = re.search(r':(\d+)\b', line)
                if m:
                    port = int(m.group(1))
                    if port not in WHITELIST_PORTS:
                        ports.add(port)
            for p in ports:
                apply_port_protections(p)

            # 3) dynamic monitoring
            attackers, total_new_conn = get_attackers()
            if total_new_conn >= GLOBAL_NEW_CONN_WARNING:
                escalate_global(total_new_conn)
            else:
                relax_global()

            # handle attackers: add only top N this loop to reduce churn
            if attackers:
                # sort descending by count
                attackers_sorted = sorted(attackers, key=lambda x: -x[1])
                to_add = 0
                for ip, cnt in attackers_sorted:
                    offender_counts[ip] = offender_counts.get(ip, 0) + 1
                    if offender_counts[ip] >= REPEAT_HITCOUNT and ip not in blocked_ips:
                        block_ip_safe(ip, reason=f"high conn {cnt}")
                        offender_counts[ip] = 0
                        to_add += 1
                        if to_add >= BATCH_ADD_LIMIT:
                            break

            # decay offender counts
            for ip in list(offender_counts.keys()):
                offender_counts[ip] = max(0, offender_counts[ip] - 1)
                if offender_counts[ip] == 0:
                    del offender_counts[ip]

            time.sleep(CHECK_INTERVAL)

        except Exception as e:
            log(f"Main loop exception: {e}")
            time.sleep(1)

if __name__ == "__main__":
    main()
