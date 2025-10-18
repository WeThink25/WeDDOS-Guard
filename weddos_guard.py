#!/usr/bin/env python3
"""
WeDDOS Guard v1.7 - Ultimate Defense
- Author: WeThink
- ENHANCED: Anti-Spoofing, Anti-Smurf, SYN/ACK, RST/FIN Flood Limits added.
- TCP/UDP/ICMP flood protection
- Per-IP, per-port, global thresholds
- Adaptive escalation/relaxation
- ipset blacklisting and timeouts
"""

import subprocess, time, re, os, sys, requests, signal

# ================= CONFIG ===================
DISCORD_WEBHOOK = ""               # <-- Discord webhook URL
CHECK_INTERVAL = 5                 # seconds
CONN_THRESHOLD = 500               # total simultaneous connections to consider attacker
REPEAT_HITCOUNT = 2                # Hits before an IP is added to the block list
BLOCK_TIME = 600                   # seconds (10 minutes)
IPSET_NAME = "weddos_block"
IPSET_SCANNER_NAME = "weddos_scan" 
CHAIN_NAME = "WEDDOS-PORT"
WHITELIST_PORTS = {22, 53, 80, 443} # CRITICAL: Add any other essential listening ports here!
MAX_CONN_PER_IP = 60               # simultaneous connections per IP to a single port
HASHLIMIT_RATE = "20/min"          # per-IP new connections
HASHLIMIT_BURST = 10
ICMP_RATE = "10/second"
ICMP_BURST = 20
SYN_RATE = "200/second"
SYN_BURST = 500
UDP_RATE = "2000/second"
UDP_BURST = 1000
GLOBAL_NEW_CONN_WARNING = 2000     # Total system-wide NEW connections before escalation
PORT_SCAN_THRESHOLD = 5            # Number of unique ports scanned in 60s
# ===========================================

offender_counts = {}
escalated = False

def run(cmd):
    """Executes a shell command and returns output."""
    return subprocess.getoutput(cmd)

def log(msg):
    """Prints a timestamped log message."""
    print(f"[WeDDOS] {msg}", flush=True)

def send_discord(msg):
    """Sends a notification to the configured Discord webhook."""
    if not DISCORD_WEBHOOK:
        return
    try:
        requests.post(DISCORD_WEBHOOK, json={"content": msg}, timeout=5)
    except Exception as e:
        log(f"Discord notify failed: {e}")

def apply_sysctl_hardening():
    """Applies kernel-level hardening for flood resistance."""
    tweaks = {
        "net.ipv4.tcp_syncookies": "1",
        "net.ipv4.tcp_max_syn_backlog": "8192",
        "net.netfilter.nf_conntrack_max": "524288",
        "net.ipv4.tcp_fin_timeout": "30",
        "net.ipv4.tcp_tw_reuse": "1",
        "net.ipv4.conf.all.accept_source_route": "0",
        "net.ipv4.conf.all.rp_filter": "1", # Reverse Path Filter (Anti-spoofing)
        "net.netfilter.nf_conntrack_tcp_loose": "0", # STRICT TCP STATE TRACKING (Essential for SYN/ACK/RST flood defense)
    }
    for k, v in tweaks.items():
        run(f"sysctl -w {k}={v}")
    log("Applied sysctl kernel hardening (strict TCP state, SYN cookies, RP filter)")

def ensure_established_accept():
    """Ensures ESTABLISHED and RELATED traffic is accepted immediately."""
    check = run("iptables -C INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || echo NO")
    if "NO" in check:
        run("iptables -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
        log("Inserted ESTABLISHED,RELATED accept rule (Pos 1)")

def ensure_ipset():
    """Creates and links ipsets for blocking and port scanning."""
    run(f"ipset create {IPSET_NAME} hash:ip timeout {BLOCK_TIME} -exist")
    run(f"ipset create {IPSET_SCANNER_NAME} hash:ip,port timeout 60 -exist") 
    
    # Block known abusers (IPSET_NAME)
    check_block = run(f"iptables -C INPUT -m set --match-set {IPSET_NAME} src -j DROP 2>/dev/null || echo NO")
    if "NO" in check_block:
        run(f"iptables -I INPUT 2 -m set --match-set {IPSET_NAME} src -j DROP")
        
    log("ipset assured and linked into INPUT (Pos 2)")

def ensure_chain():
    """Creates the custom chain and links it into INPUT."""
    chains_out = run("iptables -S | sed -n 's/^-N \\(.*\\)/\\1/p'")
    if CHAIN_NAME not in chains_out:
        run(f"iptables -N {CHAIN_NAME}")
    input_rules = run("iptables -S INPUT")
    # Insert at position 3, after ESTABLISHED and ipset blocks
    if f"-j {CHAIN_NAME}" not in input_rules:
        run(f"iptables -I INPUT 3 -j {CHAIN_NAME}")
    log(f"Chain {CHAIN_NAME} ready (Linked at Pos 3)")

def iptables_has(rule, chain="INPUT"):
    """Checks if a rule exists in a given chain."""
    cmd = f"iptables -C {chain} {rule} 2>/dev/null || echo NO"
    return "NO" not in run(cmd)

def apply_global_filters():
    """Applies core, non-port-specific filtering rules."""
    
    # --- FRAGMENT, MALFORMED, AND INVALID TRAFFIC ---
    if not iptables_has("-m conntrack --ctstate INVALID -j DROP", CHAIN_NAME):
        run(f"iptables -I {CHAIN_NAME} 1 -m conntrack --ctstate INVALID -j DROP")
    if not iptables_has("-f -j DROP", CHAIN_NAME): # IP fragments rule
        run(f"iptables -A {CHAIN_NAME} -f -j DROP")

    # --- 1. ANTI-SMURF/BROADCAST DEFENSE ---
    smurf_rules = [
        f"! -i lo -d 255.255.255.255 -j DROP",
        f"! -i lo -d 224.0.0.0/4 -j DROP",
    ]
    for r in smurf_rules:
        if not iptables_has(r, CHAIN_NAME):
            run(f"iptables -A {CHAIN_NAME} {r}")

    # --- ENHANCED TCP FLAG ABUSE FILTERS ---
    tcp_flag_rules = [
        # Drop packets with only ACK set and not part of an established connection (ACK flood)
        "-p tcp -m conntrack --ctstate NEW -m tcp --tcp-flags ACK ACK -j DROP",
        # Drop traffic where FIN/RST/ACK are set but SYN is NOT (Non-SYN new connection attempts)
        "-p tcp -m conntrack --ctstate NEW -m tcp ! --tcp-flags FIN,SYN,RST,PSH,ACK SYN -j DROP",
        # Drop FIN/URG/PSH only (stealth scan/probe)
        "-p tcp -m tcp --tcp-flags ALL FIN,PSH,URG -j DROP",
        # Drop XMAS/NULL/FIN-only/SYN+FIN 
        "-p tcp -m tcp --tcp-flags ALL NONE -j DROP",
        "-p tcp -m tcp --tcp-flags ALL ALL -j DROP",
        "-p tcp -m tcp --tcp-flags FIN FIN -j DROP",
        "-p tcp -m tcp --tcp-flags SYN,FIN SYN,FIN -j DROP",
    ]
    for r in tcp_flag_rules:
        if r not in run(f"iptables -S {CHAIN_NAME}"):
            run(f"iptables -A {CHAIN_NAME} {r}")
            
    # --- 2. SYN/ACK AND NON-SYN NEW CONNECTION DEFENSE ---
    # Drop incoming packets trying to start a connection without SYN flag (critical L4 filter)
    non_syn_new = "-p tcp ! --syn -m conntrack --ctstate NEW -j DROP"
    if not iptables_has(non_syn_new, CHAIN_NAME):
        run(f"iptables -A {CHAIN_NAME} {non_syn_new}")

    # Limit SYN+ACK rate (anti-spoofing/reflection defense)
    syn_ack_limit = (f"-p tcp --tcp-flags SYN,ACK SYN,ACK -m limit --limit {SYN_RATE} "
                     f"--limit-burst {SYN_BURST} -j ACCEPT")
    if not iptables_has(syn_ack_limit, CHAIN_NAME):
        run(f"iptables -A {CHAIN_NAME} {syn_ack_limit}")

    # --- 3. FIN/RST FLOOD LIMITS ---
    # Prevents excessive connection resets/teardowns from a single IP
    rst_limit = f"-p tcp --tcp-flags RST RST -m limit --limit 5/s --limit-burst 10 -j ACCEPT"
    if not iptables_has(rst_limit, CHAIN_NAME):
        run(f"iptables -A {CHAIN_NAME} {rst_limit}")
        run(f"iptables -A {CHAIN_NAME} -p tcp --tcp-flags RST RST -j DROP") 

    fin_limit = f"-p tcp --tcp-flags FIN FIN -m limit --limit 5/s --limit-burst 10 -j ACCEPT"
    if not iptables_has(fin_limit, CHAIN_NAME):
        run(f"iptables -A {CHAIN_NAME} {fin_limit}")
        run(f"iptables -A {CHAIN_NAME} -p tcp --tcp-flags FIN FIN -j DROP") 

    # --- ANTI-PORT SCANNING ---
    port_scan_rule = (f"-p tcp -m conntrack --ctstate NEW -m recent --name PORT_SCANNER --set --rsource "
                      f"-m recent --name PORT_SCANNER --update --seconds 60 --hitcount {PORT_SCAN_THRESHOLD} "
                      f"-j SET --add-set {IPSET_NAME} src --exist")
    if not iptables_has(port_scan_rule, CHAIN_NAME):
        run(f"iptables -A {CHAIN_NAME} {port_scan_rule}")
        
    # --- ICMP RATE LIMITING ---
    icmp_allow = f"-p icmp -m limit --limit {ICMP_RATE} --limit-burst {ICMP_BURST} -j ACCEPT"
    if not iptables_has(icmp_allow, CHAIN_NAME):
        run(f"iptables -I {CHAIN_NAME} 1 {icmp_allow}")
    icmp_return = "-p icmp -j RETURN" 
    if not iptables_has(icmp_return, CHAIN_NAME):
        run(f"iptables -I {CHAIN_NAME} 2 {icmp_return}")
        
    log("Applied global filters and strict TCP rules (v1.7).")

def apply_port_protections(port):
    """Applies protections specific to an actively listening port."""
    
    # TCP MSS clamp (Anti-fragmentation/Large packet size attack)
    mangle_rule = f"-t mangle -I PREROUTING -p tcp --dport {port} -m conntrack --ctstate NEW -j TCPMSS --clamp-mss-to-pmtu"
    if not iptables_has(mangle_rule.replace("-I", "-C"), "PREROUTING -t mangle"):
        run(f"iptables {mangle_rule}")
    
    # Connlimit (simultaneous connections per IP)
    cl = f"-p tcp --dport {port} -m connlimit --connlimit-above {MAX_CONN_PER_IP} --connlimit-mask 32 -j REJECT --reject-with tcp-reset"
    if not iptables_has(cl, CHAIN_NAME):
        run(f"iptables -A {CHAIN_NAME} {cl}")
        
    # Hashlimit (new connection rate-limit, and block on excessive rate)
    hl = (f"-p tcp --dport {port} -m conntrack --ctstate NEW -m hashlimit --hashlimit-name hl_new_{port} "
          f"--hashlimit-above {HASHLIMIT_RATE} --hashlimit-burst {HASHLIMIT_BURST} --hashlimit-mode srcip --hashlimit-srcmask 32 -j SET --add-set {IPSET_NAME} src")
    if not iptables_has(hl, CHAIN_NAME):
        run(f"iptables -A {CHAIN_NAME} {hl} 2>/dev/null || true")
        
    # SYN rate-limit (Soft limit for new SYNs)
    syn = f"-p tcp --dport {port} --syn -m conntrack --ctstate NEW -m limit --limit {SYN_RATE} --limit-burst {SYN_BURST} -j ACCEPT"
    if not iptables_has(syn, CHAIN_NAME):
        run(f"iptables -A {CHAIN_NAME} {syn}")
    syn_ret = f"-p tcp --dport {port} --syn -m conntrack --ctstate NEW -j RETURN"
    if not iptables_has(syn_ret, CHAIN_NAME):
        run(f"iptables -A {CHAIN_NAME} {syn_ret}")
        
    # UDP soft-limit (for UDP floods)
    udp = f"-p udp --dport {port} -m limit --limit {UDP_RATE} --limit-burst {UDP_BURST} -j ACCEPT"
    if not iptables_has(udp, CHAIN_NAME):
        run(f"iptables -A {CHAIN_NAME} {udp}")
    udp_ret = f"-p udp --dport {port} -j RETURN"
    if not iptables_has(udp_ret, CHAIN_NAME):
        run(f"iptables -A {CHAIN_NAME} {udp_ret}")
        
    log(f"Applied protections for port {port}")

def get_attackers():
    """Identifies IPs with excessively high total simultaneous connections."""
    out = run("ss -ntup 2>/dev/null || netstat -ntu 2>/dev/null")
    ip_counts = {}
    total_new_conn = 0
    
    for line in out.splitlines():
        if 'SYN-SENT' in line or 'SYN-RECV' in line:
            total_new_conn += 1
        
        m = re.search(r'(\d+\.\d+\.\d+\.\d+):\d+', line)
        if not m:
            continue
        ip = m.group(1)
        ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
    attackers = [(ip, cnt, []) for ip, cnt in ip_counts.items() if cnt >= CONN_THRESHOLD]
    return attackers, total_new_conn

def add_ipset(ip):
    """Adds an IP to the persistent block ipset."""
    run(f"ipset add {IPSET_NAME} {ip} timeout {BLOCK_TIME} -exist")
    log(f"Blocked IP {ip} via ipset for {BLOCK_TIME}s")
    send_discord(f"🚨 WeDDOS Guard: Blocked `{ip}` for {BLOCK_TIME}s due to repeated abuse/overload")

def escalate_global():
    """Inserts a temporary, aggressive global throttle rule."""
    global escalated
    if escalated:
        return
    escalated = True
    limit_rule = "-m conntrack --ctstate NEW -m limit --limit 50/second --limit-burst 100 -j RETURN"
    if not iptables_has(limit_rule, CHAIN_NAME):
        run(f"iptables -I {CHAIN_NAME} 1 {limit_rule}") 
        send_discord("⚠️ WeDDOS Guard: Escalated mitigation (High global new connection rate)")
        log("Global escalation enabled: New connections throttled.")

def relax_global():
    """Removes the aggressive global throttle rule."""
    global escalated
    if not escalated:
        return
    escalated = False
    lines = run(f"iptables -S {CHAIN_NAME}").splitlines()
    for l in lines:
        if "--limit 50/second" in l and "--ctstate NEW" in l:
            to_del = l.replace(f"-A {CHAIN_NAME}", "").replace(f"-I {CHAIN_NAME} 1", "").strip()
            run(f"iptables -D {CHAIN_NAME} {to_del}")
            log("Removed global escalation rule")
            break
    send_discord("✅ WeDDOS Guard: Global escalation relaxed")
    log("Global escalation removed")

def cleanup(signum, frame):
    """Graceful exit handler."""
    log("Exiting. Rules left intact for inspection. Use 'iptables -F' to clear.")
    sys.exit(0)

def main():
    if os.geteuid() != 0:
        print("Run as root")
        sys.exit(1)
    
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)
    
    # --- Setup ---
    apply_sysctl_hardening()
    ensure_established_accept()
    ensure_ipset()
    ensure_chain()
    apply_global_filters()
    send_discord("✅ WeDDOS Guard v1.7 Ultimate Defense started and protective rules applied.")

    while True:
        # 1. Apply Per-Port Protections 
        ports = set()
        for line in run("ss -lntu").splitlines():
            m = re.search(r':(\d+)\s', line)
            if m and m.group(1).isdigit():
                port = int(m.group(1))
                if port not in WHITELIST_PORTS:
                    ports.add(port)
                    
        for p in ports:
            apply_port_protections(p)

        # 2. Dynamic Connection Monitoring and Escalation
        attackers, total_new_conn = get_attackers()
        
        # Adaptive Global Control
        if total_new_conn >= GLOBAL_NEW_CONN_WARNING:
            escalate_global()
        else:
            relax_global()

        # Per-IP High Connection Check
        if attackers:
            for ip, cnt, _ in attackers:
                offender_counts[ip] = offender_counts.get(ip, 0) + 1
                log(f"Suspicious IP {ip}: {cnt} total connections (Flag {offender_counts[ip]}/{REPEAT_HITCOUNT})")
                if offender_counts[ip] >= REPEAT_HITCOUNT:
                    add_ipset(ip)
                    offender_counts[ip] = 0

        # Decay hit counts for temporary offenders
        for ip in list(offender_counts.keys()):
            offender_counts[ip] = max(0, offender_counts[ip]-1)

        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()
