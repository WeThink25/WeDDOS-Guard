#!/usr/bin/env python3
"""
WeDDOS Guard - Advanced DDoS Protection System
Protects servers using iptables with rate limiting and auto port detection
Minecraft Server Compatible (TCP/UDP)
Discord Webhook Integration for logging and alerts
Configurable settings and port whitelisting
"""

import subprocess
import socket
import re
import sys
import time
import argparse
import json
import requests
from datetime import datetime
from collections import defaultdict

# ============================================================================
# CONFIGURATION SETTINGS - EDIT THESE VALUES
# ============================================================================

CONFIG = {
    # Discord Webhook URL (leave empty to disable Discord notifications)
    'DISCORD_WEBHOOK_URL': '',
    
    # Whitelisted ports (these ports will NEVER be rate-limited or blocked)
    # Common ports: 22 (SSH), 80 (HTTP), 443 (HTTPS)
    'WHITELISTED_PORTS': [22, 80, 443],
    
    # Rate limiting settings
    'DEFAULT_RATE_LIMIT': 100,          # Connections per second
    'DEFAULT_BURST_LIMIT': 200,         # Burst tolerance
    'SYN_FLOOD_RATE': 10,               # SYN packets per second
    'SYN_FLOOD_BURST': 50,              # SYN burst tolerance
    'ICMP_RATE_LIMIT': 1,               # Ping requests per second
    'ICMP_BURST': 2,                    # Ping burst tolerance
    'RST_RATE_LIMIT': 2,                # RST packets per second
    'RST_BURST': 2,                     # RST burst tolerance
    
    # Minecraft specific settings
    'MINECRAFT_TCP_RATE': 50,           # TCP connections per second
    'MINECRAFT_TCP_BURST': 100,         # TCP burst limit
    'MINECRAFT_UDP_RATE': 100,          # UDP packets per second
    'MINECRAFT_UDP_BURST': 150,         # UDP burst limit
    'MINECRAFT_MAX_CONN_PER_IP': 3,     # Max simultaneous connections per IP
    
    # Attack detection thresholds
    'ATTACK_THRESHOLD': 1000,           # Packets dropped to consider it an attack
    'MONITOR_INTERVAL': 60,             # Seconds between monitoring checks
    'STATS_REPORT_INTERVAL': 10,        # Send stats every N checks
    
    # Connection tracking
    'CONNTRACK_MAX': 100000,            # Maximum tracked connections
    
    # Logging
    'LOG_LEVEL': 'INFO',                # INFO, WARNING, ERROR, CRITICAL
    'VERBOSE_LOGGING': True,            # Detailed logging
    
    # Advanced protection features
    'ENABLE_GEO_BLOCKING': False,       # Enable country-based blocking (requires geoip)
    'BLOCKED_COUNTRIES': [],            # Country codes to block (e.g., ['CN', 'RU'])
    'ENABLE_FAIL2BAN_INTEGRATION': False,  # Work with fail2ban
    
    # Automatic features
    'AUTO_SAVE_RULES': True,            # Automatically save rules on exit
    'AUTO_DETECT_PORTS': True,          # Auto-detect open ports on startup
    'PROTECT_MINECRAFT_AUTO': True,     # Auto-protect Minecraft ports if detected
}

# ============================================================================
# END OF CONFIGURATION
# ============================================================================

class DiscordWebhook:
    def __init__(self, webhook_url):
        self.webhook_url = webhook_url
        self.enabled = bool(webhook_url)
        
    def send_message(self, title, description, color=0x00ff00, fields=None):
        """Send embed message to Discord"""
        if not self.enabled:
            return
        
        try:
            embed = {
                "title": title,
                "description": description,
                "color": color,
                "timestamp": datetime.utcnow().isoformat(),
                "footer": {
                    "text": "WeDDOS Guard"
                }
            }
            
            if fields:
                embed["fields"] = fields
            
            payload = {
                "embeds": [embed]
            }
            
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=10
            )
            
            if response.status_code not in [200, 204]:
                print(f"[WARNING] Discord webhook failed: {response.status_code}")
                
        except Exception as e:
            print(f"[WARNING] Failed to send Discord message: {str(e)}")
    
    def send_alert(self, message, level="INFO"):
        """Send alert message with color coding"""
        colors = {
            "INFO": 0x3498db,      # Blue
            "SUCCESS": 0x2ecc71,   # Green
            "WARNING": 0xf39c12,   # Orange
            "ERROR": 0xe74c3c,     # Red
            "CRITICAL": 0x992d22   # Dark Red
        }
        
        self.send_message(
            title=f"🛡️ WeDDOS Guard - {level}",
            description=message,
            color=colors.get(level, 0x95a5a6)
        )
    
    def send_attack_alert(self, attack_type, source_ip, port, packets_dropped):
        """Send detailed attack alert"""
        fields = [
            {"name": "⚠️ Attack Type", "value": attack_type, "inline": True},
            {"name": "🌐 Source IP", "value": source_ip, "inline": True},
            {"name": "🔌 Target Port", "value": str(port), "inline": True},
            {"name": "🚫 Packets Dropped", "value": str(packets_dropped), "inline": True}
        ]
        
        self.send_message(
            title="🚨 ATTACK DETECTED",
            description="Potential DDoS attack blocked by WeDDOS Guard",
            color=0xe74c3c,
            fields=fields
        )
    
    def send_statistics(self, protected_ports, whitelisted_ports, total_dropped, uptime):
        """Send statistics summary"""
        fields = [
            {"name": "🔒 Protected Ports", "value": str(len(protected_ports)), "inline": True},
            {"name": "✅ Whitelisted Ports", "value": str(len(whitelisted_ports)), "inline": True},
            {"name": "🚫 Total Dropped", "value": str(total_dropped), "inline": True},
            {"name": "⏱️ Uptime", "value": uptime, "inline": True},
            {"name": "📋 Protected", "value": ", ".join(map(str, protected_ports)) if protected_ports else "None", "inline": False},
            {"name": "✅ Whitelisted", "value": ", ".join(map(str, whitelisted_ports)), "inline": False}
        ]
        
        self.send_message(
            title="📊 Protection Statistics",
            description="Current WeDDOS Guard status report",
            color=0x3498db,
            fields=fields
        )

class WeDDOSGuard:
    def __init__(self, config=None, webhook_url=None):
        self.config = config or CONFIG
        self.protected_ports = []
        self.whitelisted_ports = self.config['WHITELISTED_PORTS'].copy()
        self.minecraft_ports = [25565]
        
        # Use webhook from config or parameter
        webhook = webhook_url or self.config.get('DISCORD_WEBHOOK_URL')
        self.discord = DiscordWebhook(webhook)
        
        self.start_time = datetime.now()
        self.attack_counts = defaultdict(int)
        self.last_stats = {}
        
    def log(self, message, level="INFO"):
        """Log messages with timestamp and send to Discord"""
        if self.config.get('LOG_LEVEL') == 'ERROR' and level == 'INFO':
            return
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] [{level}] {message}"
        print(log_message)
        
        # Send to Discord for important messages
        if level in ["SUCCESS", "WARNING", "ERROR", "CRITICAL"]:
            self.discord.send_alert(message, level)
    
    def check_root(self):
        """Check if script is running with root privileges"""
        if subprocess.call(['id', '-u'], stdout=subprocess.DEVNULL) != 0:
            return False
        result = subprocess.run(['id', '-u'], capture_output=True, text=True)
        return result.stdout.strip() == '0'
    
    def run_command(self, command):
        """Execute shell command safely"""
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            self.log(f"Command timed out: {command}", "ERROR")
            return False, "", "Timeout"
        except Exception as e:
            self.log(f"Command failed: {str(e)}", "ERROR")
            return False, "", str(e)
    
    def detect_open_ports(self):
        """Detect open listening ports on the system"""
        self.log("Detecting open ports...")
        open_ports = []
        
        success, output, _ = self.run_command("netstat -tuln 2>/dev/null || ss -tuln")
        
        if success and output:
            lines = output.split('\n')
            for line in lines:
                match = re.search(r'(tcp|udp)\s+\d+\s+\d+\s+[\d\.:]+:(\d+)', line.lower())
                if match:
                    port = int(match.group(2))
                    if port not in open_ports and port > 0:
                        open_ports.append(port)
        
        for port in self.minecraft_ports:
            if self.check_port_open(port) and port not in open_ports:
                open_ports.append(port)
        
        open_ports.sort()
        self.log(f"Detected open ports: {open_ports}")
        
        # Send to Discord
        if open_ports:
            fields = [
                {"name": "🔍 Detected Ports", "value": ", ".join(map(str, open_ports)), "inline": False},
                {"name": "📊 Total Count", "value": str(len(open_ports)), "inline": True}
            ]
            self.discord.send_message(
                title="🔎 Port Detection Complete",
                description="Open ports detected on the system",
                color=0x3498db,
                fields=fields
            )
        
        return open_ports
    
    def check_port_open(self, port):
        """Check if a specific port is open"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            return result == 0
        except:
            return False
    
    def check_existing_rules(self):
        """Check for existing iptables rules"""
        self.log("Checking existing firewall rules...")
        success, output, _ = self.run_command("iptables -L -n")
        
        if success:
            rule_count = len([l for l in output.split('\n') if l.strip() and not l.startswith('Chain') and not l.startswith('target')])
            self.log(f"Found {rule_count} existing iptables rules (will be preserved)")
            
            fields = [
                {"name": "📜 Existing Rules", "value": str(rule_count), "inline": True},
                {"name": "✅ Status", "value": "Rules preserved", "inline": True}
            ]
            self.discord.send_message(
                title="🔧 Firewall Status",
                description="Existing firewall rules detected and preserved",
                color=0x3498db,
                fields=fields
            )
            
            return rule_count
        return 0
    
    def setup_whitelist_rules(self):
        """Setup rules to whitelist important ports"""
        self.log("Setting up whitelist for critical ports...")
        
        whitelisted_count = 0
        for port in self.whitelisted_ports:
            # Accept all traffic on whitelisted ports (both TCP and UDP)
            rules = [
                f"iptables -A INPUT -p tcp --dport {port} -j ACCEPT",
                f"iptables -A INPUT -p udp --dport {port} -j ACCEPT"
            ]
            
            for rule in rules:
                success, _, _ = self.run_command(rule)
                if success:
                    whitelisted_count += 1
        
        self.log(f"Whitelisted {len(self.whitelisted_ports)} ports: {self.whitelisted_ports}", "SUCCESS")
        
        # Send to Discord
        fields = [
            {"name": "✅ Whitelisted Ports", "value": ", ".join(map(str, self.whitelisted_ports)), "inline": False},
            {"name": "🛡️ Protection", "value": "No rate limiting applied", "inline": True}
        ]
        self.discord.send_message(
            title="✅ Port Whitelist Active",
            description="Critical ports are whitelisted and fully accessible",
            color=0x2ecc71,
            fields=fields
        )
    
    def setup_base_protection(self):
        """Setup base iptables protection rules"""
        self.log("Setting up base protection rules...")
        
        # Get configured values
        syn_rate = self.config.get('SYN_FLOOD_RATE', 10)
        syn_burst = self.config.get('SYN_FLOOD_BURST', 50)
        icmp_rate = self.config.get('ICMP_RATE_LIMIT', 1)
        icmp_burst = self.config.get('ICMP_BURST', 2)
        rst_rate = self.config.get('RST_RATE_LIMIT', 2)
        rst_burst = self.config.get('RST_BURST', 2)
        
        rules = [
            # CRITICAL: Accept established and related connections FIRST
            "iptables -I INPUT 1 -m state --state ESTABLISHED,RELATED -j ACCEPT",
            
            # Accept loopback (localhost)
            "iptables -A INPUT -i lo -j ACCEPT",
            
            # Drop invalid packets (but not established connections)
            "iptables -A INPUT -m state --state INVALID -j DROP",
            
            # Protection against SYN flood (configurable)
            "iptables -N syn_flood 2>/dev/null || true",
            "iptables -F syn_flood 2>/dev/null || true",
            f"iptables -A syn_flood -m limit --limit {syn_rate}/s --limit-burst {syn_burst} -j RETURN",
            "iptables -A syn_flood -j DROP",
            "iptables -A INPUT -p tcp --syn -m state --state NEW -j syn_flood",
            
            # Drop fragmented packets
            "iptables -A INPUT -f -j DROP",
            
            # Drop XMAS packets
            "iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP",
            
            # Drop NULL packets
            "iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP",
            
            # Drop excessive RST packets (configurable)
            f"iptables -A INPUT -p tcp --tcp-flags RST RST -m limit --limit {rst_rate}/s --limit-burst {rst_burst} -j ACCEPT",
            "iptables -A INPUT -p tcp --tcp-flags RST RST -j DROP",
            
            # Limit ICMP (ping) requests (configurable)
            f"iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit {icmp_rate}/s --limit-burst {icmp_burst} -j ACCEPT",
            "iptables -A INPUT -p icmp --icmp-type echo-request -j DROP",
            
            # Protection against port scanning
            "iptables -N port_scan 2>/dev/null || true",
            "iptables -F port_scan 2>/dev/null || true",
            "iptables -A port_scan -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN",
            "iptables -A port_scan -j DROP"
        ]
        
        applied_rules = 0
        failed_rules = 0
        
        for rule in rules:
            success, _, stderr = self.run_command(rule)
            if success or "already exists" in stderr.lower():
                applied_rules += 1
            else:
                failed_rules += 1
                if "already exists" not in stderr.lower() and self.config.get('VERBOSE_LOGGING'):
                    self.log(f"Failed to apply rule: {rule}", "WARNING")
        
        self.log(f"Base protection setup complete: {applied_rules} rules applied", "SUCCESS")
        
        # Send summary to Discord
        fields = [
            {"name": "✅ Applied Rules", "value": str(applied_rules), "inline": True},
            {"name": "❌ Failed Rules", "value": str(failed_rules), "inline": True},
            {"name": "🛡️ Protection Level", "value": "Enhanced", "inline": True},
            {"name": "⚙️ SYN Flood Rate", "value": f"{syn_rate}/s (burst: {syn_burst})", "inline": True},
            {"name": "🏓 ICMP Rate", "value": f"{icmp_rate}/s (burst: {icmp_burst})", "inline": True}
        ]
        self.discord.send_message(
            title="🔒 Base Protection Activated",
            description="Core DDoS protection rules applied. Established connections are preserved.",
            color=0x2ecc71,
            fields=fields
        )
    
    def protect_port(self, port, protocol="both", rate_limit=None, burst=None):
        """Apply DDoS protection to a specific port"""
        
        # Skip if port is whitelisted
        if port in self.whitelisted_ports:
            self.log(f"Port {port} is whitelisted, skipping protection", "INFO")
            return
        
        # Use config defaults if not specified
        if rate_limit is None:
            rate_limit = self.config.get('DEFAULT_RATE_LIMIT', 100)
        if burst is None:
            burst = self.config.get('DEFAULT_BURST_LIMIT', 200)
        
        self.log(f"Protecting port {port} ({protocol}) - Rate: {rate_limit}/s, Burst: {burst}...")
        
        protocols = ['tcp', 'udp'] if protocol == 'both' else [protocol]
        
        for proto in protocols:
            chain_name = f"PORT_{port}_{proto.upper()}"
            self.run_command(f"iptables -N {chain_name} 2>/dev/null || iptables -F {chain_name}")
            
            rules = [
                # Allow established connections
                f"iptables -A {chain_name} -m state --state ESTABLISHED,RELATED -j ACCEPT",
                # Track new connections
                f"iptables -A {chain_name} -m state --state NEW -m recent --set --name {chain_name}_track",
                # Rate limit new connections
                f"iptables -A {chain_name} -m state --state NEW -m recent --update --seconds 1 --hitcount {rate_limit} --name {chain_name}_track -j DROP",
                # Burst limit
                f"iptables -A {chain_name} -m limit --limit {rate_limit}/s --limit-burst {burst} -j ACCEPT",
                # Drop excess
                f"iptables -A {chain_name} -j DROP"
            ]
            
            for rule in rules:
                self.run_command(rule)
            
            # Direct traffic to the chain (only for NEW connections)
            self.run_command(f"iptables -A INPUT -p {proto} --dport {port} -m state --state NEW -j {chain_name}")
            
        self.protected_ports.append(port)
        self.log(f"Port {port} is now protected", "SUCCESS")
        
        # Send to Discord
        fields = [
            {"name": "🔌 Port", "value": str(port), "inline": True},
            {"name": "📡 Protocol", "value": protocol.upper(), "inline": True},
            {"name": "⚡ Rate Limit", "value": f"{rate_limit}/s", "inline": True},
            {"name": "💥 Burst", "value": str(burst), "inline": True},
            {"name": "✅ Established Connections", "value": "Always allowed", "inline": False}
        ]
        self.discord.send_message(
            title="✅ Port Protection Enabled",
            description=f"Port {port} is now protected. Established connections are preserved.",
            color=0x2ecc71,
            fields=fields
        )
    
    def setup_minecraft_protection(self, port=25565):
        """Setup optimized protection for Minecraft servers"""
        
        # Skip if whitelisted
        if port in self.whitelisted_ports:
            self.log(f"Minecraft port {port} is whitelisted, skipping special protection", "INFO")
            return
        
        self.log(f"Setting up Minecraft server protection on port {port}...")
        
        # Use configured values
        tcp_rate = self.config.get('MINECRAFT_TCP_RATE', 50)
        tcp_burst = self.config.get('MINECRAFT_TCP_BURST', 100)
        udp_rate = self.config.get('MINECRAFT_UDP_RATE', 100)
        udp_burst = self.config.get('MINECRAFT_UDP_BURST', 150)
        max_conn = self.config.get('MINECRAFT_MAX_CONN_PER_IP', 3)
        
        self.protect_port(port, protocol='tcp', rate_limit=tcp_rate, burst=tcp_burst)
        self.protect_port(port, protocol='udp', rate_limit=udp_rate, burst=udp_burst)
        
        rules = [
            # Limit connections per IP (but allow established)
            f"iptables -A INPUT -p tcp --dport {port} --syn -m connlimit --connlimit-above {max_conn} -j REJECT --reject-with tcp-reset",
            # Drop oversized UDP packets
            f"iptables -A INPUT -p udp --dport {port} -m length --length 1500:65535 -j DROP"
        ]
        
        for rule in rules:
            self.run_command(rule)
        
        self.log(f"Minecraft server on port {port} is now protected", "SUCCESS")
        
        # Send Minecraft-specific alert
        fields = [
            {"name": "🎮 Server Type", "value": "Minecraft", "inline": True},
            {"name": "🔌 Port", "value": str(port), "inline": True},
            {"name": "🛡️ Protection", "value": "TCP + UDP", "inline": True},
            {"name": "👥 Max Connections/IP", "value": str(max_conn), "inline": True},
            {"name": "⚡ TCP Rate", "value": f"{tcp_rate}/s", "inline": True},
            {"name": "⚡ UDP Rate", "value": f"{udp_rate}/s", "inline": True}
        ]
        self.discord.send_message(
            title="🎮 Minecraft Protection Active",
            description="Minecraft server protected with optimized rules. Players can stay connected!",
            color=0x2ecc71,
            fields=fields
        )
    
    def analyze_attacks(self):
        """Analyze dropped packets and detect attacks"""
        success, output, _ = self.run_command("iptables -L -n -v -x")
        
        if not success:
            return []
        
        attacks_detected = []
        lines = output.split('\n')
        threshold = self.config.get('ATTACK_THRESHOLD', 1000)
        
        for line in lines:
            if 'DROP' in line:
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        packets = int(parts[0])
                        if packets > threshold:
                            attacks_detected.append({
                                'packets': packets,
                                'rule': line.strip()
                            })
                    except ValueError:
                        continue
        
        return attacks_detected
    
    def show_statistics(self):
        """Display current iptables statistics"""
        self.log("Gathering protection statistics...")
        success, output, _ = self.run_command("iptables -L -n -v -x")
        
        if success:
            print("\n" + output)
            
            # Calculate total dropped packets
            total_dropped = 0
            lines = output.split('\n')
            for line in lines:
                if 'DROP' in line:
                    parts = line.split()
                    if len(parts) >= 1:
                        try:
                            total_dropped += int(parts[0])
                        except ValueError:
                            continue
            
            # Calculate uptime
            uptime = datetime.now() - self.start_time
            uptime_str = str(uptime).split('.')[0]
            
            # Send to Discord
            self.discord.send_statistics(self.protected_ports, self.whitelisted_ports, total_dropped, uptime_str)
            
            return total_dropped
        return 0
    
    def save_rules(self):
        """Save iptables rules to persist across reboots"""
        self.log("Saving iptables rules...")
        
        commands = [
            "mkdir -p /etc/iptables 2>/dev/null",
            "iptables-save > /etc/iptables/rules.v4",
            "service iptables save",
            "netfilter-persistent save"
        ]
        
        for cmd in commands:
            success, _, _ = self.run_command(cmd)
            if success:
                self.log("Rules saved successfully", "SUCCESS")
                return
        
        self.log("Could not save rules automatically. Use 'iptables-save' manually.", "WARNING")
    
    def monitor_mode(self, interval=None):
        """Monitor mode - continuously check for attacks"""
        if interval is None:
            interval = self.config.get('MONITOR_INTERVAL', 60)
        
        self.log(f"Starting monitor mode (checking every {interval} seconds)...")
        self.log("Press Ctrl+C to stop")
        
        # Send monitoring start notification
        fields = [
            {"name": "⏱️ Check Interval", "value": f"{interval} seconds", "inline": True},
            {"name": "🔒 Protected Ports", "value": str(len(self.protected_ports)), "inline": True},
            {"name": "✅ Whitelisted Ports", "value": str(len(self.whitelisted_ports)), "inline": True},
            {"name": "📋 Protected", "value": ", ".join(map(str, self.protected_ports)) if self.protected_ports else "None", "inline": False},
            {"name": "✅ Whitelisted", "value": ", ".join(map(str, self.whitelisted_ports)), "inline": False}
        ]
        self.discord.send_message(
            title="👁️ Monitor Mode Started",
            description="WeDDOS Guard is now actively monitoring for attacks",
            color=0x3498db,
            fields=fields
        )
        
        try:
            check_count = 0
            stats_interval = self.config.get('STATS_REPORT_INTERVAL', 10)
            
            while True:
                check_count += 1
                
                # Analyze for attacks
                attacks = self.analyze_attacks()
                
                if attacks:
                    for attack in attacks:
                        self.log(f"Attack detected: {attack['packets']} packets dropped", "WARNING")
                        
                        # Send attack alert
                        fields = [
                            {"name": "🚫 Packets Dropped", "value": str(attack['packets']), "inline": True},
                            {"name": "📋 Rule", "value": f"```{attack['rule'][:100]}```", "inline": False}
                        ]
                        self.discord.send_message(
                            title="⚠️ High Traffic Detected",
                            description="Potential attack blocked by WeDDOS Guard",
                            color=0xf39c12,
                            fields=fields
                        )
                
                # Send periodic statistics
                if check_count % stats_interval == 0:
                    total_dropped = self.show_statistics()
                    uptime = datetime.now() - self.start_time
                    uptime_str = str(uptime).split('.')[0]
                    
                    self.log(f"Monitor check #{check_count} - Total dropped: {total_dropped}")
                
                time.sleep(interval)
                
        except KeyboardInterrupt:
            self.log("Monitor mode stopped", "INFO")
            
            # Send stop notification
            uptime = datetime.now() - self.start_time
            uptime_str = str(uptime).split('.')[0]
            
            fields = [
                {"name": "⏱️ Total Uptime", "value": uptime_str, "inline": True},
                {"name": "🔍 Total Checks", "value": str(check_count), "inline": True}
            ]
            self.discord.send_message(
                title="🛑 Monitor Mode Stopped",
                description="WeDDOS Guard monitoring has been stopped",
                color=0x95a5a6,
                fields=fields
            )

def main():
    parser = argparse.ArgumentParser(
        description='WeDDOS Guard - Advanced DDoS Protection System with Discord Integration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 weddos_guard.py --auto
  sudo python3 weddos_guard.py --auto --minecraft --monitor
  sudo python3 weddos_guard.py -p 8080,9000 --whitelist 22,80,443
  sudo python3 weddos_guard.py --auto -w "DISCORD_WEBHOOK_URL"
        """
    )
    
    parser.add_argument('-a', '--auto', action='store_true',
                       help='Auto-detect and protect all open ports')
    parser.add_argument('-p', '--ports', type=str,
                       help='Comma-separated list of ports to protect (e.g., 80,443,25565)')
    parser.add_argument('-m', '--minecraft', type=int, nargs='?', const=25565,
                       help='Enable Minecraft server protection (default port: 25565)')
    parser.add_argument('-r', '--rate-limit', type=int,
                       help=f'Rate limit (connections per second, default: {CONFIG["DEFAULT_RATE_LIMIT"]})')
    parser.add_argument('-b', '--burst', type=int,
                       help=f'Burst limit (default: {CONFIG["DEFAULT_BURST_LIMIT"]})')
    parser.add_argument('-w', '--webhook', type=str,
                       help='Discord webhook URL for logging and alerts')
    parser.add_argument('--whitelist', type=str,
                       help='Comma-separated list of ports to whitelist (e.g., 22,80,443)')
    parser.add_argument('--monitor', action='store_true',
                       help='Enable monitoring mode')
    parser.add_argument('--monitor-interval', type=int,
                       help=f'Monitor check interval in seconds (default: {CONFIG["MONITOR_INTERVAL"]})')
    parser.add_argument('--stats', action='store_true',
                       help='Show current statistics')
    parser.add_argument('--save', action='store_true',
                       help='Save rules to persist across reboots')
    parser.add_argument('--show-config', action='store_true',
                       help='Show current configuration and exit')
    
    args = parser.parse_args()
    
    # Show configuration if requested
    if args.show_config:
        print("=" * 60)
        print("WeDDOS Guard - Current Configuration")
        print("=" * 60)
        for key, value in CONFIG.items():
            print(f"{key}: {value}")
        print("=" * 60)
        sys.exit(0)
    
    # Override config with command-line arguments
    config = CONFIG.copy()
    if args.rate_limit:
        config['DEFAULT_RATE_LIMIT'] = args.rate_limit
    if args.burst:
        config['DEFAULT_BURST_LIMIT'] = args.burst
    if args.monitor_interval:
        config['MONITOR_INTERVAL'] = args.monitor_interval
    if args.whitelist:
        # Add to existing whitelist
        new_ports = [int(p.strip()) for p in args.whitelist.split(',')]
        config['WHITELISTED_PORTS'].extend(new_ports)
        config['WHITELISTED_PORTS'] = list(set(config['WHITELISTED_PORTS']))  # Remove duplicates
    
    guard = WeDDOSGuard(config=config, webhook_url=args.webhook)
    
    print("=" * 60)
    print("WeDDOS Guard - DDoS Protection System")
    print("=" * 60)
    print(f"Version: 2.0 | Configurable & Whitelist Support")
    print("=" * 60)
    
    # Check root privileges
    if not guard.check_root():
        guard.log("This script requires root privileges!", "ERROR")
        guard.log("Please run with: sudo python3 weddos_guard.py", "ERROR")
        sys.exit(1)
    
    # Send startup notification
    if guard.discord.enabled:
        fields = [
            {"name": "⚙️ Rate Limit", "value": f"{config['DEFAULT_RATE_LIMIT']}/s", "inline": True},
            {"name": "💥 Burst Limit", "value": str(config['DEFAULT_BURST_LIMIT']), "inline": True},
            {"name": "✅ Whitelisted Ports", "value": ", ".join(map(str, guard.whitelisted_ports)), "inline": False}
        ]
        guard.discord.send_message(
            title="🚀 WeDDOS Guard Starting",
            description="DDoS protection system is initializing...\nEstablished connections will be preserved.",
            color=0x3498db,
            fields=fields
        )
    
    # Check existing rules
    guard.check_existing_rules()
    
    # Setup whitelist FIRST (before any blocking rules)
    guard.setup_whitelist_rules()
    
    # Setup base protection
    guard.setup_base_protection()
    
    # Auto-detect and protect ports
    if args.auto:
        ports = guard.detect_open_ports()
        for port in ports:
            if port not in guard.whitelisted_ports:
                guard.protect_port(port, rate_limit=config['DEFAULT_RATE_LIMIT'], burst=config['DEFAULT_BURST_LIMIT'])
            else:
                guard.log(f"Skipping port {port} (whitelisted)", "INFO")
        
        # Auto-protect Minecraft if enabled in config
        if config.get('PROTECT_MINECRAFT_AUTO'):
            for port in guard.minecraft_ports:
                if port in ports and port not in guard.whitelisted_ports:
                    guard.setup_minecraft_protection(port)
    
    # Protect specific ports
    if args.ports:
        ports = [int(p.strip()) for p in args.ports.split(',')]
        for port in ports:
            guard.protect_port(port, rate_limit=config['DEFAULT_RATE_LIMIT'], burst=config['DEFAULT_BURST_LIMIT'])
    
    # Minecraft protection
    if args.minecraft:
        guard.setup_minecraft_protection(args.minecraft)
    
    # Show statistics
    if args.stats:
        guard.show_statistics()
    
    # Save rules
    if args.save or config.get('AUTO_SAVE_RULES'):
        guard.save_rules()
    
    # Monitor mode
    if args.monitor:
        guard.monitor_mode(interval=config['MONITOR_INTERVAL'])
    
    guard.log("WeDDOS Guard setup complete!", "SUCCESS")
    guard.log(f"Protected ports: {guard.protected_ports}")
    guard.log(f"Whitelisted ports: {guard.whitelisted_ports}")
    
    # Send completion notification
    if guard.discord.enabled:
        uptime = datetime.now() - guard.start_time
        uptime_str = str(uptime).split('.')[0]
        
        fields = [
            {"name": "🔒 Protected Ports", "value": str(len(guard.protected_ports)), "inline": True},
            {"name": "✅ Whitelisted Ports", "value": str(len(guard.whitelisted_ports)), "inline": True},
            {"name": "⏱️ Setup Time", "value": uptime_str, "inline": True},
            {"name": "📋 Protected", "value": ", ".join(map(str, guard.protected_ports)) if guard.protected_ports else "None", "inline": False},
            {"name": "✅ Whitelisted", "value": ", ".join(map(str, guard.whitelisted_ports)), "inline": False},
            {"name": "🔄 Established Connections", "value": "Always preserved", "inline": False}
        ]
        guard.discord.send_message(
            title="✅ WeDDOS Guard Active",
            description="DDoS protection is now fully operational!\nYour existing connections remain safe.",
            color=0x2ecc71,
            fields=fields
        )
    
    print("=" * 60)
    print("Configuration Summary:")
    print(f"  • Protected Ports: {len(guard.protected_ports)}")
    print(f"  • Whitelisted Ports: {len(guard.whitelisted_ports)}")
    print(f"  • Rate Limit: {config['DEFAULT_RATE_LIMIT']}/s")
    print(f"  • Burst Limit: {config['DEFAULT_BURST_LIMIT']}")
    print(f"  • Discord Alerts: {'Enabled' if guard.discord.enabled else 'Disabled'}")
    print(f"  • Established Connections: Protected")
    print("=" * 60)

if __name__ == "__main__":
    main()
