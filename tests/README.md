# NetGuard AI - Test Tools

Realistic, VM-safe attack simulations for validating NetGuard detection.

## `attack_simulator.py`

This simulator performs **real attacker behaviors** (not dummy packets) so you
can prove NetGuard detects live threats. It is designed to run inside a VM and
only targets the IP you specify.

### What it does

| Module | Real behavior | Expected detection |
|---|---|---|
| `portscan` | Full TCP connect scan + SYN sweep of 27 common ports | `port_scan` |
| `ssh` | Real SSH login attempts with common credentials | `brute_force` |
| `web` | SQLi, XSS, LFI, RCE, and web-shell HTTP requests | `attack` / suspicious |
| `reverse_shell` | Real TCP callbacks with reverse-shell payloads | `attack` / C2 |
| `lateral` | Probes SMB/RDP/WinRM/SSH lateral-movement ports | `port_scan` |
| `privesc` | Sudo password guessing against the local VM | local audit event |
| `dns` | DNS tunneling-style queries with encoded subdomains | suspicious / anomalous |
| `synflood` | Raw SYN flood to one port | `ddos` |
| `all` | Runs the full chain sequentially | Multiple threat types |

### Requirements

- Python 3
- scapy, requests, paramiko (installed by NetGuard installer)
- root / sudo access (for raw packets and SSH brute-force)

### Install test dependencies

If you did not run `install.sh`, install manually:

```bash
sudo /opt/netguard/venv/bin/pip install scapy requests paramiko
```

### Usage

```bash
# Full realistic attack chain against this VM (recommended)
sudo python3 tests/attack_simulator.py --target $(hostname -I | awk '{print $1}') --test all --duration 180

# Individual modules
sudo python3 tests/attack_simulator.py --target 127.0.0.1 --test portscan --duration 30
sudo python3 tests/attack_simulator.py --target 127.0.0.1 --test ssh --duration 60
sudo python3 tests/attack_simulator.py --target 127.0.0.1 --test web --duration 60
sudo python3 tests/attack_simulator.py --target 127.0.0.1 --test reverse_shell --duration 60
```

### Verifying detection

1. Ensure NetGuard services are running:
   ```bash
   sudo systemctl status netguard-capture netguard-processor netguard-web
   ```

2. Run the simulator.

3. Watch the dashboard at **http://localhost:8765**:
   - **Connections**: look for HIGH/CRITICAL threat levels and GeoIP locations
   - **Threats**: detected attack types (port_scan, brute_force, ddos, etc.)
   - **Alerts**: generated alerts with severity and threat level

### Expected results

Within a few minutes you should see:
- Port scan activity flagged as `port_scan`
- SSH attempts flagged as `brute_force`
- High packet-rate SYN flood flagged as `ddos`
- Web attack requests flagged as `attack`
- Reverse-shell traffic flagged as `attack`
- GeoIP fields populated with `Local` or country codes

### Safety

- The simulator only creates traffic and authentication attempts.
- No malware is installed, no files are deleted, and no external hosts are contacted unless you explicitly set `--target` to an external IP.
- Do not point this at networks or systems you do not own or have written permission to test.
