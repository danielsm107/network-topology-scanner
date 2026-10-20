# Network Topology Scanner

[![CI](https://github.com/danielsm107/network-topology-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/danielsm107/network-topology-scanner/actions/workflows/ci.yml)

Scans a network range, discovers active hosts, their open ports/services,
vendor (via MAC) and device type, and generates an interactive HTML topology
graph with icons per category (router, PC, NAS, printer, etc). Flags hosts
with sensitive open ports in red (Telnet, SMB, RDP, FTP, VNC), stores every
scan in SQLite to diff against the previous one (new/dropped hosts, ports
that changed), and can export the inventory to CSV. Optionally queries your
routers/switches over SNMP to draw the **real topology** (which host hangs
from which switch port or access point) instead of an approximate star.
Available as a CLI or as a local web interface (Streamlit, optional).

![Command Center dashboard](docs/screenshots/dashboard.png)
![Inventory and changes](docs/screenshots/inventario.png)

*Screenshots use fictional demo data — no real network is exposed here.*

## ⚠️ Legal notice
Only use this tool **on networks you own or have explicit authorization to
scan** (your homelab, or your workplace's network if you have permission).
Scanning networks without consent is illegal in most countries.

## Project structure

```
network-topology-scanner/
├── src/topology_scanner/
│   ├── scanner.py        # nmap scanning (discovery + ports)
│   ├── classifier.py      # Device classification by MAC/vendor
│   ├── graph.py            # Graph construction (networkx)
│   ├── export.py           # HTML export (pyvis), text and CSV
│   ├── history.py          # Scan history in SQLite (diff vs. the previous scan)
│   ├── snmp.py             # Real topology via SNMP (ARP, routes, MAC table, neighbors)
│   ├── cli.py               # Command-line interface
│   └── webapp.py            # Web interface (Streamlit, optional)
├── tests/                   # pytest, with nmap mocks (no real network needed)
└── pyproject.toml           # single source of dependencies (pip install -e ".[dev,web,snmp]")
```

## Installation

Requires Python 3.10+.

```bash
# System dependency
sudo apt install nmap        # Linux
# On Windows: download the installer from nmap.org

# Virtual environment
python3 -m venv venv
source venv/bin/activate      # Linux/Mac
# venv\Scripts\Activate.ps1   # Windows PowerShell

# Package install (editable mode, includes dev dependencies)
pip install -e ".[dev]"

# Optional, only if you want the web interface
pip install -e ".[web]"

# Optional, only if you want the real topology via SNMP
pip install -e ".[snmp]"
```

## Usage

```bash
sudo topology-scanner 192.168.1.0/24
sudo topology-scanner 192.168.1.0/24 --rapido
sudo topology-scanner 192.168.1.0/24 --con-so --output my_network.html

# Real topology: query the router(s) over SNMP (see below)
export TOPOLOGY_SNMP_COMMUNITY='your-read-only-community'
sudo -E topology-scanner 192.168.1.0/24 --snmp 192.168.1.1

# Alternative without the installed entry point:
sudo python3 -m topology_scanner 192.168.1.0/24
```

| Flag              | Description                                                     | Default              |
|-------------------|-------------------------------------------------------------------|-----------------------|
| `range`           | CIDR range to scan                                                 | (required)            |
| `--ports`         | Ports to scan (nmap format)                                        | common ports           |
| `--nmap-args`     | Extra arguments passed to nmap                                     | `-sV -T4`             |
| `--output`        | Output HTML file name                                              | `topologia_red.html`  |
| `--con-so`        | Enables OS detection (-O), the slowest option                      | disabled               |
| `--sin-2-fases`   | Disables the preliminary ping scan, scans the full range directly  | disabled               |
| `--rapido`        | Max-speed preset, ports only (incompatible with `--con-so`/`--nmap-args`) | disabled         |
| `--csv`           | Also exports a CSV inventory to the given path                     | disabled               |
| `--history-db`    | SQLite file where scan history is stored                           | `historial.db`         |
| `--sin-historial` | Skips saving the scan to history / diffing against the previous one | disabled              |
| `--snmp`          | Routers/switches to query over SNMP v2c (comma-separated IPs)      | disabled (star layout) |

## Web interface

Requires the `[web]` extra (see Installation). Form with automatic detection
of your local network, real cancellable scanning (kills the actual nmap
process, not just the UI), results table, CSV download and the embedded
graph.

```bash
topology-scanner-web
# or, without the installed entry point:
streamlit run src/topology_scanner/webapp.py
```

## Real topology via SNMP

By default the graph is an approximate star: nmap knows *which* hosts are
alive, not *how* they are connected. With `--snmp`, the scanner reads a few
standard tables from your routers/switches and builds a tree instead:

| SNMP table | What it tells | Used for |
|---|---|---|
| Routes (`ipCidrRouteTable`) | "10.0.10.0/24 is behind 192.168.1.44" | Upstream gateway, downstream routers and their subnets |
| Neighbors (MikroTik `mtxrNeighborTable`, MNDP/LLDP/CDP) | "Access point X is on my ether2" | Links between network devices |
| MAC table (`BRIDGE-MIB`) | "MAC aa:bb:… is on port wlan1" | Which port each host is on |
| ARP (`ipNetToMediaTable`) | "192.168.1.20 is aa:bb:…" | Matching MACs to the IPs nmap found |

Hosts seen on a port that leads to another network device hang from that
device; hosts that only SNMP sees (not detected by nmap) are shown too —
an unknown device on a switch port is exactly what you want to notice. If no
device answers, the scan still finishes with the star layout.

**Setup** (MikroTik RouterOS example — read-only, restricted to the
scanning machine):

```
/snmp community add name=<long-random-string> addresses=<scanner-ip>/32 read-access=yes write-access=no
/snmp community set [find name=public] disabled=yes
/snmp set enabled=yes
```

The community is read from the `TOPOLOGY_SNMP_COMMUNITY` environment
variable, never from a command-line argument (arguments show up in `ps` and
in your shell history). On Windows PowerShell:
`$env:TOPOLOGY_SNMP_COMMUNITY = "..."`.

**Current limitations**: SNMP v2c only; device-to-device links come from
MikroTik's neighbor table (other vendors still contribute routes, ARP and
MAC table); the web interface doesn't use SNMP yet.

## Device classification

Each host's MAC address is used to look up its vendor (via nmap's built-in
database), which is then heuristically mapped to a category with its own
icon: router, firewall, VM, NAS, printer, camera, IoT, mobile, Apple, PC.

**Limitation**: MAC resolution only works if the scanning machine is on the
**same L2 segment** as the target host (ARP doesn't cross routers/VLANs).
Hosts on other subnets will show up as category "unknown".

## Tests

```bash
pytest tests/ -v
pytest tests/ --cov=topology_scanner   # with coverage
```

`scanner.py` tests use `unittest.mock` to simulate nmap's responses, so they
run without a real network or the nmap binary installed.

## Roadmap

- [x] Visual alerts for sensitive open ports (RDP, Telnet, SMB, FTP, VNC)
- [x] Scan history in SQLite (new/dropped hosts, ports that change)
- [x] CSV export for audits/inventory
- [x] Visual icon/color legend in the HTML
- [x] Web interface with Streamlit
- [x] CI: run tests + ruff on every push
- [x] Real topology via SNMP against routers/switches, CLI (instead of the approximate star layout)
- [ ] SNMP in the web interface
- [ ] SNMPv3 and the standard LLDP-MIB for non-MikroTik devices
