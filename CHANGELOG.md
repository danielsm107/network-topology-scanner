# Changelog

All notable changes to this project are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Isometric view of the topology in the web interface, in the style of
  FossFLOW: a Flat / Isometric switch next to "Topology". Devices stand on
  coloured tiles over a grid, cables run at right angles along the floor, and
  the hosts behind each switch, access point or scanned range sit together on
  a raised, labelled platform. Switching views only redraws the map; it
  doesn't scan again.

### Changed
- The web interface now needs Streamlit 1.56 or later (`pip install -U
  "topology-scanner[web]"` upgrades it). The topology map moved from
  `st.components.v1.html`, which Streamlit deprecated and plans to remove,
  to `st.iframe`, so new installs keep working when it goes away.

## [1.1.0] - 2026-10-22

### Changed
- The CLI is now in English: help text, messages and flag names (`--fast`,
  `--os-detection`, `--no-discovery`, `--no-history`). The old Spanish flags
  keep working as hidden aliases, so existing scripts don't break.
- Scanner, SNMP, range and history errors and log messages are now in
  English too (they show up in both the CLI and the web interface).
- The terminal report, the history diff and the sensitive-port reasons
  (shown in every output) are in English.
- CSV columns renamed to English: `ip, hostname, mac, vendor, category, os,
  ports, alerts` (were `categoria`, `so`, `puertos`, `alertas`). Update any
  spreadsheet or script that reads them by name.
- Unclassified devices and undetected OS are now `unknown` (were
  `desconocido`), and category names are in English (Printer, Camera...).
- The HTML map is in English: legend, node tooltips and the central node of
  each range (`Network <range>`, was `Red <range>`).
- The web interface is in English: sidebar, results panels, scan progress
  and messages. The downloaded inventory is now `inventory.csv`.
- README screenshots regenerated in English, with fictional data only.
- The default HTML output is now `network_topology.html` (was
  `topologia_red.html`). The history database keeps its name
  (`historial.db`) so new scans still compare against the old ones.

## [1.0.0] - 2026-10-22

First public release. Earlier versions (0.x) were never published.

### Scanning
- Two-phase nmap scan: ping sweep first, then ports/services only on live hosts
  (`--rapido` for a quick scan, `--con-so` for OS detection).
- Several ranges in one run (`topology-scanner 192.0.2.0/24 198.51.100.0/24`).
- Device classification from the MAC vendor (router, NAS, printer, camera,
  IoT, mobile, Apple, PC, VM, firewall).
- Visual alerts for sensitive open ports (FTP, Telnet, SMB, RDP, VNC).

### Real topology via SNMP
- `--snmp` reads routes, ARP, MAC table and neighbors from routers/switches
  and draws the real tree instead of the approximate star.
- Neighbors via MikroTik MNDP and standard LLDP-MIB (any vendor), with the
  port on both ends of each link.
- SNMP v2c and v3 (SHA + AES by default); credentials only through
  environment variables, never command-line arguments.
- If SNMP fails, the scan still finishes with the star layout.

### Output
- Interactive HTML map (pyvis) with icons per category and a legend.
- CSV export for audits and inventory.
- Scan history in SQLite, per range: new/dropped hosts and changed ports,
  highlighting newly opened sensitive ports.

### Web interface (`[web]` extra)
- Streamlit app (`topology-scanner-web`): local range detection, cancellable
  scans (kills the nmap process), live scan log, paginated inventory, SVG
  topology with pan/zoom, CSV download and SNMP v2c/v3.

### Project
- CI on every push/PR (ruff + pytest on Python 3.10 and 3.12).
- Releases published to PyPI by GitHub Actions from a tag, with trusted
  publishing (OIDC, no API tokens).
