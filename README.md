# 🔍 Zone Transfer Scanner

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)
[![GitHub stars](https://img.shields.io/github/stars/Infiniteim23/zone-transfer-scanner.svg)](https://github.com/Infiniteim23/zone-transfer-scanner/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/Infiniteim23/zone-transfer-scanner.svg)](https://github.com/Infiniteim23/zone-transfer-scanner/network)
[![GitHub issues](https://img.shields.io/github/issues/Infiniteim23/zone-transfer-scanner.svg)](https://github.com/Infiniteim23/zone-transfer-scanner/issues)

> ⚠️ **Disclaimer**: This tool is for educational and authorized testing only.

## 📋 Overview

Zone Transfer Scanner detects DNS zone transfer (AXFR) vulnerabilities.

### ✨ Features

- 🚀 **Fast**: Async scanning
- 🎯 **Multi-Domain**: Scan single or multiple domains
- 🔧 **Flexible**: Custom ports, nameservers
- 📊 **Multiple Outputs**: JSON, CSV, TXT

### 📦 Installation

```bash
git clone https://github.com/YOUR_USERNAME/zone-transfer-scanner.git
cd zone-transfer-scanner
pip3 install -r requirements.txt --break-system-packages 

## 🚀 Usage

### Quick Start
```bash
# Scan a single domain
python3 zone_transfer_check.py -d example.com

# Scan with custom DNS server
python3 zone_transfer_check.py -d lab.local -n 127.0.0.1 -p 5353

# Scan multiple domains from file
python3 zone_transfer_check.py -f domains.txt
```
# Example running zone_transfer_check.py

```bash
python3 zone_transfer_check.py -d zonetransfer.me

╔══════════════════════════════════════════════════════════════╗
║  ███████╗ ██████╗ ███╗   ██╗███████╗                              ║
║  ╚══███╔╝██╔═══██╗████╗  ██║██╔════╝                              ║
║    ███╔╝ ██║   ██║██╔██╗ ██║█████╗                                ║
║   ███╔╝  ██║   ██║██║╚██╗██║██╔══╝                                ║
║  ███████╗╚██████╔╝██║ ╚████║███████╗                              ║
║  ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝                              ║
║                                                                  ║
║  ████████╗██████╗  █████╗ ███╗   ██╗███████╗                    ║
║  ╚══██╔══╝██╔══██╗██╔══██╗████╗  ██║██╔════╝                    ║
║     ██║   ██████╔╝███████║██╔██╗ ██║███████╗                    ║
║     ██║   ██╔══██╗██╔══██║██║╚██╗██║╚════██║                    ║
║     ██║   ██║  ██║██║  ██║██║ ╚████║███████║                    ║
║     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝                    ║
║                                                                  ║
║     Zone Transfer Vulnerability Scanner v2.0                    ║
║     Custom Port • Multi-Domain • AXFR Testing                   ║
╚══════════════════════════════════════════════════════════════╝


============================================================
Scan Configuration
============================================================
  DNS Port:          53
  Concurrency:       50
  Timeout:           10s
  Output Format:     json
  Output Directory:  ./output
============================================================

[*] Testing single domain: zonetransfer.me

[*] Loaded 1 domains to scan
[*] Concurrency: 50 workers
[*] Timeout: 10s per domain
────────────────────────────────────────────────────────────

⚠ VULNERABLE: zonetransfer.me via nsztm2.digi.ninja:53 (51 records)                                                                                          
Testing Zone Transfers: 100%|█████████████████████████████████████████████████████████████████████████████████████████████████████████████| 1/1 [00:01<00:00]

============================================================
📊 ZONE TRANSFER SCAN RESULTS
============================================================
  Total Domains:     1
  Vulnerable:        1
  Safe:              0
  Errors:            0
  NS Tested:         1
  Records Found:     51
  Duration:          1.67s
============================================================

============================================================
⚠️  VULNERABLE DOMAINS - ZONE TRANSFER ENABLED
============================================================

1. zonetransfer.me
   Nameserver: nsztm2.digi.ninja (5.196.105.10:53)
   Records Found: 51
   Sample Records:
     → zonetransfer.me SOA nsztm1.digi.ninja. robin.digi.ninja. 2019100801 172800 900 1209600 3600
     → zonetransfer.me DNSKEY 256 3 7 AwEAAapoL+InQBYx2oi3dI424+dEDFgn VW0cOINfCY3jLrngZxBsEur8ByhMOQsx oIOYu/7b3c8tj2BwlQquqxZe79QHSW78 fK7D+bP/8AosnBG5K5gJXEvphEtJ9x8/ X0Y971XaW9lLmtJ6h4AXsrbgTr2g9KOi PSIbvDPMW8qLMaQkTm89hvPc+NuzrOEO PNhoXs/iPM+SQzrvTBfr6y0w2yPtYYdW I1kN76OQBxh0xjIdlyT0QKiohKq2bybP ROJO7K3NlDc8oaOZoXH5/RfLDQzxzXyY SV8fLwimUeulo7YA11I/AHQ7DsUsFu2S 2vxGCyR8nmx9gYbN4sBvTF2i5eM=
     → zonetransfer.me TXT "google-site-verification=tyP28J7JAUHA9fw2sHXMgcCC0I6XBmmoVi04VlMewxA"
     → zonetransfer.me MX 0 ASPMX.L.GOOGLE.COM.
     → zonetransfer.me MX 10 ALT1.ASPMX.L.GOOGLE.COM.
     ... and 46 more records

============================================================

[+] JSON saved: output/zone_transfer_20260712_145615.json
[+] Zone files saved in: output/zone_files_20260712_145615
[+] Scan complete!
```


