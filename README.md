# SHARP - Async Subdomain Finder

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE) [![GitHub stars](https://img.shields.io/github/stars/KARA-git/SHARP?style=social)](https://github.com/KARA-git/SHARP/stargazers)

SHARP (Subdomain Hunter Async & Rapid Probe) — **asynchronous subdomain enumeration tool**.  
Supports **passive** (crt.sh, subdomainfinder.c99.nl) and **brute-force** methods with tagging and IP resolution.

**GitHub:** [https://github.com/KARA-git/SHARP](https://github.com/KARA-git/SHARP)

---

## Features

- ✅ Async DNS resolution using `asyncio` + `ThreadPoolExecutor`
- ✅ Passive enumeration:
  - crt.sh `[CRT.SH]`
  - subdomainfinder.c99.nl `[C99]`
- ✅ Brute-force enumeration `[B-F]` with wordlist
- ✅ Wildcard detection (skips false positives)
- ✅ Progress tracking (press Enter to see brute-force % complete)
- ✅ Optional output file (`-o`) to store results only
- ✅ Colorful terminal banner + GitHub link
- ✅ Mode selection: `passive`, `brute-force`, `both` (default: both)
- ✅ Deduplicates results and resolves IPs

---

## Demo

Example run with output file:

```bash
python3 sharp.py -d example.com -w wordlist.txt -c 200 -o results.txt

 ____  _   _    _    ____  ____  
/ ___|| | | |  / \  |  _ \|  _ \ 
\___ \| |_| | / _ \ | |_) | |_) |
 ___) |  _  |/ ___ \|  _ <|  __/ 
|____/|_| |_/_/   \_\_| \_\_|    

GitHub: https://github.com/KARA-git/SHARP

waiting for adding results to results.txt
[*] Detecting wildcard DNS...
[*] No wildcard detected.
[*] Querying passive sources...
[*] Passive sources returned 26 candidate subdomains.
[*] Starting 200 workers for bruteforce + passive probing...
[CRT.SH] www.example.com -> 93.184.216.34
[C99] mail.example.com -> 93.184.216.50
[B-F] test.example.com -> 93.184.216.60

```

Installation
```bash
git clone https://github.com/KARA-git/SHARP.git
cd SHARP
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

```
Dependencies:

- aiohttp
- pyfiglet

Usage:

```bash
python3 sharp.py -d example.com -w wordlist.txt -c 200 -o results.txt
```

Examples

Passive only:
```bash
python3 sharp.py -d example.com -m passive -o passive_results.txt
```

Brute-force only:
```bash
python3 sharp.py -d example.com -w wordlist.txt -m brute-force
```

Passive + brute-force (default):
```bash
python3 sharp.py -d example.com -w wordlist.txt
```

Press Enter during run to see brute-force progress percentage.

