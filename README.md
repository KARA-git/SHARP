# SHARP - Async Subdomain Finder

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)

SHARP (Subdomain Hunter Async & Rapid Probe) — asinxron subdomain tapma alətidir.  
Həm **passive** (crt.sh, subdomainfinder.c99.nl), həm də **brute-force** üsulları ilə subdomainləri kəşf edə bilir.

---

## Features

- Asynchronous DNS resolution (asyncio + ThreadPoolExecutor)
- Passive enumeration:
  - crt.sh (`[CRT.SH]` taglı)
  - subdomainfinder.c99.nl (`[C99]` taglı)
- Brute-force enumeration (`[B-F]` taglı)
- Wildcard detection (skips false positives)
- Progress tracking with Enter key (shows brute-force % complete)
- Optional output file (`-o`) to store results only, suppress terminal output
- Colorful banner + GitHub link on start
- Mode selection: `passive`, `brute-force`, `both` (default: both)
- Deduplicates results and resolves IPs

---

## Installation

Clone this repository:

```bash
git clone https://github.com/youruser/sharp.git
cd sharp

