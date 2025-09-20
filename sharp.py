#!/usr/bin/env python3

from __future__ import annotations
import argparse
import asyncio
import socket
import random
import sys
import re
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Optional, Set, Dict

# optional libs
try:
    import aiohttp
except Exception:
    print("[!] Missing dependency: aiohttp. Install with: pip install aiohttp")
    raise

try:
    import pyfiglet
except Exception:
    pyfiglet = None

# --- banner colors: only red ---
ANSI_COLORS = ["31"]   # red
RESET = "\x1b[0m"
BOLD = "\x1b[1m"

# Global printing toggle (if output file set -> False)
PRINT_RESULTS = True

def colorize_text(text: str) -> str:
    out_chars = []
    idx = 0
    for ch in text:
        if ch == "\n":
            out_chars.append(ch)
            continue
        color = ANSI_COLORS[idx % len(ANSI_COLORS)]
        out_chars.append(f"\x1b[{color}m{ch}{RESET}")
        idx += 1
    return "".join(out_chars)

async def print_banner():
    title = "SHARP"
    if pyfiglet:
        try:
            fig = pyfiglet.figlet_format(title)
        except Exception:
            fig = title + "\n"
    else:
        fig = title + "\n"
    # banner in red
    print(colorize_text(fig))
    # GitHub link also in red
    print(f"{BOLD}\x1b[31mGitHub: https://github.com/KARA-git/SHARP{RESET}\n")

# ---------------- blocking DNS resolver (run in executor) ----------------
def blocking_getaddrinfo(name: str):
    """Blocking getaddrinfo wrapper returns set of IP strings or None"""
    try:
        res = socket.getaddrinfo(name, None)
        ips = set()
        for entry in res:
            addr = entry[4][0]
            ips.add(addr)
        return ips if ips else None
    except Exception:
        return None

async def resolve(loop: asyncio.AbstractEventLoop, executor: ThreadPoolExecutor, fqdn: str, timeout: int = 5):
    try:
        fut = loop.run_in_executor(executor, blocking_getaddrinfo, fqdn)
        return await asyncio.wait_for(fut, timeout=timeout + 1)
    except asyncio.TimeoutError:
        return None
    except Exception:
        return None

# ---------------- passive sources ----------------
async def fetch_crt_sh(session: aiohttp.ClientSession, domain: str, timeout: int = 20) -> Set[str]:
    subdomains = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        async with session.get(url, timeout=timeout) as resp:
            if resp.status != 200:
                return subdomains
            text = await resp.text()
            # try parse JSON (crt.sh sometimes returns concatenated objects)
            try:
                data = json.loads(text)
            except Exception:
                try:
                    data = json.loads("[" + text.replace("}{", "},{") + "]")
                except Exception:
                    return subdomains
            for item in data:
                for key in ("common_name", "name_value"):
                    if key in item and item[key]:
                        for line in str(item[key]).splitlines():
                            line = line.strip()
                            if line.endswith("."):
                                line = line[:-1]
                            if line.endswith("." + domain) or line == domain:
                                subdomains.add(line.lower())
    except Exception:
        pass
    return subdomains

async def fetch_c99(session: aiohttp.ClientSession, domain: str, timeout: int = 20) -> Set[str]:
    subdomains = set()
    try:
        url = f"https://subdomainfinder.c99.nl/?q={domain}"
        async with session.get(url, timeout=timeout) as resp:
            text = await resp.text()
            pattern = re.compile(r"([a-zA-Z0-9\-\._]{1,256}\." + re.escape(domain) + r")", re.IGNORECASE)
            for m in pattern.finditer(text):
                subdomains.add(m.group(1).lower())
    except Exception:
        pass
    return subdomains

# ---------------- worker ----------------
async def worker_loop(domain: str,
                      q: asyncio.Queue,
                      loop: asyncio.AbstractEventLoop,
                      executor: ThreadPoolExecutor,
                      results_set: set,
                      wildcard_ips: Optional[Set[str]],
                      output_file_handle,
                      processed_dict: dict,
                      processed_lock: asyncio.Lock,
                      source_map: Dict[str, Optional[str]]):
   
    while True:
        item = await q.get()
        if item is None:
            q.task_done()
            break

        src_prefix = None  # None | "CRT" | "C99" | "WL"
        fqdn = None

        if item.startswith("__FQDN__"):
            fqdn = item[len("__FQDN__"):]
        elif item.startswith("__CRT__"):
            fqdn = item[len("__CRT__"):]
            src_prefix = "CRT"
        elif item.startswith("__C99__"):
            fqdn = item[len("__C99__"):]
            src_prefix = "C99"
        elif item.startswith("__WL__"):
            label = item[len("__WL__"):]
            src_prefix = "WL"
            if label.endswith("." + domain) or label == domain:
                fqdn = label
            else:
                fqdn = f"{label}.{domain}"
        else:
            if item.endswith("." + domain) or item == domain:
                fqdn = item
            else:
                fqdn = f"{item}.{domain}"

        info = await resolve(loop, executor, fqdn)
        if info:
            # skip wildcard identical responses
            if wildcard_ips and info == wildcard_ips:
                if PRINT_RESULTS:
                    print(f"[-] (wildcard) {fqdn} -> {', '.join(sorted(info))}")
            else:
                # choose src tag string for output
                src_tag = ""
                if src_prefix == "CRT":
                    src_tag = "[CRT.SH] "
                elif src_prefix == "C99":
                    src_tag = "[C99] "
                elif src_prefix == "WL":
                    src_tag = "[B-F] "

                # Add to dedupe set and output (but preserve source_map)
                if fqdn not in results_set:
                    results_set.add(fqdn)
                    # record source if not present (prefer CRT over others)
                    prev = source_map.get(fqdn)
                    if prev is None or (src_prefix == "CRT" and prev != "CRT"):
                        if src_prefix:
                            source_map[fqdn] = src_prefix
                        else:
                            source_map.setdefault(fqdn, None)
                    line = f"{src_tag}{fqdn} -> {', '.join(sorted(info))}"
                    if output_file_handle:
                        try:
                            output_file_handle.write(line + "\n")
                            output_file_handle.flush()
                        except Exception:
                            pass
                    if PRINT_RESULTS:
                        print(f"[+] {line}")

        # update processed counter if wordlist item
        if src_prefix == "WL":
            async with processed_lock:
                processed_dict['count'] += 1

        q.task_done()

# ---------------- wildcard detection ----------------
async def detect_wildcard(domain: str, loop: asyncio.AbstractEventLoop, executor: ThreadPoolExecutor) -> Optional[Set[str]]:
    tests = [f"{random.getrandbits(64):x}.{domain}" for _ in range(3)]
    ip_sets = []
    for t in tests:
        res = await resolve(loop, executor, t)
        if not res:
            return None
        ip_sets.append(frozenset(res))
    if len(set(ip_sets)) == 1 and len(ip_sets[0]) > 0:
        return set(ip_sets[0])
    return None

# ---------------- Enter-progress handler ----------------
async def on_enter(processed_dict: dict, total_wordlist: int):
    # consume a line (in thread) then print progress
    await asyncio.to_thread(sys.stdin.readline)
    proc = processed_dict.get('count', 0)
    if total_wordlist <= 0:
        print("[*] No wordlist loaded (0 total entries).")
        return
    pct = (proc / total_wordlist) * 100
    remaining = total_wordlist - proc
    print(f"[*] Brute-force progress: {proc}/{total_wordlist} ({pct:.2f}%) — remaining: {remaining}")

# ---------------- main async ----------------
async def main_async(domain: str, wordlist_path: Optional[str], concurrency: int, output_path: Optional[str], mode: str):
    global PRINT_RESULTS

    await print_banner()

    # output handling
    output_handle = None
    if output_path:
        # open in append mode for incremental writes; will canonical-overwrite at end
        output_handle = open(output_path, "a", encoding="utf-8")
        PRINT_RESULTS = False
        print(f"Waiting for adding results to {output_path}....")

    loop = asyncio.get_event_loop()
    executor = ThreadPoolExecutor(max_workers=max(32, concurrency * 2))
    q = asyncio.Queue()
    results_set = set()
    processed_dict = {'count': 0}
    processed_lock = asyncio.Lock()
    # map fqdn -> source token ("CRT"|"C99"|"WL"|None)
    source_map: Dict[str, Optional[str]] = {}

    print(f"[*] Mode: {mode}")

    # load wordlist (if brute-force or both)
    wordlist_labels = []
    if mode in ("brute-force", "both"):
        if not wordlist_path:
            print("[!] Wordlist path required for brute-force mode.")
            if output_handle:
                output_handle.close()
            return
        wl = Path(wordlist_path)
        if not wl.exists():
            print(f"[!] Wordlist file not found: {wordlist_path}")
            if output_handle:
                output_handle.close()
            return
        with wl.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                ln = line.strip()
                if not ln:
                    continue
                wordlist_labels.append(ln)
    total_wordlist = len(wordlist_labels)

    # wildcard detection
    print("[*] Detecting wildcard DNS...")
    wildcard_ips = await detect_wildcard(domain, loop, executor)
    if wildcard_ips:
        print(f"[!] Wildcard detected: {', '.join(sorted(wildcard_ips))}")
    else:
        print("[*] No wildcard detected (or unable to detect).")

    # PASSIVE FIRST if mode == both (or passive)
    passive_found = set()
    crt_found = set()
    c99_found = set()
    if mode in ("passive", "both"):
        print("[*] Querying passive sources (crt.sh, c99)...")
        async with aiohttp.ClientSession() as session:
            try:
                crt_task = asyncio.create_task(fetch_crt_sh(session, domain))
                c99_task = asyncio.create_task(fetch_c99(session, domain))
                crt_res, c99_res = await asyncio.gather(crt_task, c99_task)
                if crt_res:
                    crt_found = set(crt_res)
                if c99_res:
                    c99_found = set(c99_res)
                passive_found = (crt_found | c99_found)
                print(f"[*] Passive sources returned {len(passive_found)} candidate subdomains ({len(crt_found)} from crt.sh).")
            except Exception as e:
                print("[!] Passive source fetching error:", e)

        # enqueue passive: mark crt.sh items specially with __CRT__ token
        for sub in sorted(passive_found):
            if sub == domain:
                continue
            # if multi-label (left contains dot) push full FQDN token but keep CRT/C99 tag when appropriate
            if sub.endswith("." + domain):
                left = sub[:-(len(domain) + 1)]
                if "." in left:
                    # full fqdn token but keep source info
                    if sub in crt_found:
                        await q.put("__CRT__" + sub)
                    elif sub in c99_found:
                        await q.put("__C99__" + sub)
                    else:
                        await q.put("__FQDN__" + sub)
                else:
                    # single label -> push label but mark CRT/C99 if from those
                    if sub in crt_found:
                        await q.put("__CRT__" + sub)
                    elif sub in c99_found:
                        await q.put("__C99__" + sub)
                    else:
                        await q.put(left)
            else:
                # unusual case
                await q.put(sub)
    else:
        print("[*] Skipping passive enumeration (mode)")

    # Now enqueue brute-force entries (after passive) if requested
    if mode in ("brute-force", "both"):
        for w in wordlist_labels:
            await q.put("__WL__" + w)

    # install stdin Enter watcher for progress (Unix-add_reader fallback implemented)
    try:
        loop.add_reader(sys.stdin, lambda: asyncio.create_task(on_enter(processed_dict, total_wordlist)))
    except Exception:
        async def stdin_watcher():
            while True:
                await asyncio.to_thread(sys.stdin.readline)
                await on_enter(processed_dict, total_wordlist)
        asyncio.create_task(stdin_watcher())

    # start workers
    print(f"[*] Starting {concurrency} workers for bruteforce + passive probing...")
    workers = []
    for _ in range(concurrency):
        workers.append(asyncio.create_task(
            worker_loop(domain, q, loop, executor, results_set, wildcard_ips, output_handle,
                        processed_dict, processed_lock, source_map)
        ))

    # after enqueue done, push None sentinel for each worker
    await asyncio.sleep(0.1)
    for _ in range(concurrency):
        await q.put(None)

    # wait for workers
    await asyncio.gather(*workers)

    # final normalization & final resolution pass for passive-only entries (to get IPs)
    final_subs = set(results_set)
    print("[*] Final resolution pass for discovered candidates...")
    resolved_cache = {}
    for s in sorted(final_subs):
        ips = await resolve(loop, executor, s)
        if ips:
            resolved_cache[s] = ips

    # write canonical results file if output was provided (overwrite with canonical list including tags)
    if output_handle:
        print(f"[*] Writing canonical results to {output_path} ...")
        output_handle.close()
        try:
            with open(output_path, "w", encoding="utf-8") as fout:
                for s in sorted(final_subs):
                    tag = source_map.get(s)
                    src_tag = ""
                    if tag == "CRT":
                        src_tag = "[CRT.SH] "
                    elif tag == "C99":
                        src_tag = "[C99] "
                    elif tag == "WL":
                        src_tag = "[B-F] "
                    ips = resolved_cache.get(s)
                    if ips:
                        fout.write(f"{src_tag}{s} -> {', '.join(sorted(ips))}\n")
                    else:
                        fout.write(f"{src_tag}{s}\n")
        except Exception as e:
            print("[!] Error writing canonical results:", e)
        print(f"[*] Done. Found {len(final_subs)} total candidates. Results in {output_path}")
    else:
        print(f"[*] Done. Found {len(final_subs)} total candidates. (No output file specified; results were printed to terminal.)")

# ---------------- CLI ----------------
def parse_args():
    p = argparse.ArgumentParser(description="SHARP - Async subdomain finder (wordlist + crt.sh + c99 scraper)")
    p.add_argument("-d", "--domain", required=True, help="Target domain (e.g. example.com)")
    p.add_argument("-w", "--wordlist", default=None, help="Wordlist file (one sub-label per line) - required for brute-force")
    p.add_argument("-c", "--concurrency", type=int, default=200, help="Number of concurrent workers (default 200)")
    p.add_argument("-o", "--output", default=None, help="Output file (if omitted results printed to terminal)")
    p.add_argument("-m", "--mode", choices=["passive", "brute-force", "both"], default="both", help="Mode: passive, brute-force or both (default: both)")
    return p.parse_args()

def main():
    args = parse_args()
    try:
        asyncio.run(main_async(args.domain.lower(), args.wordlist, args.concurrency, args.output, args.mode))
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        try:
            sys.exit(1)
        except SystemExit:
            import os
            os._exit(1)

if __name__ == "__main__":
    main()
