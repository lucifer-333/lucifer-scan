#!/usr/bin/env python3
"""
LuciferScan - Fast, multi-threaded TCP port scanner & service banner grabber.
Author: Lucifer
"""

import sys
import os
import socket
import argparse
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import json

# Terminal colors (ANSI)
# Windows 10/11 supports ANSI if virtual terminal sequences are enabled
if os.name == 'nt':
    os.system('')  # enables ANSI escape codes in Windows cmd/powershell

RED = "\033[91m"
DARK_RED = "\033[31m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
WHITE = "\033[97m"
GRAY = "\033[90m"
BOLD = "\033[1m"
RESET = "\033[0m"

BANNER = f"""{RED}
  _                 _  __             ____                  
 | |   _   _  ___  (_)/ _| ___ _ __  / ___|  ___ __ _ _ __  
 | |  | | | |/ __| | | |_ / _ \\ '__| \\___ \\ / __/ _` | '_ \\ 
 | |__| |_| | (__  | |  _|  __/ |     ___) | (_| (_| | | | |
 |_____\\__,_|\\___| |_|_|  \\___|_|    |____/ \\___\\__,_|_| |_|
{GRAY}                     [ High-Speed Port Recon ]{RESET}
"""

# Common top 100 ports list for quick scanning
TOP_PORTS = [
    20, 21, 22, 23, 25, 53, 69, 80, 88, 110, 111, 123, 135, 137, 138, 139, 143,
    161, 162, 179, 389, 443, 445, 465, 500, 514, 515, 587, 636, 873, 993, 995,
    1025, 1080, 1433, 1434, 1521, 1723, 1883, 2049, 2082, 2083, 2086, 2087,
    2181, 2222, 3000, 3128, 3268, 3306, 3389, 3690, 4000, 4444, 5000, 5432,
    5672, 5900, 5985, 5986, 6379, 6667, 7001, 7077, 8000, 8008, 8080, 8081,
    8088, 8443, 8500, 8888, 9000, 9042, 9092, 9200, 9300, 9418, 9999, 10000,
    11211, 27017, 27018, 50000, 50070
]

# Fallback service map for ports getservbyport often misses
KNOWN_SERVICES = {
    81: "hosts2-ns",
    88: "kerberos",
    135: "msrpc",
    139: "netbios-ssn",
    445: "microsoft-ds",
    1433: "ms-sql-s",
    1521: "oracle",
    2082: "cpanel",
    2083: "cpanel-ssl",
    2086: "whm",
    2087: "whm-ssl",
    2222: "directadmin / ssh-alt",
    3000: "node / dev-server",
    3306: "mysql",
    3389: "ms-wbt-server (rdp)",
    5000: "upnp / flask",
    5432: "postgresql",
    5672: "rabbitmq",
    5900: "vnc",
    6379: "redis",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    8888: "jupyter / http-alt",
    9000: "sonarqube / php-fpm",
    9092: "kafka",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb"
}


def resolve_target(target_str):
    """Resolves hostname to IPv4 address."""
    clean_target = target_str.strip().replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    try:
        ip = socket.gethostbyname(clean_target)
        return clean_target, ip
    except socket.gaierror:
        return None, None


def get_service_name(port):
    """Gets human-readable service name from port."""
    if port in KNOWN_SERVICES:
        return KNOWN_SERVICES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except (socket.error, OSError):
        return "unknown"


def grab_banner(ip, port, timeout=1.0):
    """
    Attempts to read banner string sent by service upon connection.
    Sends simple probes for generic services like HTTP.
    """
    banner = ""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            
            # Send small generic probe for web/protocol services
            try:
                if port in (80, 8080, 8000, 3000, 5000):
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                elif port == 443 or port == 8443:
                    # Raw SSL won't reply plain text banner cleanly without wrap, skip raw send
                    pass
                else:
                    s.sendall(b"\r\n")
            except Exception:
                pass
            
            raw_data = s.recv(1024)
            if raw_data:
                # Clean up non-printable characters and newlines
                decoded = raw_data.decode('utf-8', errors='ignore').strip()
                # Grab just the first line of the banner to keep output clean
                first_line = decoded.splitlines()[0] if decoded.splitlines() else ""
                banner = "".join([c for c in first_line if 31 < ord(c) < 127 or c == ' ']).strip()
    except Exception:
        pass
    
    return banner[:50]  # truncate long banners


def scan_single_port(ip, port, timeout, grab_service_banner=False):
    """Checks if a single TCP port is open."""
    result = None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            status = sock.connect_ex((ip, port))
            if status == 0:
                service = get_service_name(port)
                banner = grab_banner(ip, port, timeout) if grab_service_banner else ""
                result = {
                    "port": port,
                    "state": "open",
                    "service": service,
                    "banner": banner
                }
    except Exception:
        pass
    return result


def parse_port_argument(port_arg):
    """Parses port range or comma-separated string."""
    ports = set()
    if not port_arg or port_arg.lower() in ("top", "default"):
        return TOP_PORTS
    
    if port_arg.lower() in ("all", "full"):
        return list(range(1, 65536))
    
    for item in port_arg.split(","):
        item = item.strip()
        if not item:
            continue
        if "-" in item:
            try:
                start, end = item.split("-")
                start, end = int(start), int(end)
                if 1 <= start <= 65535 and 1 <= end <= 65535 and start <= end:
                    ports.update(range(start, end + 1))
            except ValueError:
                pass
        else:
            try:
                p = int(item)
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                pass
    
    return sorted(list(ports)) if ports else TOP_PORTS


def main():
    parser = argparse.ArgumentParser(
        description="LuciferScan - High-speed TCP Port Scanner & Banner Grabber",
        usage="%(prog)s -t <target> [options]"
    )
    
    parser.add_argument("-t", "--target", dest="target", required=True, help="Target host or IP address (e.g. 192.168.1.1, scanme.nmap.org)")
    parser.add_argument("-p", "--ports", dest="ports", default="top", help="Port range (e.g. 1-1024, 80,443,8080, 'top', 'full') [Default: top]")
    parser.add_argument("-T", "--threads", dest="threads", type=int, default=100, help="Number of concurrent worker threads [Default: 100]")
    parser.add_argument("--timeout", dest="timeout", type=float, default=0.8, help="Connection timeout in seconds [Default: 0.8]")
    parser.add_argument("-b", "--banner", dest="banner", action="store_true", help="Enable service banner grabbing")
    parser.add_argument("-o", "--output", dest="output", help="Save results to output file (.txt or .json)")
    parser.add_argument("-q", "--quiet", dest="quiet", action="store_true", help="Quiet mode (display open ports only)")
    
    args = parser.parse_args()
    
    if not args.quiet:
        print(BANNER)
        print(f" {GRAY}Started at:{RESET} {time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Resolve host
    hostname, target_ip = resolve_target(args.target)
    if not target_ip:
        print(f"[{RED}!{RESET}] Error: Could not resolve target host '{args.target}'")
        sys.exit(1)
    
    port_list = parse_port_argument(args.ports)
    if not port_list:
        print(f"[{RED}!{RESET}] Error: No valid ports specified to scan.")
        sys.exit(1)
        
    if not args.quiet:
        print(f" {CYAN}[*]{RESET} Target: {BOLD}{hostname}{RESET} ({target_ip})")
        print(f" {CYAN}[*]{RESET} Scanning {len(port_list)} ports using {args.threads} threads (timeout: {args.timeout}s)")
        if args.banner:
            print(f" {CYAN}[*]{RESET} Banner grabbing: {GREEN}Enabled{RESET}")
        print(f"{GRAY}{'-' * 65}{RESET}")
        header = f"{'PORT':<10} {'STATE':<8} {'SERVICE':<18}"
        if args.banner:
            header += f" {'BANNER':<25}"
        print(f"{BOLD}{header}{RESET}")
        print(f"{GRAY}{'-' * 65}{RESET}")

    start_time = time.time()
    open_ports = []
    
    try:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {
                executor.submit(scan_single_port, target_ip, p, args.timeout, args.banner): p
                for p in port_list
            }
            
            for future in as_completed(futures):
                res = future.result()
                if res:
                    open_ports.append(res)
                    port_str = f"{res['port']}/tcp"
                    service_str = res['service']
                    banner_str = res['banner'] if args.banner else ""
                    
                    if args.quiet:
                        print(f"{res['port']}")
                    else:
                        line = f"{GREEN}{port_str:<10}{RESET} {GREEN}{'open':<8}{RESET} {CYAN}{service_str:<18}{RESET}"
                        if args.banner:
                            line += f" {WHITE}{banner_str:<25}{RESET}"
                        print(line)
                        
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Scan interrupted by user. Processing discovered ports...{RESET}")
    
    # Sort discovered ports ascending
    open_ports.sort(key=lambda x: x["port"])
    duration = time.time() - start_time
    
    if not args.quiet:
        print(f"{GRAY}{'-' * 65}{RESET}")
        print(f" {GREEN}[+]{RESET} Done! Found {BOLD}{len(open_ports)}{RESET} open port(s) in {duration:.2f} seconds.")
    
    # Save output if requested
    if args.output:
        try:
            if args.output.endswith(".json"):
                data = {
                    "target": hostname,
                    "ip": target_ip,
                    "scan_time": time.strftime('%Y-%m-%d %H:%M:%S'),
                    "duration_seconds": round(duration, 2),
                    "open_ports": open_ports
                }
                with open(args.output, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=4)
            else:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(f"LuciferScan Report - {hostname} ({target_ip})\n")
                    f.write(f"Scanned at: {time.strftime('%Y-%m-%d %H:%M:%S')} in {duration:.2f}s\n\n")
                    f.write(f"{'PORT':<10} {'STATE':<8} {'SERVICE':<18} {'BANNER'}\n")
                    f.write("-" * 65 + "\n")
                    for p in open_ports:
                        f.write(f"{str(p['port']) + '/tcp':<10} {'open':<8} {p['service']:<18} {p['banner']}\n")
            
            if not args.quiet:
                print(f" {CYAN}[*]{RESET} Results successfully saved to {BOLD}{args.output}{RESET}")
        except Exception as e:
            print(f"[{RED}!{RESET}] Failed to save output to {args.output}: {e}")


if __name__ == "__main__":
    main()
