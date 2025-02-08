#!/usr/bin/env python3
import argparse
import socket
import time
from scapy.all import ARP, Ether, srp, conf, sr1, IP, TCP
import sys

# Define placeholders for colors (empty strings if colorama is not used)
GREEN = ""
RED = ""
YELLOW = ""
CYAN = ""
RESET = ""

# ASCII Art
ASCII_ART = f"""
{CYAN}
██╗███╗   ██╗██╗   ██╗██╗███████╗██╗███████╗ ██████╗ █████╗ ███╗   ██╗
██║████╗  ██║██║   ██║██║██╔════╝██║██╔════╝██╔════╝██╔══██╗████╗  ██║
██║██╔██╗ ██║██║   ██║██║█████╗  ██║███████╗██║     ███████║██╔██╗ ██║
██║██║╚██╗██║╚██╗ ██╔╝██║██╔══╝  ██║╚════██║██║     ██╔══██║██║╚██╗██║
██║██║ ╚████║ ╚████╔╝ ██║██║     ██║███████║╚██████╗██║  ██║██║ ╚████║
╚═╝╚═╝  ╚═══╝  ╚═══╝  ╚═╝╚═╝     ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{RESET}
"""

# Predefined list of common ports (Top 100)
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1723, 3306, 3389,
    5900, 8080, 8443
]

def print_banner():
    print(ASCII_ART)

def resolve_dns(target):
    try:
        ip_address = socket.gethostbyname(target)
        print(f"{GREEN}[+] Resolved {target} to IP: {ip_address}{RESET}")
        return ip_address
    except socket.gaierror:
        print(f"{RED}[-] Failed to resolve {target}{RESET}")
        return None

def network_scan(subnet):
    print(f"{YELLOW}[*] Scanning network {subnet} for active devices...{RESET}")
    arp = ARP(pdst=subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

def port_scan(target, ports, stealth=False, delay=0.1):
    open_ports = []
    print(f"{YELLOW}[*] Scanning {target}...{RESET}")
    
    for port in ports:
        try:
            if stealth:
                # SYN Stealth Scan
                pkt = IP(dst=target)/TCP(dport=port, flags="S")
                resp = sr1(pkt, timeout=1, verbose=0)
                if resp and resp.haslayer(TCP):
                    if resp.getlayer(TCP).flags == 0x12:  # SYN-ACK
                        open_ports.append(port)
                        sr(IP(dst=target)/TCP(dport=port, flags="R"), timeout=1, verbose=0)
            else:
                # Regular TCP Connect Scan
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                result = s.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
                s.close()
            
            if stealth:
                time.sleep(delay)
                
        except Exception as e:
            pass

    return open_ports

def get_service_name(port):
    try:
        return socket.getservbyport(port)
    except:
        return "unknown"

def print_results(target, open_ports):
    print(f"\n{GREEN}Scan results for {target}:{RESET}")
    if not open_ports:
        print(f"{RED}No open ports found{RESET}")
        return
    
    print(f"{CYAN}PORT\tSTATE\tSERVICE{RESET}")
    for port in open_ports:
        service = get_service_name(port)
        print(f"{GREEN}{port}\topen\t{service}{RESET}")

def main():
    print_banner()
    parser = argparse.ArgumentParser(description='InvisiScan - Advanced Network Scanner')
    parser.add_argument('target', help='IP address, domain name, or subnet (e.g., 192.168.1.1, example.com, 192.168.1.0/24)')
    parser.add_argument('-f', '--fast', action='store_true', help='Fast scan (common ports only)')
    parser.add_argument('-s', '--stealth', action='store_true', help='Stealth mode (slower)')
    parser.add_argument('-d', '--delay', type=float, default=0.1, help='Delay between packets in stealth mode')
    parser.add_argument('-n', '--network', action='store_true', help='Network devices discovery')

    args = parser.parse_args()

    # Resolve DNS if the target is a domain name
    if not args.network and not args.target.replace('.', '').isdigit():
        resolved_ip = resolve_dns(args.target)
        if not resolved_ip:
            print(f"{RED}[-] Cannot proceed without resolving the target.{RESET}")
            return
        args.target = resolved_ip

    if args.network:
        devices = network_scan(args.target)
        print(f"\n{GREEN}Discovered devices:{RESET}")
        print(f"{CYAN}IP Address\tMAC Address{RESET}")
        for device in devices:
            print(f"{GREEN}{device['ip']}\t{device['mac']}{RESET}")
        return

    ports = COMMON_PORTS if args.fast else range(1, 65536)
    
    try:
        open_ports = port_scan(args.target, ports, args.stealth, args.delay)
        print_results(args.target, open_ports)
    except KeyboardInterrupt:
        print(f"\n{RED}Scan interrupted by user{RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()
