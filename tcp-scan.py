#!/usr/bin/env python3
# chaos_blaster_god_final.py
# 2025 Tamil GOD MODE – 3 IP Formats + Full Shuffle + Source Port Control
# sudo python3 chaos_blaster_god_final.py

from scapy.all import IP, TCP, send
import ipaddress
import random
import time
import signal
import sys
import re

# Clean Ctrl+C
def stop(sig, frame):
    print(f"\n\nCHAOS STOPPED BY USER!")
    print(f"Total packets sent: {sent:,}")
    sys.exit(0)
signal.signal(signal.SIGINT, stop)

print("""
  ███████╗ █████╗ ███████╗████████╗    ████████╗ ██████╗██████╗ 
  ██╔════╝██╔══██╗██╔════╝╚══██╔══╝    ╚══██╔══╝██╔════╝██╔══██╗
  █████╗  ███████║███████╗   ██║          ██║   ██║     ██████╔╝
  ██╔══╝  ██╔══██║╚════██║   ██║          ██║   ██║     ██╔═══╝ 
  ██║     ██║  ██║███████║   ██║          ██║   ╚██████╗██║     
  ╚═╝     ╚═╝  ╚═╝╚══════╝   ╚═╝          ╚═╝    ╚═════╝╚═╝     
                                                                by abd0xa23(AR)                 
                                                                
                                                                
                                                                
                                                                                       """)

# ============== IP INPUT + PARSING ==============
def parse_ip_input(user_input):
    user_input = user_input.strip()
    ips = []

    # Format 1: CIDR (192.168.1.0/24)
    if '/' in user_input:
        try:
            net = ipaddress.ip_network(user_input, strict=False)
            ips = [str(ip) for ip in net.hosts()] if net.num_addresses > 1 else [str(net.network_address)]
            print(f"CIDR detected → {len(ips)} hosts")
            return ips
        except:
            pass

    # Format 2: Single IP (192.168.1.10)
    try:
        ipaddress.ip_address(user_input)
        print("Single IP detected")
        return [user_input]
    except:
        pass

    # Format 3: Range 192.168.3.10-225
    range_match = re.match(r'^(\d+\.\d+\.\d+)\.(\d+)-(\d+)$', user_input)
    if range_match:
        prefix = range_match.group(1)
        start = int(range_match.group(2))
        end = int(range_match.group(3))
        if 0 <= start <= end <= 255:
            ips = [f"{prefix}.{i}" for i in range(start, end + 1)]
            print(f"IP Range detected → {len(ips)} hosts ({start}-{end})")
            return ips

    print("Invalid IP format! Using loopback.")
    return ["127.0.0.1"]

# ============== USER INPUT ==============
target_input   = input("Target IP(s): 192.168.1.0/24 | 192.168.1.10 | 192.168.3.10-225 → ").strip()
srcport_input  = input("Source Port (5000-6000 or 8080 or Enter=RANDOM): ").strip()
ports_input    = input("Target Port(s) (ex: 80 or 22,80,443 or 1-1000): ").strip()
flags_input    = input("TCP Flags (S,SA,A,RA,F,FA,PA) [default S]: ").strip().upper() or "S"
delay_ms       = float(input("Delay ms (0 = max speed): ").strip() or "0")


# ============== PARSE IPs ==============
all_ips = parse_ip_input(target_input)

# ============== SOURCE PORT ==============
src_ports = None
if srcport_input:
    try:
        if "-" in srcport_input:
            s, e = map(int, srcport_input.split("-"))
            src_ports = list(range(s, e + 1))
            print(f"Source port range: {s}-{e}")
        else:
            src_ports = [int(srcport_input)]
            print(f"Source port fixed: {srcport_input}")
    except:
        src_ports = None
if not src_ports:
    print("Source port = RANDOM per packet")

# ============== TARGET PORTS ==============
def parse_ports(p):
    ports = set()
    for part in p.replace(" ", "").split(","):
        if "-" in part:
            s, e = map(int, part.split("-"))
            ports.update(range(s, e + 1))
        else:
            try: ports.add(int(part))
            except: pass
    return list(ports)

target_ports = parse_ports(ports_input) or [80]
print(f"Target ports: {target_ports}")

# ============== FLAGS ==============
flag_map = {"S":0x02,"SA":0x12,"A":0x10,"RA":0x14,"R":0x04,"F":0x01,"FA":0x11,"PA":0x18}
flags = sum(flag_map.get(f,0) for f in flags_input) or 0x02

# ============== CHAOS COMBOS + SHUFFLE ==============
combos = [(ip, port) for ip in all_ips for port in target_ports]
random.shuffle(combos)
total = len(combos)

print(f"\nTotal unique combos: {total:,}")
print("First 5 chaos targets:")
for i in range(min(5, total)):
    print(f"  → {combos[i][0]}:{combos[i][1]}")
print(f"\nSTARTING... Press Ctrl+C to stop!\n")
time.sleep(3)

# ============== BLAST ==============
sent = 0
for ip, port in combos:
    sport = random.choice(src_ports) if src_ports else random.randint(1024, 65535)
    pkt = IP(dst=ip) / TCP(sport=sport, dport=port, flags=flags)
    send(pkt, verbose=0)
    sent += 1

    if sent <= 5 or sent % 3000 == 0 or sent == total:
        print(f"Sent {sent:,}/{total:,} → {ip}:{port} (src_port={sport})")

    if delay_ms > 0:
        time.sleep(delay_ms / 1000.0)

print(f"\nMISSION COMPLETED!")
print(f"All {total:,} unique IP+Port combos blasted in pure random order!")
print("Undetectable | No pattern | Professional red team level!\n")
