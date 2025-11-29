from scapy.all import IP, TCP, sr1
import nmap
import ipaddress
import time

def check_zombie_candidate(ip, zombie_port=80, count=3):
    ids = []
    print(f"[*] Probing {ip}:{zombie_port} for IP ID behavior...")

    for _ in range(count):
        pkt = IP(dst=ip)/TCP(dport=zombie_port, flags='SA')
        response = sr1(pkt, timeout=1, verbose=0)
        if response and response.haslayer(IP):
            ids.append(response[IP].id)
        else:
            print(f"[-] No response from {ip}, skipping.")
            return False
        time.sleep(1)

    if len(ids) >= 2 and all(ids[i+1] > ids[i] for i in range(len(ids)-1)):
        print(f"\n[+] {ip} shows predictable IP ID behavior (potential zombie).")
        return True
    else:
        print(f"[-] {ip} is not a suitable zombie.")
        return False

def find_zombie_in_range(ip_range, zombie_port):
    for ip in ipaddress.IPv4Network(ip_range, strict=False):
        ip_str = str(ip)
        if check_zombie_candidate(ip_str, zombie_port=zombie_port):
            print(f"\n[+] Zombie candidate found: {ip_str}")
            choice = input("Use this zombie IP? (y/n): ").strip().lower()
            if choice == 'y':
                return ip_str
            else:
                print("[*] Searching for next zombie...\n")
    return None


def zombie_scan(target, zombie_host, target_port, source_port):
    nm = nmap.PortScanner()
    print(f"\n[+] Launching Zombie scan with OS detection on {target}:{target_port} using zombie {zombie_host} and source port {source_port}...\n")
    try:
        # -g sets the source port; -sI sets the zombie host
        args = f'-sI {zombie_host} -p {target_port} -O -Pn -v -g {source_port}'
        nm.scan(hosts=target, arguments=args)

        for host in nm.all_hosts():
            print(f"\nHost: {host} ({nm[host].hostname()})")
            print(f"State: {nm[host].state()}")

            # Port scan result
            if 'tcp' in nm[host] and target_port in nm[host]['tcp']:
                port_data = nm[host]['tcp'][target_port]
                print(f"Port: {target_port}/tcp\tState: {port_data['state']}")
            else:
                print(f"Port {target_port} not found or filtered.")

            # OS Detection
            if 'osmatch' in nm[host]:
                print("\nOS Detection:")
                for os in nm[host]['osmatch']:
                    print(f" - {os['name']} ({os['accuracy']}% accuracy)")

            # MAC & Vendor
            if 'mac' in nm[host]['addresses']:
                mac = nm[host]['addresses']['mac']
                vendor = nm[host]['vendor'].get(mac, 'Unknown')
                print(f"\nMAC Address: {mac}")
                print(f"Vendor: {vendor}")

        return True
    except Exception as e:
        print(f"[-] Error during zombie scan: {e}")
        return False

if __name__ == "__main__":
    print("=== Zombie Scanner with OS & Hardware Info ===")
    zombie_range = input("Enter zombie IP range (e.g., 192.168.1.0/24): ")
    zombie_port = int(input("Enter port to probe zombie candidates (e.g., 80): "))
    target_port = int(input("Enter target port to scan (e.g., 22): "))
    target_ip = input("Enter target IP for zombie scan: ")
    source_port = int(input("Enter source port to use for the scan (e.g., 4444): "))

    zombie_ip = find_zombie_in_range(zombie_range, zombie_port)

    if zombie_ip:
        print(f"\n[+] Potential zombie found: {zombie_ip}")
        print("[*] Proceeding with zombie scan including OS and hardware info...\n")

        scan_success = zombie_scan(target_ip, zombie_ip, target_port, source_port)

        if not scan_success:
            print("[-] Zombie scan failed.")
    else:
        print("[-] No suitable zombie found in the given range.")
