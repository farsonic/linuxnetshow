#!/usr/bin/python3
import subprocess
import json
import sys
from datetime import datetime, timedelta
import re
import ipaddress
import os

OUI_FILE_URL = "https://standards-oui.ieee.org/oui/oui.txt"
OUI_FILE_PATH = "/var/tmp/oui.txt"

def download_oui_file():
    if not os.path.exists(OUI_FILE_PATH):
        os.system(f"wget -O {OUI_FILE_PATH} {OUI_FILE_URL}")

def get_oui_vendor(mac_address):
    try:
        if not os.path.exists(OUI_FILE_PATH):
            download_oui_file()

        oui_prefix = mac_address.replace(':', '').upper()[:6]
        with open(OUI_FILE_PATH, 'r') as file:
            for line in file:
                if oui_prefix in line.replace('-', '').upper():
                    parts = line.split('\t')
                    if len(parts) >= 3:
                        return parts[2].strip()
        return "Unknown"
    except Exception as e:
        print(f"Error fetching OUI data: {e}")
        return "Unknown"
    
def format_speed(speed_str):
    match = re.match(r"(\d+)Mb/s", speed_str)
    if match:
        speed = int(match.group(1))
        if speed >= 1000:
            return f"{speed // 1000}Gb/s"
        return f"{speed}Mb/s"
    return speed_str

def get_interface_data(interface=None):
    link_cmd = f"ip --json -details link show {interface}" if interface else "ip --json link show"
    addr_cmd = f"ip --json -details addr show {interface}" if interface else "ip --json addr show"

    link_result = subprocess.run(link_cmd, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    addr_result = subprocess.run(addr_cmd, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if link_result.returncode != 0 or addr_result.returncode != 0:
        print(f"No such interface: {interface}")
        return None, None

    link_data = json.loads(link_result.stdout)
    addr_data = json.loads(addr_result.stdout)

    return link_data, addr_data

def get_last_change_time(interface):
    cmd = f"ip -details link show {interface}"
    result = subprocess.run(cmd, shell=True, text=True, stdout=subprocess.PIPE)
    match = re.search(r"link.*?(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", result.stdout)
    return datetime.strptime(match.group(1), '%Y-%m-%d %H:%M:%S') if match else None

def format_duration(td):
    days, remainder = divmod(td.total_seconds(), 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{int(days)} days, {int(hours)} hours, {int(minutes)} minutes, {int(seconds)} seconds"

def format_ip_address(addr_info):
    ip_with_prefix = f"{addr_info['local']}/{addr_info['prefixlen']}"
    subnet = calculate_subnet(ip_with_prefix)
    if 'broadcast' in addr_info and addr_info['family'] == 'inet':
        broadcast = addr_info['broadcast']
    else:
        broadcast = 'N/A'

    return f"{ip_with_prefix} (subnet: {subnet}, broadcast: {broadcast})"


def calculate_subnet(ip_with_prefix):
    network = ipaddress.ip_network(ip_with_prefix, strict=False)
    return str(network)

def get_link_speed(interface):
    cmd = f"ethtool {interface}"
    result = subprocess.run(cmd, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    match = re.search(r"Speed: (.+)", result.stdout)
    return format_speed(match.group(1)) if match else 'N/A'

def show_interface(interface):
    link_data, addr_data = get_interface_data(interface)
    if not link_data or not addr_data:
        return

    iface = link_data[0]
    mac = iface.get('address', 'N/A')
    ifindex = iface.get('ifindex', 'N/A')
    type = iface.get('link_type','N/A')
    operstate = iface.get('operstate', 'UNKNOWN').capitalize()
    mtu = iface.get('mtu', 'N/A')
    speed = get_link_speed(interface)
    ipv4 = ', '.join([format_ip_address(addr) for addr in addr_data[0]['addr_info'] if addr['family'] == 'inet'])
    ipv6 = ', '.join([format_ip_address(addr) for addr in addr_data[0]['addr_info'] if addr['family'] == 'inet6'])

    print(f"Interface: {interface}, Physical Link is {operstate}")
    print(f"  Interface index {ifindex}")
    print(f"  Type: {type}")
    print(f"  Link state: {operstate} since {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Speed: {speed}")
    print(f"  MTU: {mtu}")
    print(f"  MAC Address: {mac}")
    print(f"  IPv4 Address: {ipv4}")
    print(f"  IPv6 Address: {ipv6}")
    print("\n")



def show_all_interfaces():
    print("{:<18} {:<20} {:<12} {:<8} {:<20} {:<40}".format("Interface", "MAC", "Operstate", "Admin", "IPv4", "IPv6"))
    print("=" * 112)

    link_data, addr_data = get_interface_data()

    for iface in link_data:
        interface = iface['ifname']
        mac = iface.get('address', 'N/A')
        operstate = iface.get('operstate', 'UNKNOWN')
        admin_state = 'UP' if 'UP' in iface['flags'] else 'DOWN'

        ipv4_addrs = [f"{addr['local']}/{addr['prefixlen']}" for item in addr_data if item['ifname'] == interface for addr in item['addr_info'] if addr['family'] == 'inet']
        ipv6_addrs = [f"{addr['local']}/{addr['prefixlen']}" for item in addr_data if item['ifname'] == interface for addr in item['addr_info'] if addr['family'] == 'inet6']

        ipv4 = ', '.join(ipv4_addrs)
        ipv6 = ', '.join(ipv6_addrs)

        print("{:<18} {:<20} {:<12} {:<8} {:<20} {:<40}".format(interface, mac, operstate, admin_state, ipv4, ipv6))


def show_mac():
    cmd = "ip --json -detail neigh"
    result = subprocess.run(cmd, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    neighbors = json.loads(result.stdout)

    print("{:<22} {:<20} {:<15} {:<15}".format("MAC Address", "Address", "Interface", "Vendor"))
    print("=" * 90)

    for neighbor in neighbors:
        mac = neighbor.get("lladdr", "N/A")
        address = neighbor.get("dst", "N/A")
        interface = neighbor.get("dev", "N/A")
        vendor = get_oui_vendor(mac) if mac != "N/A" else "N/A"
        print("{:<22} {:<20} {:<15} {:<15}".format(mac, address, interface, vendor))



def main():
    args = sys.argv[1:]

    if 'mac' in args:
        show_mac()
    elif 'int' in args or 'interface' in args:
        if len(args) > 1:
            interface = args[1]
            show_interface(interface)
        else:
            show_all_interfaces()
    else:
        print("Invalid command. Usage: 'show mac' or 'show interface [name]'")

if __name__ == "__main__":
    main()
