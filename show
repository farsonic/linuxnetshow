#!/usr/bin/python3
import subprocess
import json
import sys
from datetime import datetime, timedelta
import re

def get_interface_data(interface=None):
    link_cmd = f"ip --json link show {interface}" if interface else "ip --json link show"
    addr_cmd = f"ip --json addr show {interface}" if interface else "ip --json addr show"

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

def show_interface(interface):
    link_data, addr_data = get_interface_data(interface)
    if not link_data or not addr_data:
        return

    iface = link_data[0]
    mac = iface.get('address', 'N/A')
    operstate = iface.get('operstate', 'UNKNOWN').capitalize()
    mtu = iface.get('mtu', 'N/A')

    ipv4_addrs = [f"{addr['local']}/{addr['prefixlen']}" for addr in addr_data[0]['addr_info'] if addr['family'] == 'inet']
    ipv6_addrs = [f"{addr['local']}/{addr['prefixlen']}" for addr in addr_data[0]['addr_info'] if addr['family'] == 'inet6']

    ipv4 = ', '.join(ipv4_addrs) if ipv4_addrs else 'N/A'
    ipv6 = ', '.join(ipv6_addrs) if ipv6_addrs else 'N/A'

    print(f"Interface {interface} is {operstate}")
    print(f" Admin state is {operstate}")
    print(f" Link state: {operstate} for {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f" MAC Address: {mac}")
    print(f" MTU {mtu}")
    print(f" IPv4 Address: {ipv4}")
    print(f" IPv6 Address: {ipv6}")

    last_change = get_last_change_time(interface)
    if last_change:
        up_duration = datetime.now() - last_change
        up_time_str = format_duration(up_duration)
        print(f" Link has been {iface.get('operstate', 'UNKNOWN')} for {up_time_str}")
    else:
        print(" Unable to determine link up time.")

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

def main():
    args = sys.argv[1:]

    if 'int' in args or 'interface' in args:
        if len(args) > 1:
            interface = args[1]
            show_interface(interface)
        else:
            show_all_interfaces()

if __name__ == "__main__":
    main()
