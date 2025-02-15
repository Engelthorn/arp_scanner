#!/usr/bin/python3.12
from argparse import ArgumentParser
from scapy.layers.l2 import Ether, ARP, srp


def get_args():
    """Input arguments from user."""
    parser = ArgumentParser()
    parser.add_argument("-i", "--interface", help="An interface.")
    parser.add_argument("-t", "--target", help="Target's IP address or range (/24).")
    args = parser.parse_args()
    if not args.interface:
        parser.error("\n[-] Specify an interface. Ex: eth0, en0, wlan0.")
    elif not args.target:
        parser.error("\n[-] Please specify target's IP. Only IPv4. Use --help to get more info.")
    return args


def scanning(interface, target_ip):
    """Send broadcast request to all LAN machines than extracts MAC addresses from victims IPv4 range"""
    print(f"\n[!] Using interface: {interface}")
    brd_arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip)
    answered_list = srp(brd_arp_request, verbose=0, timeout=1)[0]

    target_list = []
    for target in answered_list:
        target_dict = {"ip": target[1].psrc, "mac": target[1].hwsrc}
        target_list.append(target_dict)
    return target_list


def show(results):
    """Outputs formatted results (IP addresses & MAC)"""
    print("\nIP\t\t\t\t\tMAC"
          "\n-------------------------------------------------------")
    for res in results:
        print(f"{res['ip']}\t\t\t\t{res['mac']}")
    print("-------------------------------------------------------")


user_args = get_args()
scan_results = scanning(user_args.interface, user_args.target)
