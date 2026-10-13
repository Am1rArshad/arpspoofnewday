#!/usr/bin/env python3
"""Controlled ARP IDS test traffic for an authorized isolated lab.

The IDS evaluates rules before ML. ML severity is model-dependent and is not guaranteed.
"""

import argparse
import ipaddress
import sys
import time

from scapy.all import ARP, Ether, sendp


DEFAULT_ATTACKER_IP = "192.168.122.148"
DEFAULT_VICTIM_IP = "192.168.122.139"
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
ZERO_MAC = "00:00:00:00:00:00"


def lab_ip(args, slot):
    network = ipaddress.ip_network(f"{args.attacker_ip}/24", strict=False)
    candidates = [str(address) for address in network.hosts()]
    excluded = {args.attacker_ip, args.victim_ip}
    return [address for address in candidates if address not in excluded][slot]


def stable_mac(slot, variant=0):
    return f"02:aa:bb:{slot:02x}:{variant:02x}:01"


def send_packet(packet, args):
    sendp(packet, iface=args.interface, verbose=False)


def send_request(args, source_ip, source_mac, target_ip):
    send_packet(
        Ether(src=source_mac, dst=BROADCAST_MAC)
        / ARP(op=1, psrc=source_ip, pdst=target_ip, hwsrc=source_mac),
        args,
    )


def send_directed_reply(args, source_ip, source_mac):
    """Directed reply: source IP differs from target IP and Ethernet is unicast."""
    send_packet(
        Ether(src=source_mac, dst=args.victim_mac)
        / ARP(
            op=2,
            psrc=source_ip,
            pdst=args.victim_ip,
            hwsrc=source_mac,
            hwdst=args.victim_mac,
        ),
        args,
    )


def send_gratuitous_reply(args, source_ip, source_mac):
    send_packet(
        Ether(src=source_mac, dst=BROADCAST_MAC)
        / ARP(op=2, psrc=source_ip, pdst=source_ip, hwsrc=source_mac, hwdst=ZERO_MAC),
        args,
    )


def rule_low(args):
    """More than 20 requests in 60 seconds -> ARP_SCAN / Low."""
    source_ip = lab_ip(args, 0)
    source_mac = stable_mac(0x10)
    targets = [f"192.168.122.{host}" for host in range(1, 23)]
    targets = [target for target in targets if target not in {source_ip, args.victim_ip}]
    for target_ip in targets[:21]:
        send_request(args, source_ip, source_mac, target_ip)
        time.sleep(0.08)


def rule_medium(args):
    """Same IP with a new MAC -> MAC_CHURN / Medium."""
    source_ip = lab_ip(args, 1)
    send_directed_reply(args, source_ip, stable_mac(0x20, 0))
    time.sleep(1)
    send_directed_reply(args, source_ip, stable_mac(0x20, 1))


def rule_high(args):
    """Four gratuitous replies in 30 seconds -> UNSOLICITED_ARP / High."""
    source_ip = lab_ip(args, 2)
    source_mac = stable_mac(0x30)
    for _ in range(4):
        send_gratuitous_reply(args, source_ip, source_mac)
        time.sleep(0.25)


def ml_low(args):
    """Ordinary request; no rule should match."""
    source_ip = lab_ip(args, 3)
    send_request(args, source_ip, stable_mac(0x40), args.victim_ip)


def ml_medium(args):
    """Directed replies; avoids gratuitous and MAC churn rules."""
    source_ip = lab_ip(args, 4)
    source_mac = stable_mac(0x50)
    for _ in range(2):
        send_directed_reply(args, source_ip, source_mac)
        time.sleep(0.5)


def ml_high(args):
    """Fast directed replies; ML score remains model-dependent."""
    source_ip = lab_ip(args, 5)
    source_mac = stable_mac(0x60)
    for _ in range(3):
        send_directed_reply(args, source_ip, source_mac)
        time.sleep(0.08)


OPTIONS = {
    "1": ("Rule Low - ARP scan -> ARP_SCAN / Low", rule_low),
    "2": ("Rule Medium - directed MAC churn -> MAC_CHURN / Medium", rule_medium),
    "3": ("Rule High - gratuitous burst -> UNSOLICITED_ARP / High", rule_high),
    "4": ("ML Low - ordinary request -> no rule; model-dependent", ml_low),
    "5": ("ML Medium - directed replies -> no rule; model-dependent", ml_medium),
    "6": ("ML High - directed burst -> no rule; model-dependent", ml_high),
}


def parse_args():
    parser = argparse.ArgumentParser(description="Authorized ARP IDS network test")
    parser.add_argument("--interface", required=True, help="Attacker interface, e.g. eth0")
    parser.add_argument("--victim-mac", required=True, help="Victim IDS MAC for directed tests")
    parser.add_argument("--attacker-ip", default=DEFAULT_ATTACKER_IP)
    parser.add_argument("--victim-ip", default=DEFAULT_VICTIM_IP)
    return parser.parse_args()


def main():
    args = parse_args()
    print("Authorized isolated-lab ARP IDS tester")
    print(f"Attacker network: {args.attacker_ip}  Victim: {args.victim_ip}")
    print(f"Interface: {args.interface}  Victim MAC: {args.victim_mac}")
    for key, (label, _) in OPTIONS.items():
        print(f"{key}. {label}")
    print("q. Quit")

    while True:
        choice = input("\nChoose a test: ").strip().lower()
        if choice == "q":
            return
        selected = OPTIONS.get(choice)
        if selected is None:
            print("Choose 1-6 or q.")
            continue
        label, action = selected
        print(f"Running: {label}")
        try:
            action(args)
        except PermissionError:
            print("Permission denied. Run with sudo and verify the interface.")
        except OSError as exc:
            print(f"Could not send packets: {exc}")
        else:
            print("Packets sent. Check the IDS alert stage and alert type.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")
        sys.exit(130)
