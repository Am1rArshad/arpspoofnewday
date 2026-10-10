"""Start the API bound to the configured dashboard network interface."""
import ipaddress
import socket

import psutil
import uvicorn

import database


def interface_ipv4(interface):
    for address in psutil.net_if_addrs().get(interface, []):
        if address.family != socket.AF_INET:
            continue
        try:
            return str(ipaddress.ip_address(address.address))
        except ValueError:
            continue
    return None


def main():
    database.init_db()
    config = database.get_config()
    interface = config.get("dashboard_interface", "ens37")
    host = interface_ipv4(interface)
    if not host:
        raise SystemExit(
            f"No IPv4 address found on dashboard interface {interface!r}. "
            "Configure the interface or assign it an IPv4 address."
        )
    print(f"Dashboard/API binding to {interface} ({host})", flush=True)
    uvicorn.run("main:app", host=host, port=8000)


if __name__ == "__main__":
    main()