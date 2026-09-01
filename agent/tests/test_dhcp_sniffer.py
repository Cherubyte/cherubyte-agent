"""The passive DHCP sniffer's packet handler."""

import pytest
from scapy.all import BOOTP, DHCP, Ether, IP, UDP

from cherubyte_agent import dhcp_sniffer


@pytest.fixture(autouse=True)
def _clean():
    dhcp_sniffer._prints.clear()
    dhcp_sniffer._servers.clear()
    yield
    dhcp_sniffer._prints.clear()
    dhcp_sniffer._servers.clear()


def _offer(server_ip: str, server_mac: str):
    return (
        Ether(src=server_mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src=server_ip, dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(op=2)
        / DHCP(options=[("message-type", "offer"), ("server_id", server_ip), "end"])
    )


def _discover(client_mac: str):
    return (
        Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(op=1, chaddr=bytes.fromhex(client_mac.replace(":", "")))
        / DHCP(options=[("message-type", "discover"), ("param_req_list", [1, 3, 6, 15]), "end"])
    )


def test_an_offer_records_the_server():
    dhcp_sniffer._handle(_offer("192.168.1.1", "aa:bb:cc:dd:ee:ff"))
    servers = dhcp_sniffer.all_servers()
    assert "192.168.1.1" in servers
    assert servers["192.168.1.1"].mac == "aa:bb:cc:dd:ee:ff"


def test_two_servers_are_both_kept():
    dhcp_sniffer._handle(_offer("192.168.1.1", "aa:bb:cc:00:00:01"))
    dhcp_sniffer._handle(_offer("192.168.1.66", "de:ad:be:ef:00:02"))
    assert set(dhcp_sniffer.all_servers()) == {"192.168.1.1", "192.168.1.66"}


def test_a_discover_is_a_fingerprint_not_a_server():
    dhcp_sniffer._handle(_discover("11:22:33:44:55:66"))
    assert dhcp_sniffer.all_servers() == {}
    assert dhcp_sniffer.get("11:22:33:44:55:66") is not None
