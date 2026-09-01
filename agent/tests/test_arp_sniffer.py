"""The passive ARP sniffer's packet handler."""

import pytest
from scapy.all import ARP, Ether

from cherubyte_agent import arp_sniffer


@pytest.fixture(autouse=True)
def _clean():
    arp_sniffer._hosts.clear()
    yield
    arp_sniffer._hosts.clear()


def _who_has(mac: str, ip: str, target_ip: str = "192.168.1.1"):
    return (
        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=1, hwsrc=mac, psrc=ip, pdst=target_ip)
    )


def _is_at(mac: str, ip: str, dst_mac: str = "aa:bb:cc:00:00:99"):
    return Ether(src=mac, dst=dst_mac) / ARP(op=2, hwsrc=mac, psrc=ip)


def test_a_request_records_its_sender():
    arp_sniffer._handle(_who_has("11:22:33:44:55:66", "192.168.1.50"))
    hosts = arp_sniffer.all_hosts()
    assert "11:22:33:44:55:66" in hosts
    assert hosts["11:22:33:44:55:66"].ip == "192.168.1.50"


def test_a_reply_records_its_sender_too():
    arp_sniffer._handle(_is_at("aa:bb:cc:dd:ee:ff", "192.168.1.77"))
    hosts = arp_sniffer.all_hosts()
    assert hosts["aa:bb:cc:dd:ee:ff"].ip == "192.168.1.77"


def test_a_dad_probe_from_the_unspecified_address_is_ignored():
    arp_sniffer._handle(_who_has("11:22:33:44:55:66", "0.0.0.0"))
    assert arp_sniffer.all_hosts() == {}


def test_a_later_sighting_overwrites_the_ip():
    arp_sniffer._handle(_who_has("11:22:33:44:55:66", "192.168.1.50"))
    arp_sniffer._handle(_who_has("11:22:33:44:55:66", "192.168.1.51"))
    hosts = arp_sniffer.all_hosts()
    assert len(hosts) == 1
    assert hosts["11:22:33:44:55:66"].ip == "192.168.1.51"


def test_two_hosts_are_both_kept():
    arp_sniffer._handle(_who_has("11:22:33:44:55:66", "192.168.1.50"))
    arp_sniffer._handle(_is_at("aa:bb:cc:dd:ee:ff", "192.168.1.77"))
    assert set(arp_sniffer.all_hosts()) == {"11:22:33:44:55:66", "aa:bb:cc:dd:ee:ff"}
