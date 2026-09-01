"""The Wake-on-LAN magic packet."""

from cherubyte_agent import wol


def test_magic_packet_shape():
    pkt = wol._packet("a4:83:e7:1c:2d:9f")
    assert pkt is not None
    assert len(pkt) == 6 + 16 * 6
    assert pkt[:6] == b"\xff\xff\xff\xff\xff\xff"
    mac = bytes.fromhex("a483e71c2d9f")
    assert pkt[6:] == mac * 16


def test_accepts_dash_separator_and_uppercase():
    assert wol._packet("A4-83-E7-1C-2D-9F") == wol._packet("a4:83:e7:1c:2d:9f")


def test_rejects_non_mac():
    assert wol._packet("not-a-mac") is None
    assert wol._packet("a4:83:e7:1c:2d") is None
    assert wol._packet("") is None


def test_send_returns_false_for_bad_mac(caplog):
    assert wol.send("nope") is False


def test_send_all_counts_successes(monkeypatch):
    sent = []
    monkeypatch.setattr(wol, "send", lambda m: (sent.append(m), True)[1])
    assert wol.send_all(["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"]) == 2
    assert sent == ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"]
