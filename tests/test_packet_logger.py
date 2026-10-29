"""Tests for packet folder organization in PacketLogger."""

import pytest

from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether

from heimdall.packet_logger import PacketLogger, _safe_folder_name

# IPv6 addresses contain ':' which is replaced to keep folder names portable.
_v6_src = _safe_folder_name("fe80::1")
_v6_dst = _safe_folder_name("fe80::2")


def _subfolders(output_dir):
	"""Return names of subdirectories created under output_dir."""
	return sorted(p.name for p in output_dir.iterdir() if p.is_dir())


@pytest.fixture
def ipv4_packet():
	return Ether() / IP(src="192.168.1.10", dst="10.0.0.1")


@pytest.fixture
def ipv6_packet():
	return Ether() / IPv6(src="fe80::1", dst="fe80::2")


@pytest.mark.parametrize("organize_by", ["src_ip", "dst_ip"])
def test_ipv4_is_filed_under_address(tmp_path, ipv4_packet, organize_by):
	logger = PacketLogger(tmp_path, format="binary", organize_by=organize_by)
	logger.log_packet(ipv4_packet)

	expected = ipv4_packet[IP].src if organize_by == "src_ip" else ipv4_packet[IP].dst
	assert _subfolders(tmp_path) == [expected]


@pytest.mark.parametrize("organize_by", ["src_ip", "dst_ip"])
def test_ipv6_is_filed_under_address(tmp_path, ipv6_packet, organize_by):
	"""Regression: IPv6 packets were filed under 'unknown' instead of their address."""
	logger = PacketLogger(tmp_path, format="binary", organize_by=organize_by)
	logger.log_packet(ipv6_packet)

	expected = _v6_src if organize_by == "src_ip" else _v6_dst
	assert _subfolders(tmp_path) == [expected]
	assert "unknown" not in _subfolders(tmp_path)


def test_non_ip_packet_falls_back_to_unknown(tmp_path):
	logger = PacketLogger(tmp_path, format="binary", organize_by="src_ip")
	logger.log_packet(Ether())

	assert _subfolders(tmp_path) == ["unknown"]


def test_ipv6_address_is_path_safe(tmp_path, ipv6_packet):
	"""IPv6 addresses contain ':', which must not create nested folders."""
	logger = PacketLogger(tmp_path, format="binary", organize_by="src_ip")
	logger.log_packet(ipv6_packet)

	folder = next(p for p in tmp_path.iterdir() if p.is_dir())
	assert folder.is_dir()
	# No nesting created by the ':' separators
	assert len(list(folder.iterdir())) == 1


def test_outer_header_wins_when_both_versions_present(tmp_path):
	"""An IPv6 packet tunnelling IPv4 is filed under the outer IPv6 address."""
	logger = PacketLogger(tmp_path, format="binary", organize_by="src_ip")
	logger.log_packet(IPv6(src="fe80::3") / IP(src="1.2.3.4"))

	assert _subfolders(tmp_path) == [_safe_folder_name("fe80::3")]


def test_ipv6_zone_id_does_not_break_folder(tmp_path):
	"""Scoped IPv6 addresses must still map to a single, flat folder."""
	logger = PacketLogger(tmp_path, format="binary", organize_by="src_ip")
	logger.log_packet(IPv6(src="fe80::1%3") / IP(src="1.2.3.4"))

	assert _subfolders(tmp_path) == [_safe_folder_name(str(IPv6(src="fe80::1%3").src))]
	# Whatever the scope renders as, the name must be safe for every OS
	assert not any(c in _subfolders(tmp_path)[0] for c in ':%<>"/\\|?*')
