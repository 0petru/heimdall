"""Packet logger for storing traffic in multiple formats and folder structures."""

import logging
from pathlib import Path
from datetime import datetime
from typing import Literal
import json

from scapy.packet import Packet
from scapy.utils import wrpcap


class PacketLogger:
	"""Logs packets to disk in various formats and folder structures."""
	
	def __init__(
		self,
		output_dir: str | Path,
		format: Literal["pcap", "binary", "json"] = "pcap",
		organize_by: Literal["date", "protocol", "src_ip", "dst_ip", "none"] = "date",
	):
		"""
		Args:
			output_dir: Base directory for logs
			format: Output format ("pcap", "binary", "json")
			organize_by: How to organize packets in folders:
				- "date": logs/2026-03-05/packets.pcap
				- "protocol": logs/tcp/packets.pcap, logs/udp/packets.pcap
				- "src_ip": logs/192.168.1.1/packets.pcap
				- "dst_ip": logs/10.0.0.1/packets.pcap
				- "none": logs/packets.pcap (all in one)
		"""
		self.output_dir = Path(output_dir)
		self.format = format
		self.organize_by = organize_by
		self.logger = logging.getLogger("heimdall.packet_logger")
		
		# Create base directory
		self.output_dir.mkdir(parents=True, exist_ok=True)
		
		# Cache for open packet buffers (for pcap/binary accumulation)
		self._packet_buffers = {}  # key -> list of packets
		self._json_files = {}  # key -> file handle
	
	def _get_folder_path(self, packet: Packet) -> Path:
		"""Determine folder path based on organize_by strategy."""
		from scapy.layers.inet import IP, TCP, UDP, ICMP
		
		if self.organize_by == "none":
			return self.output_dir
		
		elif self.organize_by == "date":
			date_str = datetime.now().strftime("%Y-%m-%d")
			return self.output_dir / date_str
		
		elif self.organize_by == "protocol":
			proto = "other"
			if TCP in packet:
				proto = "tcp"
			elif UDP in packet:
				proto = "udp"
			elif ICMP in packet:
				proto = "icmp"
			return self.output_dir / proto
		
		elif self.organize_by == "src_ip":
			if IP in packet:
				src_ip = packet[IP].src
				return self.output_dir / src_ip
			return self.output_dir / "unknown"
		
		elif self.organize_by == "dst_ip":
			if IP in packet:
				dst_ip = packet[IP].dst
				return self.output_dir / dst_ip
			return self.output_dir / "unknown"
		
		return self.output_dir
	
	def _get_file_key(self, packet: Packet) -> str:
		"""Get unique key for grouping packets in same file."""
		folder = self._get_folder_path(packet)
		return str(folder)
	
	def log_packet(self, packet: Packet) -> None:
		"""Write a single packet."""
		file_key = self._get_file_key(packet)
		folder = Path(file_key)
		folder.mkdir(parents=True, exist_ok=True)
		
		if self.format == "pcap":
			self._log_pcap(packet, folder)
		elif self.format == "binary":
			self._log_binary(packet, folder)
		elif self.format == "json":
			self._log_json(packet, folder)
	
	def _log_pcap(self, packet: Packet, folder: Path) -> None:
		"""Append packet to pcap file."""
		pcap_file = folder / "packets.pcap"
		
		# Buffer packets and write in batches for efficiency
		if pcap_file not in self._packet_buffers:
			self._packet_buffers[pcap_file] = []
		
		self._packet_buffers[pcap_file].append(packet)
		
		# Flush every 100 packets
		if len(self._packet_buffers[pcap_file]) >= 100:
			self._flush_pcap(pcap_file)
	
	def _flush_pcap(self, pcap_file: Path) -> None:
		"""Write buffered packets to pcap file."""
		if pcap_file not in self._packet_buffers or not self._packet_buffers[pcap_file]:
			return
		
		packets = self._packet_buffers[pcap_file]
		try:
			if pcap_file.exists():
				# Read existing packets
				from scapy.all import rdpcap
				existing = rdpcap(str(pcap_file))
				packets = list(existing) + packets
			
			wrpcap(str(pcap_file), packets, append=False)
			self._packet_buffers[pcap_file] = []
			self.logger.debug(f"Flushed {len(packets)} packets to {pcap_file}")
		except Exception as e:
			self.logger.error(f"Error writing pcap {pcap_file}: {e}")
	
	def _log_binary(self, packet: Packet, folder: Path) -> None:
		"""Write packet as raw binary file."""
		timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]
		binary_file = folder / f"{timestamp}_pkt.bin"
		
		try:
			with open(binary_file, "wb") as f:
				f.write(bytes(packet))
			self.logger.debug(f"Wrote packet to {binary_file}")
		except Exception as e:
			self.logger.error(f"Error writing binary {binary_file}: {e}")
	
	def _log_json(self, packet: Packet, folder: Path) -> None:
		"""Append packet to JSON Lines file."""
		json_file = folder / "packets.jsonl"
		
		try:
			# Convert packet to dict-like structure
			packet_data = {
				"timestamp": datetime.now().isoformat(),
				"summary": packet.summary(),
				"length": len(bytes(packet)),
				"layers": self._packet_to_dict(packet),
			}
			
			with open(json_file, "a", encoding="utf-8") as f:
				f.write(json.dumps(packet_data, default=str) + "\n")
			
			self.logger.debug(f"Wrote packet to {json_file}")
		except Exception as e:
			self.logger.error(f"Error writing json {json_file}: {e}")
	
	@staticmethod
	def _packet_to_dict(packet: Packet) -> list:
		"""Convert packet layers to dict."""
		layers = []
		layer = packet
		while layer:
			try:
				fields = {k: repr(v)[:100] for k, v in getattr(layer, "fields", {}).items()}
				layers.append({
					"name": getattr(layer, "name", str(type(layer).__name__)),
					"fields": fields
				})
			except Exception:
				pass
			layer = getattr(layer, "payload", None)
			if not layer or (hasattr(layer, "__len__") and len(layer) == 0):
				break
		return layers
	
	def flush(self) -> None:
		"""Flush all buffered packets to disk."""
		for pcap_file in list(self._packet_buffers.keys()):
			self._flush_pcap(pcap_file)
		
		for json_file in self._json_files.values():
			try:
				json_file.close()
			except Exception:
				pass
		self._json_files.clear()
		
		self.logger.info("All packet buffers flushed")
	
	def log_packets(self, packets: list[Packet]) -> None:
		"""Write multiple packets."""
		for packet in packets:
			self.log_packet(packet)
