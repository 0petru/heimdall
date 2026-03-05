from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from scapy.packet import Packet
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.inet6 import IPv6

from heimdall.rules import Rule, RuleLoadError


@dataclass
class Alert:
	"""Represents a matched rule detection."""
	rule_id: int
	rule_msg: str
	priority: int
	timestamp: datetime
	src_ip: str
	dst_ip: str
	src_port: int | str
	dst_port: int | str
	proto: str
	matched_content: str
	
	def to_fast_format(self) -> str:
		"""single-line alert format"""
		return (
			f"[{self.timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}] "
			f"[**] [{self.rule_id}:1] {self.rule_msg} "
			f"{{{self.proto.upper()}}} "
			f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} "
			f"[Priority: {self.priority}]"
		)


@dataclass
class Event:
	"""Normalized packet event for rule matching."""
	timestamp: datetime
	src_ip: str
	dst_ip: str
	src_port: int | str
	dst_port: int | str
	proto: str
	payload: str = ""
	raw_packet: Packet = field(default=None, repr=False, compare=False)


class Detector:
	"""Evaluates normalized events against IDS rules."""
	
	def __init__(self, rules: list[Rule]):
		self.rules = rules
	
	def normalize_packet(self, packet: Packet) -> Event | None:
		"""Convert Scapy packet to normalized Event."""
		try:
			timestamp = datetime.utcnow()
			
			# Extract IP layer
			src_ip = "unknown"
			dst_ip = "unknown"
			proto_name = "ip"
			
			if IP in packet:
				ip_layer = packet[IP]
				src_ip = ip_layer.src
				dst_ip = ip_layer.dst
			elif IPv6 in packet:
				ip_layer = packet[IPv6]
				src_ip = ip_layer.src
				dst_ip = ip_layer.dst
			else:
				return None  # Skip non-IP packets
			
			# Extract transport layer and ports
			src_port: int | str = "any"
			dst_port: int | str = "any"
			payload = ""
			
			if TCP in packet:
				proto_name = "tcp"
				tcp_layer = packet[TCP]
				src_port = tcp_layer.sport
				dst_port = tcp_layer.dport
				if tcp_layer.payload:
					payload = bytes(tcp_layer.payload).decode("utf-8", errors="ignore")
			
			elif UDP in packet:
				proto_name = "udp"
				udp_layer = packet[UDP]
				src_port = udp_layer.sport
				dst_port = udp_layer.dport
				if udp_layer.payload:
					payload = bytes(udp_layer.payload).decode("utf-8", errors="ignore")
			
			elif ICMP in packet:
				proto_name = "icmp"
				icmp_layer = packet[ICMP]
				if icmp_layer.payload:
					payload = bytes(icmp_layer.payload).decode("utf-8", errors="ignore")
			
			return Event(
				timestamp=timestamp,
				src_ip=src_ip,
				dst_ip=dst_ip,
				src_port=src_port,
				dst_port=dst_port,
				proto=proto_name,
				payload=payload,
				raw_packet=packet,
			)
		
		except Exception as e:
			# Skip malformed packets
			return None
	
	def match_event(self, event: Event) -> list[Alert]:
		"""Evaluate event against rules, return matched alerts."""
		alerts = []
		
		for rule in self.rules:
			# Protocol match
			if rule.proto not in ("any", event.proto):
				continue
			
			# Source IP match (simple: accept any/lowercase)
			if rule.src not in ("any",) and rule.src != event.src_ip.lower():
				continue
			
			# Destination IP match
			if rule.dst not in ("any",) and rule.dst != event.dst_ip.lower():
				continue
			
			# Source port match
			if not self._port_matches(event.src_port, rule.src_port):
				continue
			
			# Destination port match
			if not self._port_matches(event.dst_port, rule.dst_port):
				continue
			
			# Content match (substring search in payload)
			matched_content = event.payload
			if rule.content:
				if rule.content.lower() not in event.payload.lower():
					continue
				matched_content = rule.content
			
			# All conditions passed, create alert
			alert = Alert(
				rule_id=rule.id,
				rule_msg=rule.msg,
				priority=rule.priority,
				timestamp=event.timestamp,
				src_ip=event.src_ip,
				dst_ip=event.dst_ip,
				src_port=event.src_port,
				dst_port=event.dst_port,
				proto=event.proto,
				matched_content=matched_content,
			)
			alerts.append(alert)
		
		return alerts
	
	@staticmethod
	def _port_matches(event_port: int | str, rule_port: int | str) -> bool:
		"""Check if event port matches rule port."""
		if rule_port == "any":
			return True
		if event_port == "any":
			return False
		return event_port == rule_port
	
	def detect(self, packet: Packet) -> list[Alert]:
		"""One-shot: normalize packet and match rules."""
		event = self.normalize_packet(packet)
		if event is None:
			return []
		return self.match_event(event)
