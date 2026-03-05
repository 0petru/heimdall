"""Alert logger for IDS detections."""

import json
import logging
from pathlib import Path
from heimdall.detector import Alert


class AlertLogger:
	"""Logs alerts in multiple formats."""
	
	def __init__(self, output_file: str | None = None, format: str = "fast"):
		"""
		Args:
			output_file: Path to write alerts. If None, writes to stdout.
			format: Alert format ("fast" = Snort-style line, "json" = JSON lines)
		"""
		self.output_file = output_file
		self.format = format
		self.logger = logging.getLogger("heimdall.alerts")
		
		if output_file:
			handler = logging.FileHandler(output_file, mode="a")
			handler.setLevel(logging.INFO)
			self.logger.addHandler(handler)
			self.logger.setLevel(logging.INFO)
	
	def log_alert(self, alert: Alert) -> None:
		"""Write a single alert."""
		if self.format == "json":
			alert_dict = {
				"timestamp": alert.timestamp.isoformat(),
				"rule_id": alert.rule_id,
				"msg": alert.rule_msg,
				"priority": alert.priority,
				"src": f"{alert.src_ip}:{alert.src_port}",
				"dst": f"{alert.dst_ip}:{alert.dst_port}",
				"proto": alert.proto,
				"matched_content": alert.matched_content,
			}
			line = json.dumps(alert_dict)
		else:  # fast format
			line = alert.to_fast_format()
		
		if self.output_file:
			self.logger.info(line)
		else:
			print(line)
	
	def log_alerts(self, alerts: list[Alert]) -> None:
		"""Write multiple alerts."""
		for alert in alerts:
			self.log_alert(alert)
