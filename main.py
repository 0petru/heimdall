import argparse
import sys
import logging

from heimdall.utils import print_banner
from heimdall.sniffer import run_sniffer
from heimdall.rules import load_rules
from heimdall.detector import Detector
from heimdall.logger import AlertLogger
from heimdall.packet_logger import PacketLogger

def get_args():
    parser = argparse.ArgumentParser(description="Heimdall IDS - Live detector, sniffer, logger")

    # subcommands for mode-specific arguments
    sub = parser.add_subparsers(dest="mode", required=True, help="mode to run")

    sniffer = sub.add_parser("sniffer", help="Run packet sniffer")
    sniffer.add_argument("-i", "--iface", required=False, help="Interface name to sniff on")
    sniffer.add_argument("-n", "--count", type=int, default=0, help="Number of packets to capture (0=infinite)")
    sniffer.add_argument("-f", "--filter", default="", help="BPF filter string")
    sniffer.add_argument("-d", "--display", choices=["brief","verbose","hexdump","json","pcap"], default="brief", help="How to format each packet")
    sniffer.add_argument("-O", "--out", help="Output file for json/pcap")
    sniffer.add_argument("-ts", "--timestamps", action="store_true", help="Prepend packet timestamps to output")
    sniffer.add_argument("-li", "--list-interfaces", help="List available interfaces and exit", action="store_true")

    detector = sub.add_parser("detector", help="Run IDS detector on live traffic or pcap file")
    detector.add_argument("--rules", required=True, help="Path to rules file (.json or .yaml)")
    detector.add_argument("-i", "--iface", help="Interface to sniff on (for live traffic)")
    detector.add_argument("--pcap", help="PCAP file to read (offline mode)")
    detector.add_argument("--alert-out", help="Write alerts to file (default: stdout)")
    detector.add_argument("--alert-format", choices=["fast", "json"], default="fast", help="Alert output format")
    detector.add_argument("-n", "--count", type=int, default=0, help="Max packets to process (0=all)")

    logger = sub.add_parser("logger", help="Log packets to disk in multiple formats")
    logger.add_argument("--out", required=True, default="logs/", help="Output directory for logs")
    logger.add_argument("--format", choices=["pcap", "binary", "json"], default="pcap", help="Output format")
    logger.add_argument("--organize-by", choices=["date", "protocol", "src_ip", "dst_ip", "none"], default="date", help="Folder organization strategy")
    logger.add_argument("-i", "--iface", help="Interface to sniff on (for live traffic)")
    logger.add_argument("--pcap", help="PCAP file to read (offline mode)")
    logger.add_argument("-n", "--count", type=int, default=0, help="Max packets to process (0=all)")

    nids = sub.add_parser("nids", help="Run NIDS mode")
    nids.add_argument("--rules", required=True, help="Path to rules file")
    nids.add_argument("--alert", action="store_true", help="Enable alerting")

    return parser.parse_args()

def run_logger(args):
	"""Log packets to disk in various formats and folder structures."""
	logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
	
	# Create packet logger
	packet_logger = PacketLogger(
		output_dir=args.out,
		format=args.format,
		organize_by=args.organize_by
	)
	
	logging.info(f"Packet logger initialized: format={args.format}, organize_by={args.organize_by}, output={args.out}")
	
	# Determine mode: live or offline
	if args.pcap:
		_run_logger_offline(packet_logger, args.pcap, args.count)
	elif args.iface:
		_run_logger_live(packet_logger, args.iface, args.count)
	else:
		logging.error("Must specify either --iface (live) or --pcap (offline)")


def _run_logger_offline(logger: PacketLogger, pcap_file: str, count: int):
	"""Log packets from a pcap file."""
	try:
		from scapy.all import rdpcap
	except ImportError:
		logging.error("Scapy not installed. Install with: pip install scapy")
		return
	
	try:
		logging.info(f"Reading packets from {pcap_file}...")
		packets = rdpcap(pcap_file)
		
		if count > 0:
			packets = packets[:count]
		
		for i, pkt in enumerate(packets):
			logger.log_packet(pkt)
			if (i + 1) % 50 == 0:
				logging.info(f"Logged {i + 1}/{len(packets)} packets")
		
		logger.flush()
		logging.info(f"Completed: logged {len(packets)} packets to {logger.output_dir}")
	
	except FileNotFoundError:
		logging.error(f"PCAP file not found: {pcap_file}")
	except Exception as e:
		logging.error(f"Error reading PCAP: {e}")


def _run_logger_live(logger: PacketLogger, iface: str, count: int):
	"""Log packets from live traffic."""
	try:
		from scapy.all import sniff
	except ImportError:
		logging.error("Scapy not installed. Install with: pip install scapy")
		return
	
	pkt_count = [0]
	
	def _packet_handler(pkt):
		pkt_count[0] += 1
		logger.log_packet(pkt)
		if pkt_count[0] % 50 == 0:
			logging.info(f"Logged {pkt_count[0]} packets")
	
	try:
		logging.info(f"Starting packet capture on {iface}...")
		sniff(iface=iface, prn=_packet_handler, count=count if count > 0 else 0, store=False)
	except PermissionError:
		logging.error("Permission denied. Run as Administrator (Windows) or with sudo (Linux)")
	except KeyboardInterrupt:
		logging.info("\nCapture stopped by user")
	except Exception as e:
		logging.error(f"Error during capture: {e}")
	finally:
		logger.flush()
		logging.info(f"Completed: logged {pkt_count[0]} packets to {logger.output_dir}")


def run_detector(args):
	"""Run IDS detector on live traffic or pcap file."""
	logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
	
	# Load rules
	try:
		rules = load_rules(args.rules)
		logging.info(f"Loaded {len(rules)} rules from {args.rules}")
	except Exception as e:
		logging.error(f"Failed to load rules: {e}")
		return
	
	if not rules:
		logging.error("No rules loaded!")
		return
	
	# Create detector and logger
	detector = Detector(rules)
	alert_logger = AlertLogger(
		output_file=args.alert_out,
		format=args.alert_format
	)
	
	# Determine mode: live or offline
	if args.pcap:
		_run_detector_offline(detector, alert_logger, args.pcap, args.count)
	elif args.iface:
		_run_detector_live(detector, alert_logger, args.iface, args.count)
	else:
		logging.error("Must specify either --iface (live) or --pcap (offline)")


def _run_detector_offline(detector: Detector, logger: AlertLogger, pcap_file: str, count: int):
	"""Run detector on a pcap file."""
	try:
		from scapy.all import rdpcap
	except ImportError:
		logging.error("Scapy not installed. Install with: pip install scapy")
		return
	
	try:
		logging.info(f"Reading packets from {pcap_file}...")
		packets = rdpcap(pcap_file)
		
		if count > 0:
			packets = packets[:count]
		
		alert_count = 0
		for i, pkt in enumerate(packets):
			alerts = detector.detect(pkt)
			if alerts:
				logger.log_alerts(alerts)
				alert_count += len(alerts)
		
		logging.info(f"Processed {len(packets)} packets, found {alert_count} alerts")
	
	except FileNotFoundError:
		logging.error(f"PCAP file not found: {pcap_file}")
	except Exception as e:
		logging.error(f"Error reading PCAP: {e}")


def _run_detector_live(detector: Detector, logger: AlertLogger, iface: str, count: int):
	"""Run detector on live traffic."""
	try:
		from scapy.all import sniff
	except ImportError:
		logging.error("Scapy not installed. Install with: pip install scapy")
		return
	
	pkt_count = [0]  # mutable counter
	alert_count = [0]
	
	def _packet_handler(pkt):
		pkt_count[0] += 1
		alerts = detector.detect(pkt)
		if alerts:
			logger.log_alerts(alerts)
			alert_count[0] += len(alerts)
	
	try:
		logging.info(f"Starting live capture on {iface}...")
		sniff(iface=iface, prn=_packet_handler, count=count if count > 0 else 0, store=False)
	except PermissionError:
		logging.error("Permission denied. Run as Administrator (Windows) or with sudo (Linux)")
	except KeyboardInterrupt:
		logging.info("\nCapture stopped by user")
	except Exception as e:
		logging.error(f"Error during capture: {e}")
	finally:
		logging.info(f"Processed {pkt_count[0]} packets, found {alert_count[0]} alerts")


def run_nids(args):
	print("running nids")
	print(f"rules={args.rules} alert={args.alert}")


def main():
	NO_ARGS_MESSAGE = "No mode provided. Run with -h for help."

	if len(sys.argv) == 1:
		print_banner()
		print(NO_ARGS_MESSAGE)
		return

	args = get_args()

	if args.mode == "sniffer":
		run_sniffer(args)
	elif args.mode == "detector":
		run_detector(args)
	elif args.mode == "logger":
		run_logger(args)
	elif args.mode == "nids":
		run_nids(args)

if __name__ == "__main__":
	main()