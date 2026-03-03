import argparse
import sys

from heimdall.utils import print_banner
from heimdall.sniffer import run_sniffer

def get_args():
    parser = argparse.ArgumentParser(description="Heimdall CLI with modes (sniffer, logger, nids)")

    # common options
    
    

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

    logger = sub.add_parser("logger", help="Run logger")
    logger.add_argument("--out", default="log.txt", help="Output logfile")
    logger.add_argument("--rotate", type=int, default=10, help="Rotate logs at this size (MB)")

    nids = sub.add_parser("nids", help="Run NIDS mode")
    nids.add_argument("--rules", required=True, help="Path to rules file")
    nids.add_argument("--alert", action="store_true", help="Enable alerting")

    return parser.parse_args()

def run_logger(args):
    print("running the logger")
    print(f"out={args.out} rotate={args.rotate}")


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
    elif args.mode == "logger":
        run_logger(args)
    elif args.mode == "nids":
        run_nids(args)

if __name__ == "__main__":
    main()