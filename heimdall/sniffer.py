import sys
import threading
import queue
import logging
import json
from datetime import datetime
from ._imports import _lazy_import_compile_filter, _lazy_import_dev_from_index, _lazy_import_hexdump, _lazy_import_pcapwriter, _lazy_import_show_interfaces, _lazy_import_sniff

# bounded queue for packets
_PKT_QUEUE = queue.Queue(maxsize=20000)

def _pkt_to_json(pkt):
    layers = []
    layer = pkt
    while layer:
        fields = {k: repr(v) for k, v in getattr(layer, "fields", {}).items()}
        layers.append({getattr(layer, "name", str(type(layer))): fields})
        layer = getattr(layer, "payload", None)
        if not layer:
            break
    return json.dumps(layers, default=str)


def _packet_timestamp(pkt):
    pkt_time = getattr(pkt, "time", None)
    if pkt_time is None:
        return datetime.now().isoformat(timespec="milliseconds")
    try:
        return datetime.fromtimestamp(float(pkt_time)).isoformat(timespec="milliseconds")
    except Exception:
        return datetime.now().isoformat(timespec="milliseconds")


def _format_verbose_packet(pkt, timestamps=False):
    try:
        pkt_len = len(bytes(pkt))
    except Exception:
        pkt_len = "unknown"

    header = f"{pkt.summary()} | len={pkt_len}"
    if timestamps:
        header = f"[{_packet_timestamp(pkt)}] {header}"

    detail = pkt.show(dump=True)
    separator = "-" * 80
    return f"{separator}\n{header}\n{separator}\n{detail}"


def _handle_packet_output(pkt, display, out_path=None, pcap_writer=None, timestamps=False):
    try:
        if display == "pcap" and pcap_writer is not None:
            pcap_writer.write(pkt)
            return

        if display == "verbose":
            s = _format_verbose_packet(pkt, timestamps)
        elif display == "hexdump":
            # produce a hex string
            hexdump_fn = _lazy_import_hexdump()
            if hexdump_fn is not None:
                s = hexdump_fn(pkt, dump=True)
            else:
                s = bytes(pkt).hex()
        elif display == "json":
            s = _pkt_to_json(pkt)
        else:  # brief
            s = pkt.summary()

        if timestamps and display != "verbose":
            s = f"[{_packet_timestamp(pkt)}] {s}"

        if out_path and display != "pcap":
            with open(out_path, "a", encoding="utf-8") as f:
                f.write(s + "\n")
        else:
            print(s)
    except Exception:
        logging.exception("Error while formatting/writing packet")


def _worker(display, out_path, timestamps=False):
    PcapWriter = _lazy_import_pcapwriter()
    pcap_writer = None
    if display == "pcap":
        if out_path is None:
            logging.error("pcap output requires --out <file>")
            return
        if PcapWriter is None:
            logging.error("scapy.utils.PcapWriter not available; install scapy")
            return

    while True:
        pkt = _PKT_QUEUE.get()
        if pkt is None:
            break
        if display == "pcap":
            if pcap_writer is None:
                try:
                    pcap_writer = PcapWriter(out_path, append=True, sync=True)
                except Exception:
                    logging.exception("Failed to open pcap writer")
                    continue
            try:
                pcap_writer.write(pkt)
            except Exception:
                logging.exception("Failed to write packet to pcap")
            continue
        _handle_packet_output(pkt, display, out_path, pcap_writer, timestamps)
    if pcap_writer:
        try:
            pcap_writer.close()
        except Exception:
            logging.exception("Failed to close pcap writer")

# creates and starts a background worker thread
def _start_worker(display, out_path, timestamps=False):
    t = threading.Thread(target=_worker, args=(display, out_path, timestamps), daemon=True)
    t.start()
    return t


def run_sniffer(args):
    """Run sniffer

    Expects args to have attributes: list_interfaces, iface, count, display, out
    """
    logging.basicConfig(level=logging.INFO)
    display = getattr(args, "display", "brief")
    out_path = getattr(args, "out", None)
    timestamps = getattr(args, "timestamps", False)

    # handle list interfaces and exit
    if getattr(args, "list_interfaces", False):
        listInterfaces()
        return

    sniff = _lazy_import_sniff()
    if sniff is None:
        logging.error("Scapy not installed; install with: python -m pip install scapy")
        return

    def _enqueue(pkt):
        try:
            _PKT_QUEUE.put_nowait(pkt)
        except queue.Full:
            logging.warning("packet queue full, dropping packet")

    try:
        iface = getattr(args, "iface", None)
        filter_expr = getattr(args, "filter", "")
        if isinstance(filter_expr, str):
            filter_expr = filter_expr.strip().lower()
        filter_check = verifyFilter(filter_expr)

        if not filter_check:
            logging.error("Incorrect filter format!")
            return

        # start worker only after validations pass
        worker = _start_worker(display, out_path, timestamps)

        if iface is None:
            sniff(prn=_enqueue, count=getattr(args, "count", 0), filter=filter_expr)
        else:
            if sys.platform == "win32":
                dev_from_index = _lazy_import_dev_from_index()
                try:
                    # accept numeric index or name
                    if isinstance(iface, str) and iface.isdigit():
                        iface = dev_from_index(int(iface)) if dev_from_index else iface
                except Exception:
                    logging.exception("Failed to resolve interface index")
                sniff(iface=iface, prn=_enqueue, count=getattr(args, "count", 0), filter=filter_expr)
            else:
                sniff(iface=iface, prn=_enqueue, count=getattr(args, "count", 0), filter=filter_expr)
    except KeyboardInterrupt:
        logging.info("Stopping capture (KeyboardInterrupt)")
    except PermissionError:
        logging.error("Permission denied while capturing. Run as Administrator and ensure Npcap is installed on Windows.")
    except Exception:
        logging.exception("Error while sniffing")
    finally:
        # signal worker to stop and wait
        if 'worker' in locals() and worker is not None:
            _PKT_QUEUE.put(None)
            worker.join()

def verifyFilter(filter_string):

    if filter_string == "" or filter_string == None:
        return True
    
    try: 
        compile_filter = _lazy_import_compile_filter()
        if compile_filter is None:
            return True
        compile_filter(filter_string)
        return True
    except Exception as e:
        logging.exception(f"[-] Invalid Filter Syntax: '{filter_string}'\nError: {e}")
        return False


# displays all the interfaces
def listInterfaces():
    show_interfaces = _lazy_import_show_interfaces()
    if show_interfaces is None:
        logging.error("Scapy not installed; install with: python -m pip install scapy")
        return
    try:
        show_interfaces()
    except Exception:
        logging.exception("Failed to list interfaces")