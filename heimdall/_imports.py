def _lazy_import_show_interfaces():
    try:
        from scapy.all import show_interfaces
        return show_interfaces
    except ImportError:
        return None
    
def _lazy_import_compile_filter():
    try:
        from scapy.all import compile_filter
        return compile_filter
    except ImportError:
        return None


def _lazy_import_sniff():
    try:
        from scapy.all import sniff
        return sniff
    except ImportError:
        return None


def _lazy_import_dev_from_index():
    try:
        from scapy.all import dev_from_index
        return dev_from_index
    except ImportError:
        return None


def _lazy_import_hexdump():
    try:
        from scapy.all import hexdump
        return hexdump
    except ImportError:
        return None


def _lazy_import_pcapwriter():
    try:
        from scapy.utils import PcapWriter
        return PcapWriter
    except Exception:
        return None