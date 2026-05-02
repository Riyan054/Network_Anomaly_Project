"""
sniffer.py — Live packet capture using Scapy.

Run with:
    sudo python3 sniffer.py
"""

import os
import time
import sys
from scapy.all import sniff, IP, TCP, UDP, ICMP, conf

from database import init_db, insert_packet
from detector import detect
from config import INTERFACE, DB_PATH, STOP_FLAG, SNIFFER_PID

conf.verb = 0   # suppress scapy banner


# ── Interface auto-detection ───────────────────────────────────────────────────
def get_interface() -> str:
    if INTERFACE:
        return INTERFACE
    try:
        from scapy.arch import get_if_list
        ifaces = get_if_list()
        for preferred in ["en0", "en1", "eth0", "wlan0", "wlp2s0", "ens33"]:
            if preferred in ifaces:
                return preferred
        return ifaces[0] if ifaces else "en0"
    except Exception:
        return "en0"


# ── Packet parser ─────────────────────────────────────────────────────────────
def parse_packet(pkt) -> dict | None:
    try:
        if not pkt.haslayer(IP):
            return None

        ip       = pkt[IP]
        src_ip   = ip.src
        dst_ip   = ip.dst
        size     = len(pkt)
        ts       = time.time()
        src_port = dst_port = None
        protocol = "OTHER"
        flags    = ""

        if pkt.haslayer(TCP):
            tcp      = pkt[TCP]
            src_port = tcp.sport
            dst_port = tcp.dport
            protocol = "TCP"
            flag_map = {0x01: "F", 0x02: "S", 0x04: "R",
                        0x08: "P", 0x10: "A", 0x20: "U"}
            flags = "".join(v for k, v in flag_map.items() if tcp.flags & k)

        elif pkt.haslayer(UDP):
            udp      = pkt[UDP]
            src_port = udp.sport
            dst_port = udp.dport
            protocol = "UDP"

        elif pkt.haslayer(ICMP):
            protocol = "ICMP"

        return {
            "timestamp": ts,
            "src_ip":    src_ip,
            "dst_ip":    dst_ip,
            "src_port":  src_port,
            "dst_port":  dst_port,
            "protocol":  protocol,
            "size":      size,
            "flags":     flags,
            "status":    "safe",
            "reason":    "",
        }
    except Exception:
        return None


# ── Callback ──────────────────────────────────────────────────────────────────
def process_packet(pkt):
    data = parse_packet(pkt)
    if data is None:
        return
    status, reason = detect(data)
    data["status"] = status
    data["reason"] = reason
    insert_packet(data)
    # Print a one-liner for quick feedback in the terminal
    marker = {"safe": "✅", "suspicious": "⚠️ ", "dangerous": "🔴"}.get(status, "  ")
    print(f"{marker} [{status.upper():10s}] {data['protocol']:5s} "
          f"{data['src_ip']:15s} → {data['dst_ip']:15s}  {size_str(data['size'])}"
          f"  {reason}", flush=True)


def size_str(n: int) -> str:
    if n >= 1024:
        return f"{n/1024:.1f} KB"
    return f"{n} B  "


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    init_db()
    # Fix DB file permissions so the dashboard (non-root) can write to it
    try:
        os.chmod(DB_PATH, 0o666)
    except Exception:
        pass
    # Write PID so the dashboard knows the sniffer is running
    with open(SNIFFER_PID, "w") as f:
        f.write(str(os.getpid()))
    try:
        os.chmod(SNIFFER_PID, 0o666)
    except Exception:
        pass
    iface = get_interface()
    # Clean up any stale stop flag from a previous session
    if os.path.exists(STOP_FLAG):
        os.remove(STOP_FLAG)
    print(f"\n🛡️  Network Anomaly Sniffer")
    print(f"   Interface : {iface}")
    print(f"   Database  : network_anomaly.db")
    print(f"   Press Ctrl+C or click Stop in the dashboard to stop\n")
    try:
        sniff(
            iface=iface,
            prn=process_packet,
            store=False,
            stop_filter=lambda _: os.path.exists(STOP_FLAG),
        )
        # Reached here because stop flag was set
        print("\n[*] Stop signal received from dashboard. Sniffer halted.")
    except PermissionError:
        print("\n❌  Permission denied.")
        print("   Please run:  sudo python3 sniffer.py\n")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Sniffer stopped (Ctrl+C).")
    finally:
        # Clean up the stop flag so it doesn't block the next run
        if os.path.exists(STOP_FLAG):
            os.remove(STOP_FLAG)
        # Remove PID file so dashboard knows sniffer has stopped
        if os.path.exists(SNIFFER_PID):
            os.remove(SNIFFER_PID)


if __name__ == "__main__":
    main()
