import time
from collections import defaultdict
from config import (
    SUSPICIOUS_SIZE, DANGEROUS_SIZE,
    SUSPICIOUS_RATE, DANGEROUS_RATE, RATE_WINDOW,
    PORT_SCAN_THRESHOLD, PORT_SCAN_WINDOW,
    ICMP_FLOOD_THRESHOLD, DANGEROUS_PORTS,
)

# ── In-memory sliding-window state ────────────────────────────────────────────
_pkt_ts:    dict[str, list] = defaultdict(list)   # src_ip  → [timestamps]
_syn_ts:    dict[str, list] = defaultdict(list)   # src_ip  → [syn timestamps]
_icmp_ts:   dict[str, list] = defaultdict(list)   # src_ip  → [icmp timestamps]
_port_hist: dict[str, list] = defaultdict(list)   # src_ip  → [(ts, dst_port)]


def _trim(lst: list, window: float):
    cutoff = time.time() - window
    while lst and lst[0] < cutoff:
        lst.pop(0)


def _trim_pairs(lst: list, window: float):
    cutoff = time.time() - window
    while lst and lst[0][0] < cutoff:
        lst.pop(0)


def detect(pkt: dict) -> tuple[str, str]:
    """
    Returns (status, reason).
    status : 'safe' | 'suspicious' | 'dangerous'
    reason : human-readable explanation string
    """
    src_ip   = pkt.get("src_ip", "") or ""
    size     = pkt.get("size", 0)    or 0
    protocol = pkt.get("protocol", "")
    dst_port = pkt.get("dst_port") or 0
    src_port = pkt.get("src_port") or 0
    flags    = pkt.get("flags", "") or ""
    now      = time.time()

    # ── Rule 1 · Extremely large packet ───────────────────────────────────────
    if size > DANGEROUS_SIZE:
        return "dangerous", f"Oversized packet: {size} bytes (limit {DANGEROUS_SIZE})"

    # ── Rule 2 · Large packet ─────────────────────────────────────────────────
    if size > SUSPICIOUS_SIZE:
        return "suspicious", f"Large packet: {size} bytes"

    # ── Rule 3 · Dangerous port ───────────────────────────────────────────────
    bad_port = None
    if dst_port in DANGEROUS_PORTS:
        bad_port = dst_port
    elif src_port in DANGEROUS_PORTS:
        bad_port = src_port
    if bad_port:
        return "suspicious", f"Dangerous port: {bad_port}"

    # ── Rule 4 · SYN flood ───────────────────────────────────────────────────
    if protocol == "TCP" and "S" in flags and "A" not in flags:
        _syn_ts[src_ip].append(now)
        _trim(_syn_ts[src_ip], RATE_WINDOW)
        rate = len(_syn_ts[src_ip]) / RATE_WINDOW
        if rate > DANGEROUS_RATE:
            return "dangerous", f"SYN flood: {rate:.0f} SYN/s from {src_ip}"

    # ── Rule 5 · ICMP flood ───────────────────────────────────────────────────
    if protocol == "ICMP":
        _icmp_ts[src_ip].append(now)
        _trim(_icmp_ts[src_ip], RATE_WINDOW)
        rate = len(_icmp_ts[src_ip]) / RATE_WINDOW
        if rate > ICMP_FLOOD_THRESHOLD:
            return "dangerous", f"ICMP flood: {rate:.0f} pkt/s from {src_ip}"

    # ── Rule 6 · General packet-rate flood ───────────────────────────────────
    _pkt_ts[src_ip].append(now)
    _trim(_pkt_ts[src_ip], RATE_WINDOW)
    rate = len(_pkt_ts[src_ip]) / RATE_WINDOW
    if rate > DANGEROUS_RATE:
        return "dangerous", f"Packet flood: {rate:.0f} pkt/s from {src_ip}"
    if rate > SUSPICIOUS_RATE:
        return "suspicious", f"High rate: {rate:.0f} pkt/s from {src_ip}"

    # ── Rule 7 · Port scan ───────────────────────────────────────────────────
    if dst_port > 0:
        _port_hist[src_ip].append((now, dst_port))
        _trim_pairs(_port_hist[src_ip], PORT_SCAN_WINDOW)
        unique = len({p for _, p in _port_hist[src_ip]})
        if unique > PORT_SCAN_THRESHOLD:
            return "dangerous", f"Port scan: {unique} unique ports from {src_ip}"

    return "safe", ""
