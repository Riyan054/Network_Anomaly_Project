import os

# ── Database ───────────────────────────────────────────────────────────────────
DB_PATH       = os.path.join(os.path.dirname(os.path.abspath(__file__)), "network_anomaly.db")
STOP_FLAG     = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".stop_sniffer")
SNIFFER_PID   = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".sniffer.pid")

# ── Packet size thresholds (bytes) ─────────────────────────────────────────────
SUSPICIOUS_SIZE = 1500
DANGEROUS_SIZE  = 65000

# ── Rate limits (packets per second per IP, measured over RATE_WINDOW seconds) ─
SUSPICIOUS_RATE = 30
DANGEROUS_RATE  = 100
RATE_WINDOW     = 5   # seconds

# ── Port scan detection ────────────────────────────────────────────────────────
PORT_SCAN_THRESHOLD = 15   # unique dst ports within window
PORT_SCAN_WINDOW    = 10   # seconds

# ── ICMP flood threshold (pkts/sec from one IP) ───────────────────────────────
ICMP_FLOOD_THRESHOLD = 50

# ── Known dangerous / suspicious ports ────────────────────────────────────────
DANGEROUS_PORTS = {23, 445, 3389, 1433, 6667, 4444, 31337, 135, 137, 138, 139}

# ── Network interface (None = auto-detect) ─────────────────────────────────────
INTERFACE = None

# ── Dashboard ─────────────────────────────────────────────────────────────────
REFRESH_INTERVAL = 2    # seconds between auto-refresh
LIVE_LOG_LIMIT   = 100  # rows shown in live packet log
CHART_WINDOW     = 60   # seconds of history for the line chart
