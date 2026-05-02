import sqlite3
import time
from config import DB_PATH


def get_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL    NOT NULL,
            src_ip    TEXT,
            dst_ip    TEXT,
            src_port  INTEGER,
            dst_port  INTEGER,
            protocol  TEXT,
            size      INTEGER,
            flags     TEXT,
            status    TEXT DEFAULT 'safe',
            reason    TEXT DEFAULT ''
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_ts     ON packets(timestamp)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_status ON packets(status)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_src    ON packets(src_ip)")
    conn.commit()
    conn.close()


def insert_packet(data: dict):
    conn = get_connection()
    conn.execute("""
        INSERT INTO packets
            (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, size, flags, status, reason)
        VALUES
            (:timestamp, :src_ip, :dst_ip, :src_port, :dst_port, :protocol, :size, :flags, :status, :reason)
    """, data)
    conn.commit()
    conn.close()


def fetch_recent_packets(limit=100):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM packets ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def fetch_status_counts():
    conn  = get_connection()
    rows  = conn.execute(
        "SELECT status, COUNT(*) as count FROM packets GROUP BY status"
    ).fetchall()
    conn.close()
    return {r["status"]: r["count"] for r in rows}


def fetch_packets_per_second(window=60):
    since = time.time() - window
    conn  = get_connection()
    rows  = conn.execute("""
        SELECT CAST(timestamp AS INTEGER) AS second, status, COUNT(*) AS count
        FROM packets
        WHERE timestamp >= ?
        GROUP BY second, status
        ORDER BY second
    """, (since,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def fetch_top_threat_ips(limit=10):
    conn = get_connection()
    rows = conn.execute("""
        SELECT src_ip,
               COUNT(*)       AS anomaly_count,
               MAX(timestamp) AS last_seen,
               MAX(status)    AS worst_status
        FROM packets
        WHERE status IN ('suspicious', 'dangerous')
        GROUP BY src_ip
        ORDER BY anomaly_count DESC
        LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def fetch_total_count():
    conn = get_connection()
    row  = conn.execute("SELECT COUNT(*) AS total FROM packets").fetchone()
    conn.close()
    return row["total"] if row else 0


def fetch_recent_dangerous(limit=5):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM packets WHERE status='dangerous' ORDER BY timestamp DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def clear_db():
    """Delete all packets and reset the auto-increment counter."""
    conn = get_connection()
    conn.execute("DELETE FROM packets")
    conn.execute("DELETE FROM sqlite_sequence WHERE name='packets'")
    conn.commit()
    conn.close()
