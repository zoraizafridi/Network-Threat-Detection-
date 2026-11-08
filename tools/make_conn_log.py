#!/usr/bin/env python3
"""Generate the bundled, fully synthetic Zeek conn.log sample and its labels.

The project ships one labelled capture so the Zeek importer, the detectors and
the evaluation service can be exercised on data the traffic simulator did not
produce.  Everything here is synthetic: every external address comes from an
RFC 5737 documentation range (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24),
so no real host is referenced.

Output
------
sample-conn.log          Zeek TSV conn.log, 1_693 connections over 30 minutes
sample-conn.labels.csv   uid,label ground truth (one row per connection)

Labels
------
NORMAL          ordinary background traffic
NORMAL_BACKUP   one 90 MiB authorised backup (benign look-alike of exfiltration)
NORMAL_TYPO     a handful of mistyped SSH logins (benign look-alike of brute force)
NTP_HEALTH      periodic NTP polling at a fixed 60 s period (benign look-alike of C2
                beaconing; the beaconing detector must allowlist it by port)
PORT_SCAN       horizontal scan by 203.0.113.50 against 10.0.1.20
BRUTE_FORCE     SSH password guessing by 203.0.113.50 against 10.0.1.20
BEACONING       10.0.1.15 -> 198.51.100.23:443 every ~60 s with near-identical payloads
LATERAL_MOVEMENT 10.0.1.15 -> 10.0.1.20 -> 10.0.1.21 -> 10.0.1.22 -> 10.0.2.7
DATA_EXFIL      10.0.2.7 -> 203.0.113.77:443 in several multi-megabyte transfers
DOS_FLOOD       203.0.113.100-109 flooding 10.0.2.6:80

Usage
-----
    python tools/make_conn_log.py --out-dir build/samples
    python tools/make_conn_log.py --install     # writes the four shipped copies
    python tools/make_conn_log.py --seed 42 --connections 1693 --minutes 30

The generator is deterministic for a given --seed: the connection count is exact
(the background is whatever remains after the scripted scenarios) and every
random attribute is drawn from one seeded ``random.Random`` instance.
"""

from __future__ import annotations

import argparse
import csv
import random
import sys
from datetime import datetime, timezone
from pathlib import Path

BASE_TS = 1767225600.0  # 2026-01-01T00:00:00Z, the start of the capture
DEFAULT_CONNECTIONS = 1693
DEFAULT_MINUTES = 30

FIELDS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
    "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig",
    "local_resp", "missed_bytes", "history", "orig_pkts", "orig_ip_bytes",
    "resp_pkts", "resp_ip_bytes", "tunnel_parents",
]
TYPES = [
    "time", "string", "addr", "port", "addr", "port", "enum", "string",
    "interval", "count", "count", "string", "bool", "bool", "count", "string",
    "count", "count", "count", "count", "set[string]",
]

UID_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

# --- asset inventory ---------------------------------------------------------

WORKSTATIONS = [f"10.0.1.{n}" for n in range(10, 26)]
DB_SERVER = "10.0.2.7"
WEB_SERVER = "10.0.2.6"
BACKUP_SERVER = "10.0.2.5"
MAIL_SERVER = "10.0.2.8"
DNS_SERVER = "10.0.2.9"
INTERNAL_HOSTS = WORKSTATIONS + [BACKUP_SERVER, WEB_SERVER, DB_SERVER, MAIL_SERVER, DNS_SERVER]

BEACON_HOST = "10.0.1.15"
BEACON_C2 = "198.51.100.23"
SCANNER = "203.0.113.50"
SCAN_TARGET = "10.0.1.20"
EXFIL_TARGET = "203.0.113.77"
NTP_SERVER = "198.51.100.53"
DOS_SOURCES = [f"203.0.113.{n}" for n in range(100, 110)]
DOS_TARGET = WEB_SERVER

LATERAL_CHAIN = ["10.0.1.15", "10.0.1.20", "10.0.1.21", "10.0.1.22", DB_SERVER]
LATERAL_PORTS = [445, 3389, 22, 5985]

SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993,
              995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 6379, 8080,
              8443, 9000, 9090, 9200, 27017]

# Background service mix: (port, proto, service, weight).
BACKGROUND_SERVICES = [
    (443, "tcp", "ssl", 22),
    (443, "tcp", "-", 8),
    (80, "tcp", "http", 20),
    (53, "udp", "dns", 14),
    (22, "tcp", "ssh", 6),
    (445, "tcp", "smb", 7),
    (3306, "tcp", "mysql", 4),
    (8080, "tcp", "http", 5),
    (25, "tcp", "smtp", 4),
    (389, "tcp", "ldap", 3),
    (636, "tcp", "ssl", 2),
    (123, "udp", "-", 3),
    (161, "udp", "-", 2),
]

# Internal pairs that belong to a scripted scenario; background traffic avoids
# them so a scenario's own signature is not diluted by look-alike noise.
RESERVED_PAIRS = {
    (BEACON_HOST, BEACON_C2),
    (SCANNER, SCAN_TARGET),
    (DB_SERVER, EXFIL_TARGET),
    (WEB_SERVER, NTP_SERVER),
    (BACKUP_SERVER, DB_SERVER),
    (LATERAL_CHAIN[0], LATERAL_CHAIN[1]),
    (LATERAL_CHAIN[1], LATERAL_CHAIN[2]),
    (LATERAL_CHAIN[2], LATERAL_CHAIN[3]),
    (LATERAL_CHAIN[3], LATERAL_CHAIN[4]),
    (SCAN_TARGET, MAIL_SERVER),
}


def is_internal(addr: str) -> bool:
    return addr.startswith("10.")


def new_uid(rng: random.Random, taken: set[str]) -> str:
    while True:
        uid = "C" + "".join(rng.choice(UID_ALPHABET) for _ in range(17))
        if uid not in taken:
            taken.add(uid)
            return uid


def packets(nbytes: int) -> int:
    """Approximate packet count for a byte total, never zero for data flows."""
    if nbytes <= 0:
        return 1
    return 1 + nbytes // 1460


def make_row(*, ts: float, src: str, sport: int, dst: str, dport: int, proto: str,
             service: str, duration: float, orig_bytes: int, resp_bytes: int,
             conn_state: str, history: str) -> dict:
    op = packets(orig_bytes)
    rp = packets(resp_bytes) if resp_bytes > 0 else 0
    return {
        "ts": ts,
        "src": src,
        "sport": sport,
        "dst": dst,
        "dport": dport,
        "proto": proto,
        "service": service,
        "duration": max(0.0, duration),
        "orig_bytes": max(0, orig_bytes),
        "resp_bytes": max(0, resp_bytes),
        "conn_state": conn_state,
        "local_orig": "T" if is_internal(src) else "F",
        "local_resp": "T" if is_internal(dst) else "F",
        "missed_bytes": 0,
        "history": history,
        "orig_pkts": op,
        "orig_ip_bytes": orig_bytes + 40 * op,
        "resp_pkts": rp,
        "resp_ip_bytes": resp_bytes + 40 * rp if rp else 0,
        "tunnel_parents": "-",
    }


def ephemeral(rng: random.Random) -> int:
    return rng.randrange(32768, 61000)


# --- scenarios ---------------------------------------------------------------

def scan_rows(rng: random.Random) -> list[dict]:
    """Horizontal SYN scan: 40 connections over 30 distinct ports."""
    rows = []
    start = BASE_TS + 120.0
    ports = SCAN_PORTS + SCAN_PORTS[:10]
    rng.shuffle(ports)
    for i, port in enumerate(ports):
        rows.append(make_row(
            ts=start + i * rng.uniform(0.15, 0.45),
            src=SCANNER, sport=ephemeral(rng), dst=SCAN_TARGET, dport=port,
            proto="tcp", service="-", duration=0.0, orig_bytes=0, resp_bytes=0,
            conn_state="S0", history="S",
        ))
    return rows


def brute_force_rows(rng: random.Random) -> list[dict]:
    """19 failed SSH logins then 1 success, from the same scanner."""
    rows = []
    start = BASE_TS + 240.0
    for i in range(19):
        rows.append(make_row(
            ts=start + i * rng.uniform(3.5, 5.5),
            src=SCANNER, sport=ephemeral(rng), dst=SCAN_TARGET, dport=22,
            proto="tcp", service="ssh", duration=rng.uniform(0.9, 1.6),
            orig_bytes=rng.randrange(3600, 4800), resp_bytes=rng.randrange(4200, 5400),
            conn_state="SF", history="ShADadFf",
        ))
    rows.append(make_row(
        ts=start + 19 * 5.0 + 2.0,
        src=SCANNER, sport=ephemeral(rng), dst=SCAN_TARGET, dport=22,
        proto="tcp", service="ssh", duration=42.5,
        orig_bytes=18500, resp_bytes=96000, conn_state="SF", history="ShADadFf",
    ))
    return rows


def beacon_rows(rng: random.Random) -> list[dict]:
    """C2 check-in every ~60 s with near-identical payload sizes."""
    rows = []
    start = BASE_TS + 300.0
    for i in range(25):
        ts = start + i * 60.0 + rng.uniform(-1.5, 1.5)
        rows.append(make_row(
            ts=ts, src=BEACON_HOST, sport=ephemeral(rng), dst=BEACON_C2, dport=443,
            proto="tcp", service="ssl", duration=rng.uniform(1.1, 1.4),
            orig_bytes=rng.randrange(480, 501), resp_bytes=rng.randrange(220, 236),
            conn_state="SF", history="ShADadFf",
        ))
    return rows


def lateral_rows(rng: random.Random) -> list[dict]:
    """Four hops across the internal estate, four connections per hop."""
    rows = []
    start = BASE_TS + 900.0
    for hop in range(len(LATERAL_CHAIN) - 1):
        src = LATERAL_CHAIN[hop]
        dst = LATERAL_CHAIN[hop + 1]
        for n in range(4):
            port = LATERAL_PORTS[(hop + n) % len(LATERAL_PORTS)]
            rows.append(make_row(
                ts=start + hop * 70.0 + n * rng.uniform(4.0, 9.0),
                src=src, sport=ephemeral(rng), dst=dst, dport=port,
                proto="tcp", service="smb" if port == 445 else "-",
                duration=rng.uniform(2.0, 18.0),
                orig_bytes=rng.randrange(45_000, 420_000),
                resp_bytes=rng.randrange(20_000, 180_000),
                conn_state="SF", history="ShADadFf",
            ))
    return rows


def exfil_rows(rng: random.Random) -> list[dict]:
    """Eight outbound transfers of several megabytes each, from the DB server."""
    rows = []
    start = BASE_TS + 1200.0
    for i in range(8):
        rows.append(make_row(
            ts=start + i * rng.uniform(35.0, 55.0),
            src=DB_SERVER, sport=ephemeral(rng), dst=EXFIL_TARGET, dport=443,
            proto="tcp", service="ssl", duration=rng.uniform(30.0, 90.0),
            orig_bytes=rng.randrange(3_000_000, 8_000_000),
            resp_bytes=rng.randrange(2_000, 12_000),
            conn_state="SF", history="ShADadFf",
        ))
    return rows


def dos_rows(rng: random.Random) -> list[dict]:
    """30 connections from each of ten sources inside one minute."""
    rows = []
    start = BASE_TS + 1500.0
    for source in DOS_SOURCES:
        for _ in range(30):
            rows.append(make_row(
                ts=start + rng.uniform(0.0, 60.0),
                src=source, sport=ephemeral(rng), dst=DOS_TARGET, dport=80,
                proto="tcp", service="http", duration=0.0,
                orig_bytes=rng.randrange(0, 120), resp_bytes=0,
                conn_state=rng.choice(["S0", "S0", "REJ"]), history="S",
            ))
    return rows


def backup_rows() -> list[dict]:
    """One authorised 90 MiB backup: large, internal, and entirely benign."""
    return [make_row(
        ts=BASE_TS + 600.0, src=BACKUP_SERVER, sport=ephemeral(random.Random(7)),
        dst=DB_SERVER, dport=445, proto="tcp", service="smb", duration=180.0,
        orig_bytes=94_371_840, resp_bytes=1_200_000, conn_state="SF",
        history="ShADadFf",
    )]


def typo_rows(rng: random.Random) -> list[dict]:
    """Five failed SSH logins from a user who mistyped their password."""
    return [make_row(
        ts=BASE_TS + 420.0 + i * rng.uniform(25.0, 45.0),
        src=SCAN_TARGET, sport=ephemeral(rng), dst=MAIL_SERVER, dport=22,
        proto="tcp", service="ssh", duration=rng.uniform(0.8, 1.4),
        orig_bytes=rng.randrange(3400, 4200), resp_bytes=rng.randrange(4000, 5000),
        conn_state="SF", history="ShADadFf",
    ) for i in range(5)]


def ntp_rows(rng: random.Random) -> list[dict]:
    """Health-check polling at exactly 60 s: regular, but allowlisted by port."""
    rows = []
    for i in range(30):
        rows.append(make_row(
            ts=BASE_TS + i * 60.0 + rng.uniform(-0.05, 0.05),
            src=WEB_SERVER, sport=123, dst=NTP_SERVER, dport=123,
            proto="udp", service="-", duration=rng.uniform(0.0001, 0.002),
            orig_bytes=76, resp_bytes=76, conn_state="SF", history="Dd",
        ))
    return rows


def background_rows(rng: random.Random, count: int, minutes: int) -> list[dict]:
    """Ordinary traffic filling the remainder of the capture."""
    internal_external = [a for a in ("198.51.100.10", "198.51.100.20", "203.0.113.10",
                                     "192.0.2.10", "203.0.113.20")]
    rows: list[dict] = []
    for _ in range(count):
        port, proto, service, _ = rng.choices(
            BACKGROUND_SERVICES, weights=[w for _, _, _, w in BACKGROUND_SERVICES],
            k=1,
        )[0]
        ts = BASE_TS + rng.uniform(0.0, minutes * 60.0)
        if rng.random() < 0.22:
            src = rng.choice(internal_external)
            dst = rng.choice(INTERNAL_HOSTS)
        elif rng.random() < 0.12:
            src = rng.choice(INTERNAL_HOSTS)
            dst = rng.choice(internal_external)
        else:
            src, dst = rng.sample(INTERNAL_HOSTS, 2)
        if (src, dst) in RESERVED_PAIRS or (dst, src) in RESERVED_PAIRS:
            src = rng.choice([h for h in INTERNAL_HOSTS if h != dst])
        if src == dst:
            dst = DNS_SERVER if src != DNS_SERVER else MAIL_SERVER

        if proto == "udp":
            duration = rng.uniform(0.0001, 0.05)
            orig = rng.randrange(60, 220)
            resp = rng.randrange(60, 900)
            state, history = "SF", "Dd"
        elif service == "ssh":
            duration = rng.uniform(1.0, 240.0)
            orig = rng.randrange(3000, 90_000)
            resp = rng.randrange(4000, 400_000)
            state, history = "SF", "ShADadFf"
        elif port == 445:
            duration = rng.uniform(0.5, 120.0)
            orig = rng.randrange(2_000, 2_000_000)
            resp = rng.randrange(1_000, 1_500_000)
            state, history = "SF", "ShADadFf"
        elif service in ("ssl", "mysql", "ldap"):
            duration = rng.uniform(0.2, 45.0)
            orig = rng.randrange(500, 900_000)
            resp = rng.randrange(500, 4_000_000)
            state, history = "SF", "ShADadFf"
        else:
            duration = rng.uniform(0.01, 8.0)
            orig = rng.randrange(200, 60_000)
            resp = rng.randrange(200, 900_000)
            state, history = "SF", "ShADadFf"

        rows.append(make_row(
            ts=ts, src=src, sport=ephemeral(rng), dst=dst, dport=port,
            proto=proto, service=service, duration=duration,
            orig_bytes=orig, resp_bytes=resp, conn_state=state, history=history,
        ))
    return rows


def build(seed: int, total: int, minutes: int) -> tuple[list[dict], list[tuple[str, str]]]:
    rng = random.Random(seed)
    scripted: list[tuple[list[dict], str]] = [
        (scan_rows(rng), "PORT_SCAN"),
        (brute_force_rows(rng), "BRUTE_FORCE"),
        (beacon_rows(rng), "BEACONING"),
        (lateral_rows(rng), "LATERAL_MOVEMENT"),
        (exfil_rows(rng), "DATA_EXFIL"),
        (dos_rows(rng), "DOS_FLOOD"),
        (backup_rows(), "NORMAL_BACKUP"),
        (typo_rows(rng), "NORMAL_TYPO"),
        (ntp_rows(rng), "NTP_HEALTH"),
    ]
    scripted_count = sum(len(rows) for rows, _ in scripted)
    if scripted_count > total:
        raise SystemExit(
            f"scripted scenarios need {scripted_count} connections, "
            f"only {total} requested: lower the scenario sizes or raise --connections"
        )

    labelled: list[tuple[dict, str]] = []
    for rows, label in scripted:
        labelled.extend((row, label) for row in rows)
    labelled.extend((row, "NORMAL") for row in background_rows(rng, total - scripted_count, minutes))

    labelled.sort(key=lambda item: (item[0]["ts"], item[0]["src"], item[0]["dport"]))
    taken: set[str] = set()
    out_rows: list[dict] = []
    labels: list[tuple[str, str]] = []
    for row, label in labelled:
        uid = new_uid(rng, taken)
        row["uid"] = uid
        out_rows.append(row)
        labels.append((uid, label))
    return out_rows, labels


# --- serialisation -----------------------------------------------------------

def write_conn_log(path: Path, rows: list[dict], start: float) -> None:
    stamp = datetime.fromtimestamp(start, tz=timezone.utc).strftime("%Y-%m-%d-%H-%M-%S")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("#separator \\x09\n")
        handle.write("#set_separator\t,\n")
        handle.write("#empty_field\t(empty)\n")
        handle.write("#unset_field\t-\n")
        handle.write("#path\tconn\n")
        handle.write(f"#open\t{stamp}\n")
        handle.write("#fields\t" + "\t".join(FIELDS) + "\n")
        handle.write("#types\t" + "\t".join(TYPES) + "\n")
        for row in rows:
            values = [
                f"{row['ts']:.6f}",
                row["uid"],
                row["src"],
                str(row["sport"]),
                row["dst"],
                str(row["dport"]),
                row["proto"],
                row["service"],
                f"{row['duration']:.6f}",
                str(row["orig_bytes"]),
                str(row["resp_bytes"]),
                row["conn_state"],
                row["local_orig"],
                row["local_resp"],
                str(row["missed_bytes"]),
                row["history"],
                str(row["orig_pkts"]),
                str(row["orig_ip_bytes"]),
                str(row["resp_pkts"]),
                str(row["resp_ip_bytes"]),
                row["tunnel_parents"],
            ]
            handle.write("\t".join(values) + "\n")


def write_labels(path: Path, labels: list[tuple[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(["uid", "label"])
        writer.writerows(labels)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out-dir", default="build/samples", help="directory for the generated pair")
    parser.add_argument("--seed", type=int, default=42, help="PRNG seed (default 42)")
    parser.add_argument("--connections", type=int, default=DEFAULT_CONNECTIONS,
                        help=f"exact number of connections (default {DEFAULT_CONNECTIONS})")
    parser.add_argument("--minutes", type=int, default=DEFAULT_MINUTES,
                        help=f"simulated capture length (default {DEFAULT_MINUTES})")
    parser.add_argument("--install", action="store_true",
                        help="also write the pair into src/main/resources/samples and src/test/resources/samples")
    parser.add_argument("--quiet", action="store_true", help="suppress the summary")
    args = parser.parse_args(argv)

    if args.connections < 1:
        parser.error("--connections must be positive")
    if args.minutes < 1:
        parser.error("--minutes must be positive")

    rows, labels = build(args.seed, args.connections, args.minutes)

    targets = [Path(args.out_dir)]
    if args.install:
        root = Path(__file__).resolve().parent.parent
        targets = [
            root / "src" / "main" / "resources" / "samples",
            root / "src" / "test" / "resources" / "samples",
        ]
    for directory in targets:
        write_conn_log(directory / "sample-conn.log", rows, BASE_TS)
        write_labels(directory / "sample-conn.labels.csv", labels)

    if not args.quiet:
        counts: dict[str, int] = {}
        for _, label in labels:
            counts[label] = counts.get(label, 0) + 1
        print(f"connections: {len(rows)}  minutes: {args.minutes}  seed: {args.seed}")
        for label in sorted(counts):
            print(f"  {label:<16} {counts[label]:>5}")
        for directory in targets:
            print(f"wrote {directory / 'sample-conn.log'} and sample-conn.labels.csv")
    return 0


if __name__ == "__main__":
    sys.exit(main())
