#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import re
import sqlite3
from pathlib import Path
from typing import List, Dict, Tuple, Iterable
from datetime import datetime

# --------- Parsing helpers (same logic as before, extended) ----------

RECORD_HEADER_RE = re.compile(r"^####\s+(.+?)\s+####\s*$")
KV_RE = re.compile(r"^([^:]+):\s*(.+?)\s*$")
COUNTER_RE = re.compile(r"^([A-Za-z0-9_]+)@(\w+)\s*#:\s*(-?\d+)\s*$")  # e.g., Constraints@memop #: 16106

CANON_KEYS = {
    "Type syscall": "type_syscall",
    "Memory operation": "memory_operation",
    "Memop signal": "memop_signal",
    "Panic": "panic",
    "Reached memop": "reached_memop",
    "Reached return": "reached_return",
}

def parse_bool(val: str):
    v = val.strip().lower()
    if v in {"yes", "true", "1", "y", "t"}:
        return 1
    if v in {"no", "false", "0", "n", "f"}:
        return 0
    return val  # leave as text if not a canonical boolean

def split_records(text: str) -> List[Tuple[str, List[str]]]:
    """
    Split the input into records. Each record begins with '#### <id> ####'.
    Returns list of (record_id, lines).
    """
    lines = text.splitlines()
    records = []
    current_id = None
    current_lines = []

    for line in lines:
        m = RECORD_HEADER_RE.match(line)
        if m:
            if current_id is not None:
                records.append((current_id, current_lines))
            current_id = m.group(1).strip()
            current_lines = []
        else:
            if current_id is not None:
                current_lines.append(line)

    if current_id is not None:
        records.append((current_id, current_lines))

    return records

def parse_record_lines(record_id: str, lines: List[str]) -> Dict[str, object]:
    """
    Parse a single record into a flat dict suitable for DB insertion.
    - Canonical KV lines are mapped via CANON_KEYS
    - Counters like 'Constraints@memop #:' -> 'constraints_memop' (int)
    - 'STATE <n>' -> 'state' (int if possible)
    """
    out = {"record_id": record_id}

    for raw in lines:
        line = raw.strip()
        if not line or line in {"----", "—", "——", "— —", "—–"}:
            continue
        if line.upper().startswith("STATE 1"):
            return out

        if line.upper().startswith("STATE 0"):
            frag = line.split(maxsplit=1)[-1]
            try:
                out["state"] = int(frag)
            except Exception:
                out["state"] = frag
            continue

        mc = COUNTER_RE.match(line)
        if mc:
            metric, phase, value = mc.groups()
            col = f"{metric.lower()}_{phase.lower()}"
            out[col] = int(value)
            continue

        mkv = KV_RE.match(line)
        if mkv:
            key, value = mkv.groups()
            key = key.strip()
            value = value.strip()
            if key in CANON_KEYS:
                col = CANON_KEYS[key]
                if col in {"memop_signal", "panic", "reached_memop", "reached_return"}:
                    out[col] = parse_bool(value)
                else:
                    out[col] = value
            else:
                col = re.sub(r"[^a-z0-9]+", "_", key.lower()).strip("_")
                vlow = value.lower()
                if vlow in {"yes", "no", "true", "false", "0", "1"}:
                    out[col] = parse_bool(value)
                else:
                    try:
                        out[col] = int(value)
                    except ValueError:
                        out[col] = value
            continue

        # Unknown line types are ignored. Uncomment to retain them:
        # out.setdefault("raw_lines", []).append(line)

    return out

# ------------- SQLite helpers ----------------

def ensure_table(conn: sqlite3.Connection, table: str):
    conn.execute(f"""
        CREATE TABLE IF NOT EXISTS {table} (
            record_id TEXT PRIMARY KEY,
            -- canonical fields
            type_syscall TEXT,
            memory_operation TEXT,
            memop_signal INTEGER,
            panic INTEGER,
            reached_memop INTEGER,
            reached_return INTEGER,
            state INTEGER,
            -- provenance
            source_root TEXT,
            source_dir TEXT,
            source_file TEXT,
            file_mtime_utc TEXT,
            scanned_at_utc TEXT
        )
    """)
    conn.commit()

def get_existing_columns(conn: sqlite3.Connection, table: str) -> set:
    cur = conn.execute(f"PRAGMA table_info({table})")
    return {row[1] for row in cur.fetchall()}

def alter_table_add_columns(conn: sqlite3.Connection, table: str, new_cols: List[Tuple[str, str]]):
    for name, sqltype in new_cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {sqltype}")
    conn.commit()

def infer_sql_type(value) -> str:
    if isinstance(value, int):
        return "INTEGER"
    return "TEXT"  # booleans stored as INTEGER upstream

def upsert_record(conn: sqlite3.Connection, table: str, rec: Dict[str, object]):
    existing = get_existing_columns(conn, table)
    missing = [(k, infer_sql_type(v)) for k, v in rec.items() if k not in existing]
    if missing:
        alter_table_add_columns(conn, table, missing)

    cols = list(rec.keys())
    placeholders = ",".join(["?"] * len(cols))
    col_list = ",".join(cols)
    update_clause = ",".join([f"{c}=excluded.{c}" for c in cols if c != "record_id"])

    sql = f"""
        INSERT INTO {table} ({col_list})
        VALUES ({placeholders})
        ON CONFLICT(record_id) DO UPDATE SET
        {update_clause}
    """
    conn.execute(sql, [rec[c] for c in cols])

# ------------- File scanning + ingestion ----------------

def iter_report_files(root: Path, pattern: str = "s2e-last/report.txt") -> Iterable[Path]:
    """
    Recursively yield paths to report files.
    Default pattern matches .../<any>/s2e-last/report.txt
    """
    # Using rglob on "s2e-last/report.txt" is efficient and avoids false positives
    yield from root.rglob(pattern)

def ingest(root: Path, db_path: Path, table: str = "records", pattern: str = "s2e-last/report.txt") -> int:
    conn = sqlite3.connect(str(db_path))
    ensure_table(conn, table)

    scanned_at = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    count_records = 0

    try:
        for report in iter_report_files(root, pattern):
            try:
                text = report.read_text(encoding="utf-8", errors="replace")
            except Exception as e:
                print(f"[WARN] Failed to read {report}: {e}")
                continue

            # Parse all records in this file
            for rec_id, lines in split_records(text):
                parsed = parse_record_lines(rec_id, lines)
                with open("./{}/{}.output".format(rec_id, rec_id), "r") as f:
                    text = f.read();
                    # Find dst_ptr_alloc cache
                    dst_match = re.search(r'"dst_ptr_alloc"\s*:\s*{[^}]*"cache"\s*:\s*"([^"]+)"', text)
                    parsed["dst_ptr_cache"] = dst_match.group(1) if dst_match else None
                    # Find target_obj_alloc cache
                    target_match = re.search(r'"target_obj_alloc"\s*:\s*{[^}]*"cache"\s*:\s*"([^"]+)"', text)
                    parsed["kdo_obj_cache"] = target_match.group(1) if target_match else None

                # Add provenance about where this record came from
                parsed["source_root"] = str(root)
                parsed["source_dir"] = str(report.parent)
                parsed["source_file"] = str(report)
                try:
                    mtime = datetime.utcfromtimestamp(report.stat().st_mtime).isoformat(timespec="seconds") + "Z"
                except Exception:
                    mtime = None
                parsed["file_mtime_utc"] = mtime
                parsed["scanned_at_utc"] = scanned_at

                upsert_record(conn, table, parsed)
                count_records += 1

        conn.commit()
    finally:
        conn.close()

    return count_records

def main():
    parser = argparse.ArgumentParser(description="Recursively parse s2e report files and load into SQLite.")
    parser.add_argument("--root", "-r", default="/home/s2e/cco_s2e/projects", help="Root directory to scan (default: current dir)")
    parser.add_argument("--db", "-d", default="kdo_final_results.sql", help="SQLite database path (created if missing)")
    parser.add_argument("--table", "-t", default="records", help="Target table name (default: records)")
    parser.add_argument("--pattern", "-p", default="s2e-last/report.txt", help="Relative pattern to find (default: s2e-last/report.txt)")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    db_path = Path(args.db).resolve()

    total = ingest(root=root, db_path=db_path, table=args.table, pattern=args.pattern)
    print(f"Ingested {total} record(s) from '{root}' into table '{args.table}' in {db_path}.")

if __name__ == "__main__":
    main()


