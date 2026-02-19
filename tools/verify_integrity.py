import os
import sys
import json
import hashlib

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

if os.path.isdir(os.path.join(BASE_DIR, "registry", "public")):
    PUBLIC_DIR = os.path.join(BASE_DIR, "registry", "public")
else:
    PUBLIC_DIR = os.path.join(BASE_DIR, "public")


def abort(message):
    print(f"INTEGRITY CHECK FAILED: {message}")
    sys.exit(1)


def compute_sha256(path):
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha.update(chunk)
    return sha.hexdigest()


def count_events(path):
    with open(path, "r", encoding="utf-8") as f:
        return sum(1 for line in f if line.strip())



def parse_iso8601_utc(value: str):
    # observed_at expected in UTC with Z (or +00:00)
    from datetime import datetime
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def canonical_json_bytes(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def compute_merkle_root_hex(leaf_digests: list) -> str:
    if not leaf_digests:
        return hashlib.sha256(b"").hexdigest()
    level = leaf_digests[:]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        nxt = []
        for i in range(0, len(level), 2):
            nxt.append(sha256_digest(level[i] + level[i+1]))
        level = nxt
    return level[0].hex()


def date_utc_from_observed_at(observed_at: str) -> str:
    dt = parse_iso8601_utc(observed_at)
    return dt.date().isoformat()


def verify_daily_roots(root_dir: str, events_file: str):
    daily_dir = os.path.join(root_dir, "integrity", "daily_roots")
    index_path = os.path.join(daily_dir, "daily_roots_index.json")
    if not os.path.exists(index_path):
        # Backward compatible: daily roots not present
        print("No daily roots index found; skipping daily Merkle verification.")
        return

    with open(index_path, "r", encoding="utf-8") as f:
        index = json.load(f)

    # Group events by UTC day
    events_by_day = {}
    with open(events_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            ev = json.loads(line)
            day = date_utc_from_observed_at(ev["observed_at"])
            events_by_day.setdefault(day, []).append(ev)

    # Verify each day declared in index
    for day_info in index.get("days", []):
        day = day_info["date_utc"]
        expected_root = day_info["merkle_root"]
        expected_count = day_info["event_count"]

        rec_path = os.path.join(daily_dir, f"daily_root_{day}.json")
        if not os.path.exists(rec_path):
            abort(f"Missing daily root record: {rec_path}")

        with open(rec_path, "r", encoding="utf-8") as f:
            rec = json.load(f)

        # Recompute
        day_events = sorted(events_by_day.get(day, []), key=lambda e: e["event_id"])
        leaf_digests = [sha256_digest(canonical_json_bytes(e)) for e in day_events]
        actual_root = compute_merkle_root_hex(leaf_digests)
        actual_count = len(day_events)

        if actual_count != expected_count or actual_count != rec.get("event_count"):
            abort(f"Daily event count mismatch for {day}")
        if actual_root != expected_root or actual_root != rec.get("merkle_root"):
            abort(f"Daily Merkle root mismatch for {day}")

    print("Daily Merkle roots verification successful.")

def resolve_root(argv):
    # default: current
    if len(argv) == 1:
        return os.path.join(PUBLIC_DIR, "current")

    if len(argv) == 3 and argv[1] == "--snapshot":
        snap_id = argv[2]
        return os.path.join(PUBLIC_DIR, "snapshots", snap_id)

    abort("Usage: python verify_integrity.py [--snapshot <publication_id>]")


def main():
    root = resolve_root(sys.argv)

    events_file = os.path.join(root, "journal", "events.jsonl")
    integrity_file = os.path.join(root, "integrity", "integrity.json")

    if not os.path.exists(events_file):
        abort(f"Missing {events_file}")
    if not os.path.exists(integrity_file):
        abort(f"Missing {integrity_file}")

    with open(integrity_file, "r", encoding="utf-8") as f:
        integrity = json.load(f)

    expected_hash = integrity.get("events_sha256")
    expected_count = integrity.get("event_count")

    actual_hash = compute_sha256(events_file)
    actual_count = count_events(events_file)

    if actual_hash != expected_hash:
        abort("SHA256 mismatch")
    if actual_count != expected_count:
        abort("Event count mismatch")

    print("Integrity verification successful.")
    verify_daily_roots(root, events_file)



if __name__ == "__main__":
    main()
