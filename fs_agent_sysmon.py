# fs_agent_sysmon_batch.py
"""
Sysmon -> batch sender for ransomware detection platform
- Reads new Sysmon events (default EventID 11: File Create)
- Batches events and posts to /traces/batch
- Tracks last processed record number in a small state file
"""

import time
import json
import requests
import os
from typing import List, Optional

try:
    import win32evtlog
except Exception as e:
    print("This script requires pywin32 (win32evtlog). Install with: pip install pywin32")
    raise

# CONFIG
API_BATCH_URL = "http://localhost:8000/traces/batch"   # adjust as needed
LOG_TYPE = "Microsoft-Windows-Sysmon/Operational"     # Sysmon operational channel
SERVER = "localhost"
STATE_FILE = "sysmon_last_record.txt"
POLL_INTERVAL = 3               # seconds between polls for new events
BATCH_SIZE = 200                # how many traces to send in one request
EVENT_IDS = {11}                # Sysmon EventIDs to process (11 = FileCreate by default)

# Helper: load last processed record number
def load_last_record() -> int:
    if not os.path.exists(STATE_FILE):
        return 0
    try:
        return int(open(STATE_FILE, "r").read().strip() or 0)
    except Exception:
        return 0

def save_last_record(n: int):
    try:
        open(STATE_FILE, "w").write(str(int(n)))
    except Exception:
        pass

# Convert a win32 event to our trace dict. This is defensive — Sysmon event format may vary by config.
def event_to_trace(evt) -> Optional[dict]:
    try:
        # often Sysmon FileCreate (ID 11) has StringInserts like:
        # [Image, TargetFilename, ...]  but depends on your config
        inserts = evt.StringInserts
        if not inserts:
            return None

        # try to detect filename and image heuristically
        # common layout: [Image, TargetFilename, ...]
        image = inserts[0] if len(inserts) > 0 else "unknown"
        filename = None
        # search for something that looks like path
        for s in inserts:
            if isinstance(s, str) and ("\\" in s or "/" in s):
                # skip images that are executables (contain .exe at end)
                if s.lower().endswith(".exe") and filename is None:
                    image = s
                    continue
                filename = s
                break

        # fallback: if no path found, try known positions
        if filename is None and len(inserts) > 1:
            filename = inserts[1]

        if filename is None:
            return None

        process_name = os.path.basename(image) if image else "unknown"
        pid = 0
        # Some Sysmon configs include ProcessId in StringInserts; try to find numeric token
        for s in inserts:
            if s and s.isdigit():
                pid = int(s)
                break

        trace = {
            "timestamp": time.time(),
            "operation_type": "write",   # Sysmon FileCreate assumed as write-like
            "file_path": filename,
            "offset": 0,
            "size": 0,
            "process_id": int(pid),
            "process_name": process_name
        }
        return trace
    except Exception as e:
        print("event_to_trace parse error:", e)
        return None

# Send a batch of traces to the API, with retries (simple)
def send_batch(traces: List[dict]):
    if not traces:
        return
    try:
        r = requests.post(API_BATCH_URL, json=traces, timeout=20)
        if r.status_code == 200:
            j = r.json()
            print(f"[SENT] batch size={len(traces)} -> processed={j.get('traces_processed')} predictions={j.get('predictions_made')}")
        else:
            print(f"[HTTP {r.status_code}] batch send failed: {r.text[:200]}")
    except Exception as e:
        print("Batch send exception:", e)

def tail_sysmon_loop():
    last_seen = load_last_record()
    print("Starting sysmon tail loop. last_seen_record =", last_seen)
    try:
        hand = win32evtlog.OpenEventLog(SERVER, LOG_TYPE)
    except Exception as e:
        print("Failed to open event log:", e)
        return

    # We'll poll for new events. We'll read backwards (newest first) and stop when we hit last_seen.
    while True:
        try:
            # get current total records
            try:
                total_records = win32evtlog.GetNumberOfEventLogRecords(hand)
            except Exception:
                total_records = 0

            # read newest events first
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            if not events:
                time.sleep(POLL_INTERVAL)
                continue

            batch = []
            max_record_in_this_poll = last_seen

            # events is an iterable of EVENTLOGRECORDs newest->older when using BACKWARDS_READ
            for evt in events:
                try:
                    rec_no = getattr(evt, "RecordNumber", None)
                    if rec_no is None:
                        # fallback: skip if can't determine
                        continue

                    # track max record
                    if rec_no > max_record_in_this_poll:
                        max_record_in_this_poll = rec_no

                    # skip if already processed
                    if rec_no <= last_seen:
                        # since events are newest first, once we see a record <= last_seen we can stop scanning
                        break

                    ev_id = int(evt.EventID) if hasattr(evt, "EventID") else None
                    if ev_id not in EVENT_IDS:
                        continue

                    trace = event_to_trace(evt)
                    if trace:
                        batch.append(trace)

                    # send when batch full
                    if len(batch) >= BATCH_SIZE:
                        send_batch(batch)
                        batch = []

                except Exception as e:
                    # per-event error — print and continue
                    print("Per-event error:", e)
                    continue

            # send remaining
            if batch:
                send_batch(batch)

            # update last_seen if we observed newer records
            if max_record_in_this_poll > last_seen:
                last_seen = max_record_in_this_poll
                save_last_record(last_seen)
                # debug print
                print("Updated last_seen to", last_seen)

        except Exception as e:
            print("Polling exception:", e)

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    print("Sysmon batch agent starting. Config:")
    print(f"  LOG_TYPE={LOG_TYPE}")
    print(f"  API_BATCH_URL={API_BATCH_URL}")
    print(f"  EVENT_IDS={EVENT_IDS}")
    print(f"  BATCH_SIZE={BATCH_SIZE}, POLL_INTERVAL={POLL_INTERVAL}s")
    tail_sysmon_loop()
