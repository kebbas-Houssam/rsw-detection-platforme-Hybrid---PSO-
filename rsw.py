import os
import time
import argparse
import random
import threading
from pathlib import Path
import shutil
import sys

# --- Helpers ---
def human(n):
    for unit in ['B','KB','MB','GB','TB']:
        if abs(n) < 1024.0:
            return f"{n:3.1f}{unit}"
        n /= 1024.0
    return f"{n:.1f}PB"

def free_space_bytes(path):
    # يعيد البايتات الحرة على نفس القرص
    usage = shutil.disk_usage(path)
    return usage.free

# --- File ops ---
def make_file(path: Path, size_kb:int):
    # كتابة ملف جديد بحجم size_kb KB
    # نفتح في وضع wb ونكتب كتلة عشوائية مقسمة لتقليل استخدام الذاكرة
    block = os.urandom(4096)
    to_write = size_kb * 1024
    written = 0
    with open(path, "wb") as f:
        while written < to_write:
            f.write(block)
            written += len(block)

def append_to_file(path: Path, size_kb:int):
    block = os.urandom(4096)
    to_write = size_kb * 1024
    written = 0
    with open(path, "ab") as f:
        while written < to_write:
            f.write(block)
            written += len(block)

# --- Worker thread ---
def worker_thread(thread_id, params, stop_event):
    tgt = params['target']
    files = params['files']
    writes_per_file = params['writes_per_file']
    size_kb = params['size_kb']
    interval = params['interval']
    mode = params['mode']  # "disk" or "api"
    api_func = params.get('api_func', None)
    safety_min_free = params['safety_min_free']

    # create initial files if needed
    for i in range(thread_id, files, params['concurrency']):
        if stop_event.is_set(): return
        p = tgt / f"sim_thr{thread_id}_file_{i}.bin"
        try:
            make_file(p, size_kb)
        except Exception as e:
            print(f"[T{thread_id}] create error {p}: {e}")
            stop_event.set()
            return

    # aggressive writes loop
    ops = 0
    while not stop_event.is_set():
        # check free space
        free = free_space_bytes(str(tgt))
        if free < safety_min_free:
            print(f"[T{thread_id}] Low disk free {human(free)} < safety_min_free. Stopping thread.")
            stop_event.set()
            return

        file_idx = random.randrange(0, files)
        p = tgt / f"sim_thr{thread_id}_file_{file_idx}.bin"
        try:
            # 80% append, 10% rewrite, 10% rename pattern
            r = random.random()
            if r < 0.8:
                append_to_file(p, size_kb)
                action = "append"
            elif r < 0.9:
                # rewrite by replace
                tmp = p.with_suffix(".tmp")
                make_file(tmp, size_kb)
                tmp.replace(p)
                action = "rewrite"
            else:
                newp = p.with_name(p.stem + f"_mod{int(time.time()*1000)}" + p.suffix)
                p.replace(newp)
                # sometimes rename back
                if random.random() < 0.6:
                    newp.replace(p)
                action = "rename"
            ops += 1
            if ops % 50 == 0:
                print(f"[T{thread_id}] ops={ops} free={human(free)} last_action={action}")
        except Exception as e:
            print(f"[T{thread_id}] write error {e}")
            stop_event.set()
            return

        time.sleep(interval)

# --- Estimation ---
def estimate_bytes(files, writes_per_file, size_kb):
    # تقدير تقريبي: files initial + writes_per_file total * size_kb
    total_ops = files + writes_per_file
    total_bytes = total_ops * size_kb * 1024
    return total_bytes

# --- Main ---
def main():
    parser = argparse.ArgumentParser(description="Aggressive safe I/O simulator (multi-threaded)")
    parser.add_argument("--target","-t", required=True, help="Target folder (must be inside isolated VM)")
    parser.add_argument("--start-delay","-s", type=int, default=60, help="Seconds before start (default 60s)")
    parser.add_argument("--files","-f", type=int, default=1000, help="Number of files to create per whole run (not per thread)")
    parser.add_argument("--writes","-w", type=int, default=20000, help="Total number of write operations (approx)")
    parser.add_argument("--size-kb","-z", type=int, default=16, help="Size per create/append in KB (default 16KB)")
    parser.add_argument("--interval","-i", type=float, default=0.005, help="Sleep between ops per thread (sec). Smaller = more aggressive")
    parser.add_argument("--concurrency","-c", type=int, default=8, help="Number of worker threads (default 8)")
    parser.add_argument("--safety-min-free-mb","-m", type=int, default=200, help="Min free MB on disk to keep (stop if lower). Default 200MB")
    parser.add_argument("--no-snapshot-check", action="store_true", help="Bypass snapshot reminder")
    args = parser.parse_args()

    tgt = Path(args.target).resolve()
    if not tgt.exists():
        print("Creating target folder:", tgt)
        try:
            tgt.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            print("Cannot create target:", e); sys.exit(1)

    if not args.no_snapshot_check:
        print("!!! تأكد أنك أخذت snapshot للـ VM وأن الـ VM معزول (Host-only/Disconnected). !!!")
        print("Start delay:", args.start_delay, "s")
        print("Target:", tgt)
        ans = input("هل أخذت snapshot وتأكدت من العزل؟ (y/N) ")
        if ans.strip().lower() != "y":
            print("Aborting. خذ snapshot ثم أعد المحاولة.")
            sys.exit(1)

    # estimate
    est_bytes = estimate_bytes(args.files, args.writes, args.size_kb)
    print(f"Estimated total write: {human(est_bytes)}")
    free_before = free_space_bytes(str(tgt))
    print(f"Free disk at target: {human(free_before)}")
    if est_bytes > free_before * 0.9:
        print("Warning: estimated writes are close to or exceed available free space. Aborting.")
        sys.exit(1)

    # compute per-thread distribution
    writes_per_thread = max(1, args.writes // args.concurrency)
    writes_per_file = max(1, args.writes // max(1, args.files))
    print(f"Threads: {args.concurrency} | files: {args.files} | writes_total: {args.writes} | size_kb: {args.size_kb}")
    print("Sleeping until start-delay...")
    time.sleep(args.start_delay)

    params = {
        'target': tgt,
        'files': args.files,
        'writes_per_file': writes_per_file,
        'size_kb': args.size_kb,
        'interval': args.interval,
        'concurrency': args.concurrency,
        'mode': 'disk',
        'safety_min_free': args.safety_min_free_mb * 1024 * 1024
    }

    stop_event = threading.Event()
    threads = []
    try:
        for tid in range(args.concurrency):
            t = threading.Thread(target=worker_thread, args=(tid, params, stop_event), daemon=True)
            t.start()
            threads.append(t)

        print("Workers started. Press Ctrl+C to stop manually.")
        while any(t.is_alive() for t in threads):
            time.sleep(1)
    except KeyboardInterrupt:
        print("KeyboardInterrupt -> stopping...")
        stop_event.set()
    finally:
        stop_event.set()
        for t in threads:
            t.join(timeout=2)
        print("All workers stopped. Done.")

if __name__ == "__main__":
    main()
