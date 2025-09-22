




import os
import time
import argparse
import random
from pathlib import Path

def make_file(path: Path, size_kb: int):
    with open(path, "wb") as f:
        f.write(os.urandom(size_kb * 1024))

def append_to_file(path: Path, size_kb: int):
    with open(path, "ab") as f:
        f.write(os.urandom(size_kb * 1024))

def simulate(target_dir: Path, files_count: int, writes_per_file: int, size_kb: int, delay_between_ops: float):
    target_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    for i in range(files_count):
        p = target_dir / f"sim_file_{i}.bin"
        make_file(p, size_kb)   # create initial file
        paths.append(p)
        time.sleep(0.01)

    for w in range(writes_per_file):
        p = random.choice(paths)
        append_to_file(p, size_kb)
        if random.random() < 0.05:
            newp = p.with_name(p.stem + f"_mod{w}" + p.suffix)
            try:
                p.replace(newp)
                newp.replace(p)
            except Exception:
                pass
        time.sleep(delay_between_ops)

def main():
    parser = argparse.ArgumentParser(description="Safe ransomware-like I/O simulator")
    parser.add_argument("--target", "-t", required=True, help="Target folder to run simulation in (must be inside VM!)")
    parser.add_argument("--start-delay", "-s", type=int, default=300, help="Delay before starting (seconds). Default 300s = 5 minutes")
    parser.add_argument("--files", "-f", type=int, default=200, help="Number of files to create")
    parser.add_argument("--writes", "-w", type=int, default=2000, help="Total write operations (loop count)")
    parser.add_argument("--size-kb", type=int, default=4, help="Size per write in KB (default 4KB)")
    parser.add_argument("--interval", "-i", type=float, default=0.02, help="Delay between operations in seconds")
    args = parser.parse_args()

    target = Path(args.target).resolve()
    # Safety checks
    if not str(target).startswith(("C:\\", "/")):
        print("Invalid target path.")
        return
    if ":\\" in str(target) and (str(target).count(":") > 1):
        print("Invalid path.")
        return
    print(f"[SIM] Starting simulator. Will wait {args.start_delay} seconds before action.")
    print(f"[SIM] Target folder: {target}")
    print("**Make sure this VM is isolated and snapshot was taken.**")
    time.sleep(args.start_delay)
    print("[SIM] Starting aggressive I/O now...")
    try:
        simulate(target, args.files, args.writes, args.size_kb, args.interval)
    except KeyboardInterrupt:
        print("[SIM] Stopped by user.")
    except Exception as e:
        print("[SIM] Error:", e)
    print("[SIM] Done. Files created/modified in:", target)

if __name__ == "__main__":
    main()
