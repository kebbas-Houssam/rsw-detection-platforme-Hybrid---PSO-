


import time, requests, random, argparse, math

def generate_offset_pattern(mode, file_idx, step_idx, params):
    # mode: 'small_wss' | 'repeating_blocks' | 'sequential'
    base = params.get('base_offset', 0)
    block = params.get('block_size', 4096)
    wss = params.get('wss', 8)
    if mode == 'small_wss':
        # اختَر من نطاق صغير من offsets (لتقليل WSS & entropy)
        return base + (step_idx % wss) * block
    if mode == 'repeating_blocks':
        # تكرار لنفس البلوكات عبر ملفات
        return base + ((file_idx % wss) * block) + ((step_idx % 4) * block)
    return base + (file_idx * block) + ((step_idx % 16) * block)

def make_trace(i, file_idx, params):
    # عملية؛ نتحكم في احتمال الكتابة والقراءة
    write_prob = params.get('write_prob', 0.95)
    op = 'write' if random.random() < write_prob else 'read'
    offset = generate_offset_pattern(params.get('offset_mode','small_wss'), file_idx, i, params)
    size = random.choice(params.get('sizes',[4096,8192,16384]))
    # insert war (write-after-read): if enable, sometimes send a read then immediate write at same offset
    return {
        "timestamp": time.time(),
        "operation_type": op,
        "file_path": f"C:\\ransom_test\\file_{file_idx}.bin",
        "offset": int(offset),
        "size": int(size),
        "process_id": int(params.get('pid',4242)),
        "process_name": params.get('process_name',"ransom_sim.exe")
    }

def run(api_url, params):
    total = params.get('total_traces', 20000)
    files = params.get('files', 200)
    interval = params.get('interval', 0.01)
    start_delay = params.get('start_delay', 10)
    burst_size = params.get('burst_size', 50)  # produce bursts
    print(f"[SIM] waiting {start_delay}s before start")
    time.sleep(start_delay)
    print("[SIM] start sending traces...")
    i = 0
    while i < total:
        # create bursts to increase burstiness
        for b in range(burst_size):
            file_idx = i % files
            trace = make_trace(i, file_idx, params)
            try:
                r = requests.post(api_url, json=trace, timeout=5)
                if r.status_code == 200:
                    j = r.json()
                    print(f"[{i}] PRED hybrid={j.get('hybrid_prediction'):.3f} (alert={j.get('hybrid_prediction')>params.get('threshold',0.24)})")
                elif r.status_code == 202:
                    print(f"[{i}] Buffered (202)")
                else:
                    print(f"[{i}] HTTP {r.status_code}")
            except Exception as e:
                print(f"[{i}] Request err:", e)
            i += 1
            if i >= total: break
        # short pause between bursts (very small to keep burstiness high)
        time.sleep(interval)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--api", default="http://localhost:8000/predict")
    parser.add_argument("--total", type=int, default=20000)
    parser.add_argument("--files", type=int, default=200)
    parser.add_argument("--interval", type=float, default=0.01)
    parser.add_argument("--start-delay", type=int, default=10)
    parser.add_argument("--burst-size", type=int, default=50)
    parser.add_argument("--write-prob", type=float, default=0.98)
    parser.add_argument("--wss", type=int, default=6)
    parser.add_argument("--offset-mode", default="small_wss", choices=["small_wss","repeating_blocks","sequential"])
    parser.add_argument("--sizes", default="4096,8192,16384")
    parser.add_argument("--pid", type=int, default=4242)
    parser.add_argument("--process-name", default="ransom_sim.exe")
    args = parser.parse_args()

    sizes = [int(x) for x in args.sizes.split(",")]
    params = {
        "write_prob": args.write_prob,
        "wss": args.wss,
        "offset_mode": args.offset_mode,
        "sizes": sizes,
        "files": args.files,
        "total_traces": args.total,
        "interval": args.interval,
        "start_delay": args.start_delay,
        "burst_size": args.burst_size,
        "pid": args.pid,
        "process_name": args.process_name,
        "threshold": 0.24
    }
    run(args.api, params)
