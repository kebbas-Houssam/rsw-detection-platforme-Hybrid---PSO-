# aggressive_stream.py
import requests, time, random

BASE="http://localhost:8000"
URL=f"{BASE}/predict"
PROCESS_NAME="ransom_sim.exe"
PID=4242

def make_trace(i, file_idx):
    op = random.choices(["read","write"], weights=[0.02,0.98])[0]
    size = random.choice([4096,8192,16384,32768])
    offset = file_idx * 4096 + (i % 16) * 4096
    return {
        "timestamp": time.time(),
        "operation_type": op,
        "file_path": f"C:\\Users\\test\\ransom_sim\\file_{file_idx}.dat",
        "offset": offset,
        "size": size,
        "process_id": PID,
        "process_name": PROCESS_NAME
    }

def run_stream(interval=0.03, files_cycle=20):
    i = 0
    try:
        while True:
            file_idx = i % files_cycle
            trace = make_trace(i, file_idx)
            try:
                r = requests.post(URL, json=trace, timeout=5)
                if r.status_code == 200:
                    j = r.json()
                    print(f"[{i}] Prediction 200 hybrid={j.get('hybrid_prediction')}")
                elif r.status_code == 202:
                    print(f"[{i}] Buffered (202)")
                else:
                    print(f"[{i}] HTTP {r.status_code}")
            except Exception as e:
                print(f"[{i}] Request error: {e}")
            i += 1
            time.sleep(interval)
    except KeyboardInterrupt:
        print("Stopped by user.")

if __name__ == "__main__":
    run_stream(interval=0.03, files_cycle=20)
