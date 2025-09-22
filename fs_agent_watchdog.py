# fs_agent_watchdog.py
import time, os, json, requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

API_URL = "http://localhost:8000/predict"  # عدّل لو السيرفر على IP/PORT آخر
PROCESS_NAME = "unknown"   # يمكنك تغييره إذا تملك PID ثابت لعميل محدد
PROCESS_ID = 0

class AgentHandler(FileSystemEventHandler):
    def send_trace(self, op_type, path):
        try:
            size = 0
            try:
                size = os.path.getsize(path)
            except:
                size = 0
            trace = {
                "timestamp": time.time(),
                "operation_type": op_type,
                "file_path": os.path.abspath(path),
                "offset": 0,
                "size": int(size),
                "process_id": PROCESS_ID,
                "process_name": PROCESS_NAME
            }
            r = requests.post(API_URL, json=trace, timeout=3)
            if r.status_code == 200:
                print(f"[SENT] {op_type} {path} -> prediction")
            elif r.status_code == 202:
                print(f"[BUFFERED] {op_type} {path}")
            else:
                print(f"[HTTP {r.status_code}] {r.text}")
        except Exception as e:
            print("Send error:", e)

    def on_created(self, event):
        if event.is_directory: return
        self.send_trace("write", event.src_path)

    def on_modified(self, event):
        if event.is_directory: return
        self.send_trace("write", event.src_path)

    def on_deleted(self, event):
        if event.is_directory: return
        self.send_trace("delete", event.src_path)

if __name__ == "__main__":
    path = r"C:"  
    observer = Observer()
    handler = AgentHandler()
    observer.schedule(handler, path=path, recursive=True)
    observer.start()
    print(f"Watcher started on: {path}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
