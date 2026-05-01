import json
import os
import time


def tail_log(file_path: str):
    """Continuously tail a file, yielding new lines as they appear."""
    while not os.path.exists(file_path):
        print(f"[monitor] Waiting for log file: {file_path}", flush=True)
        time.sleep(2)

    print(f"[monitor] Tailing {file_path}", flush=True)
    with open(file_path, "r") as f:
        f.seek(0, 2)  # Seek to end — only process new traffic
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.05)
                continue
            yield line


def parse_logs(file_path: str):
    """Yield parsed JSON log entries from the Nginx access log."""
    for raw in tail_log(file_path):
        raw = raw.strip()
        if not raw:
            continue
        try:
            yield json.loads(raw)
        except json.JSONDecodeError:
            continue
