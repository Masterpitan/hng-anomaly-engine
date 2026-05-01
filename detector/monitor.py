import json
import time
import os
import sys

def tail_log(file_path):
    print(f"[*] Checking path: {file_path}")
    
    # DEBUG: List everything in the directory to see what's actually there
    dir_name = os.path.dirname(file_path)
    if os.path.exists(dir_name):
        print(f"[*] Files found in {dir_name}: {os.listdir(dir_name)}")
    else:
        print(f"[!] Directory {dir_name} does not exist inside container!")

    while not os.path.exists(file_path):
        print(f"Waiting for log file at {file_path}...")
        time.sleep(2)

    print(f"[*] Success! Found {file_path}. Starting tail...")
    
    with open(file_path, 'r') as f:
        # Let's read from the beginning (SEEK_SET) to ensure we see current data
        f.seek(0)
        
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            yield line

def parse_logs(file_path):
    for line in tail_log(file_path):
        line = line.strip()
        if not line: continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            # DEBUG: Print if we found a line that isn't JSON
            print(f"[!] Non-JSON line found: {line[:50]}...")
            continue

if __name__ == "__main__":
    LOG_PATH = "/var/log/nginx/hng-access.log"
    # Ensure stdout is flushed immediately
    print(f"[*] Starting log monitor...", flush=True)
    
    for entry in parse_logs(LOG_PATH):
        print(f"New Request: {entry.get('source_ip')} -> {entry.get('path')}", flush=True)
