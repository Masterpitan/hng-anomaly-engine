import time
import subprocess

AUDIT_LOG = "audit.log"

def block_ip(ip, rate, baseline_mean):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    condition = "Z-Score Anomaly"
    duration = "10m"

    # Required Format: [timestamp] ACTION ip | condition | rate | baseline | duration
    log_entry = f"[{timestamp}] BAN {ip} | {condition} | {rate} RPM | Mean: {baseline_mean:.1f} | {duration}\n"

    # 1. Write to Audit Log
    with open(AUDIT_LOG, "a") as f:
        f.write(log_entry)

    print(f"[AUDIT] {log_entry.strip()}", flush=True)

    # 2. Check if rule exists before executing to prevent duplicate errors
    try:
        check_cmd = ["sudo", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"]
        res = subprocess.run(check_cmd, capture_output=True, text=True)
        
        # If return code is not 0, the rule does not exist
        if res.returncode != 0:
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            print(f"[*] IPTables rule added for {ip}")
        else:
            print(f"[*] IPTables rule already exists for {ip}")
            
    except Exception as e:
        print(f"[!] Firewall Error: {e}")

def unblock_ip(ip):
    try:
        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        print(f"[*] IP {ip} has been released.")
    except Exception as e:
        print(f"[!] Unblock Error: {e}")
