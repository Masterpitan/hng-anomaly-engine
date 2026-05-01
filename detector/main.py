from monitor import parse_logs
from baseline import TrafficTracker
from notifier import send_slack_alert
from blocker import block_ip
import sys
import threading
import http.server
import socketserver

# Whitelisting my own IP
NOTIFIED_IPS = set()
WHITELIST = ["127.0.0.1", "13.221.5.54", "102.89.76.141"]

def run_dashboard():
    PORT = 8000
    Handler = http.server.SimpleHTTPRequestHandler
    with sockerserver.TCPServer(("", PORT), Handler) as httpd:
        print(f"[*] Serving Live Metrics Dashboard at port {PORT}", flush=True)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            httpd.server_close()
def run_engine():
    LOG_PATH = "/var/log/nginx/hng-access.log"
    tracker = TrafficTracker()
    
    print("[*] HNG Anomaly Engine: ACTIVATED", flush=True)
    print(f"[*] Monitoring: {LOG_PATH}", flush=True)
    print(f"[*] Whitelist: {WHITELIST}", flush=True)

    for entry in parse_logs(LOG_PATH):
        ip = entry['source_ip']
        
        # Skip Whitelisted IPs
        if ip in WHITELIST:
            continue
            
        tracker.add_request(ip)
        
        # Get current metrics
        ip_rpm = len(tracker.ip_windows.get(ip, []))
        z_score = tracker.get_z_score(ip_rpm)
        
        # Trigger condition: Z-score > 3 and at least 50 requests
        if z_score > 3.5 and ip_rpm > 70:
            if ip not in NOTIFIED_IPS:
                print(f"\n[!!!] THREAT DETECTED: {ip}", flush=True)
                block_ip(ip, ip_rpm, tracker.mean)
                send_slack_alert(ip, ip_rpm, z_score)

                NOTIFIED_IPS.add(ip)
            
        elif ip_rpm % 20 == 0 and ip_rpm > 0:
            # Low-frequency status update
            print(f"[LIVE] IP: {ip} | RPM: {ip_rpm} | Z: {z_score:.1f} | Mean: {tracker.mean:.1f}", flush=True)

if __name__ == "__main__":
    dashboard_thread = threading.Thread(target=run_dashboard, daemon=True)
    dashboard_thread.start()
    try:
        run_engine()
    except KeyboardInterrupt:
        print("\n[*] Engine shutting down safely.")
        sys.exit(0)
