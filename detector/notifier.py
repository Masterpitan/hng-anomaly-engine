import os
import json
import requests

def send_slack_alert(ip, rpm, z_score):
    """Sends an alert to Slack using an environment variable for the webhook URL."""
    webhook_url = os.getenv('SLACK_WEBHOOK_URL')

    if not webhook_url:
        print("[!] Error: SLACK_WEBHOOK_URL environment variable is not set.", flush=True)
        return

    payload = {
        'text': f"🚨 *[HNG Anomaly Engine]* Anomaly Detected!\n"
                f"• *IP:* {ip}\n"
                f"• *Request Rate:* {rpm} RPM\n"
                f"• *Z-Score:* {z_score:.2f}"
    }

    try:
        response = requests.post(
            webhook_url, 
            data=json.dumps(payload), 
            headers={'Content-Type': 'application/json'},
            timeout=10
        )
        if response.status_code == 200:
            print(f"[Notifier] Alert sent successfully for {ip}", flush=True)
        else:
            print(f"[Notifier] Failed to send alert: {response.status_code}", flush=True)
    except Exception as e:
        print(f"[Notifier] Connection Error: {e}", flush=True)
