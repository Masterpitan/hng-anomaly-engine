import json
import os
import time
import requests


def _webhook_url(cfg) -> str:
    env_var = cfg["slack"]["webhook_env_var"]
    return os.getenv(env_var, "")


def _post(url: str, payload: dict):
    if not url:
        print("[notifier] SLACK_WEBHOOK_URL not set — skipping alert.", flush=True)
        return
    try:
        r = requests.post(url, data=json.dumps(payload),
                          headers={"Content-Type": "application/json"}, timeout=10)
        if r.status_code != 200:
            print(f"[notifier] Slack returned {r.status_code}", flush=True)
    except Exception as e:
        print(f"[notifier] Slack error: {e}", flush=True)


def send_slack_ban(cfg, ip: str, condition: str, rate: int,
                   mean: float, std: float, duration_min: int):
    url = _webhook_url(cfg)
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    dur_label = "permanent" if duration_min == -1 else f"{duration_min} min"
    payload = {
        "text": (
            f":rotating_light: *[HNG Anomaly Engine] IP BANNED*\n"
            f"• *IP:* `{ip}`\n"
            f"• *Condition:* {condition}\n"
            f"• *Current Rate:* {rate} req/60s\n"
            f"• *Baseline Mean:* {mean:.2f} | *Std:* {std:.2f}\n"
            f"• *Ban Duration:* {dur_label}\n"
            f"• *Timestamp:* {ts}"
        )
    }
    _post(url, payload)


def send_slack_global(cfg, condition: str, rate: int, mean: float, std: float):
    url = _webhook_url(cfg)
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    payload = {
        "text": (
            f":warning: *[HNG Anomaly Engine] GLOBAL TRAFFIC SPIKE*\n"
            f"• *Condition:* {condition}\n"
            f"• *Global Rate:* {rate} req/60s\n"
            f"• *Baseline Mean:* {mean:.2f} | *Std:* {std:.2f}\n"
            f"• *Timestamp:* {ts}"
        )
    }
    _post(url, payload)


def send_slack_unban(ip: str, prev_duration: int, next_duration: int, mean: float):
    """Unban alert — cfg not available here so reads env directly."""
    url = os.getenv("SLACK_WEBHOOK_URL", "")
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    prev_label = "permanent" if prev_duration == -1 else f"{prev_duration} min"
    next_label = "permanent" if next_duration == -1 else f"{next_duration} min"
    payload = {
        "text": (
            f":white_check_mark: *[HNG Anomaly Engine] IP UNBANNED*\n"
            f"• *IP:* `{ip}`\n"
            f"• *Previous Ban Duration:* {prev_label}\n"
            f"• *Next Ban Duration (if re-offends):* {next_label}\n"
            f"• *Baseline Mean at Unban:* {mean:.2f}\n"
            f"• *Timestamp:* {ts}"
        )
    }
    if not url:
        print("[notifier] SLACK_WEBHOOK_URL not set — skipping unban alert.", flush=True)
        return
    try:
        r = requests.post(url, data=json.dumps(payload),
                          headers={"Content-Type": "application/json"}, timeout=10)
        if r.status_code != 200:
            print(f"[notifier] Slack unban returned {r.status_code}", flush=True)
    except Exception as e:
        print(f"[notifier] Slack unban error: {e}", flush=True)
