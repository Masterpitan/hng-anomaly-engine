import sys
import time
import yaml

from monitor import parse_logs
from baseline import TrafficBaseline
from detector import AnomalyDetector
from blocker import block_ip, get_ban_state, write_baseline_audit
from unbanner import start_unbanner
from notifier import send_slack_ban, send_slack_global
from dashboard import start_dashboard, update_state


def load_config(path: str = "/app/config.yaml") -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def main():
    cfg = load_config()

    whitelist = set(cfg.get("whitelist", []))
    log_path = cfg["log_path"]
    schedule = cfg["ban"]["backoff_schedule_minutes"]

    baseline = TrafficBaseline(cfg)
    detector = AnomalyDetector(cfg)

    start_dashboard(cfg["dashboard_port"])
    start_unbanner(cfg, baseline)

    # Track which IPs have been banned and how many times (for backoff index)
    ban_counts: dict[str, int] = {}
    # Track IPs currently banned to avoid duplicate bans
    currently_banned: set = set()
    # Track last global alert time to avoid spam
    last_global_alert = 0.0
    last_baseline_recalc = time.time()
    last_dashboard_update = time.time()

    print("[main] HNG Anomaly Engine started.", flush=True)
    print(f"[main] Monitoring: {log_path}", flush=True)
    print(f"[main] Whitelist: {whitelist}", flush=True)
    print(f"[main] Warmup period: {cfg['detection']['warmup_seconds']}s — no bans will fire until baseline is established.", flush=True)

    for entry in parse_logs(log_path):
        ip = entry.get("source_ip", "")
        status = int(entry.get("status", 200))
        is_error = status >= 400

        if ip in whitelist:
            continue

        # Feed baseline and detector
        baseline.record(is_error)
        detector.record(ip, is_error)

        mean, std = baseline.get_stats()
        error_mean, error_std = baseline.get_error_stats()

        # --- Per-IP anomaly check ---
        if ip not in currently_banned:
            anomalous, condition = detector.check_ip(
                ip, mean, std, error_mean, error_std
            )
            if anomalous:
                ban_index = ban_counts.get(ip, 0)
                duration_min = schedule[min(ban_index, len(schedule) - 1)]
                rate = detector.ip_rate(ip)

                block_ip(ip, rate, mean, condition, duration_min, ban_index)
                send_slack_ban(cfg, ip, condition, rate, mean, std, duration_min)

                ban_counts[ip] = ban_index + 1
                currently_banned.add(ip)
                print(
                    f"[main] BANNED {ip} | {condition} | rate={rate} | "
                    f"mean={mean:.2f} | duration={duration_min}m",
                    flush=True,
                )

        # Sync currently_banned with actual ban state
        currently_banned = set(get_ban_state().keys())

        # --- Global anomaly check (Slack only, no block, max 1 alert/5 min) ---
        now = time.time()
        if now - last_global_alert > 300:
            g_anomalous, g_condition = detector.check_global(mean, std)
            if g_anomalous:
                g_rate = detector.global_rate()
                send_slack_global(cfg, g_condition, g_rate, mean, std)
                last_global_alert = now
                print(f"[main] GLOBAL ANOMALY | {g_condition}", flush=True)

        # --- Baseline recalculation audit every 60s ---
        if now - last_baseline_recalc >= 60:
            stats = baseline.force_recalculate()
            if stats:
                write_baseline_audit(
                    stats["mean"], stats["std"],
                    stats["data_points"], stats["source"]
                )
            last_baseline_recalc = now

        # --- Dashboard state update every 2s ---
        if now - last_dashboard_update >= 2:
            g_rate = detector.global_rate()
            update_state(
                banned_ips=dict(get_ban_state()),
                global_rps=round(g_rate / 60, 2),
                top_ips=detector.top_ips(10),
                mean=mean,
                std=std,
            )
            last_dashboard_update = now


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[main] Shutting down.", flush=True)
        sys.exit(0)
