import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import psutil

_state = {
    "banned_ips": {},
    "global_rps": 0.0,
    "top_ips": [],
    "mean": 0.0,
    "std": 0.0,
    "uptime_start": time.time(),
}
_lock = threading.Lock()

_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="refresh" content="3">
<title>HNG Anomaly Engine — Live Metrics</title>
<style>
  body{{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:20px}}
  h1{{color:#58a6ff}}
  table{{border-collapse:collapse;width:100%%;margin-bottom:20px}}
  th,td{{border:1px solid #30363d;padding:8px 12px;text-align:left}}
  th{{background:#161b22;color:#58a6ff}}
  .badge-ban{{color:#f85149}} .badge-ok{{color:#3fb950}}
  .card{{background:#161b22;border:1px solid #30363d;border-radius:6px;
         padding:14px;margin-bottom:16px;display:inline-block;min-width:160px;margin-right:12px}}
  .card-val{{font-size:2em;font-weight:bold;color:#58a6ff}}
  .card-lbl{{font-size:.8em;color:#8b949e}}
</style>
</head>
<body>
<h1>&#128737; HNG Anomaly Engine — Live Metrics</h1>
<p style="color:#8b949e">Auto-refreshes every 3 seconds &nbsp;|&nbsp; Uptime: <b>{uptime}</b></p>
<div>
  <div class="card"><div class="card-val">{global_rps:.1f}</div><div class="card-lbl">Global req/s</div></div>
  <div class="card"><div class="card-val">{banned_count}</div><div class="card-lbl">Banned IPs</div></div>
  <div class="card"><div class="card-val">{mean:.2f}</div><div class="card-lbl">Baseline Mean</div></div>
  <div class="card"><div class="card-val">{std:.2f}</div><div class="card-lbl">Baseline Std</div></div>
  <div class="card"><div class="card-val">{cpu:.1f}%</div><div class="card-lbl">CPU Usage</div></div>
  <div class="card"><div class="card-val">{mem:.1f}%</div><div class="card-lbl">Memory Usage</div></div>
</div>
<h2>&#128683; Banned IPs</h2>
{banned_table}
<h2>&#128200; Top 10 Source IPs (last 60s)</h2>
{top_table}
</body>
</html>
"""


def _fmt_uptime(start: float) -> str:
    secs = int(time.time() - start)
    h, rem = divmod(secs, 3600)
    m, s = divmod(rem, 60)
    return f"{h}h {m}m {s}s"


def _banned_table(banned: dict) -> str:
    if not banned:
        return '<p class="badge-ok">No IPs currently banned.</p>'
    rows = ""
    now = time.time()
    for ip, state in banned.items():
        dur = state["duration_min"]
        elapsed = int((now - state["banned_at"]) / 60)
        dur_label = "permanent" if dur == -1 else f"{dur} min"
        rows += f"<tr><td>{ip}</td><td>{dur_label}</td><td>{elapsed} min ago</td></tr>"
    return (
        "<table><tr><th>IP</th><th>Ban Duration</th><th>Banned</th></tr>"
        + rows + "</table>"
    )


def _top_table(top: list) -> str:
    if not top:
        return "<p>No traffic yet.</p>"
    rows = "".join(f"<tr><td>{ip}</td><td>{count}</td></tr>" for ip, count in top)
    return (
        "<table><tr><th>IP</th><th>Requests (last 60s)</th></tr>"
        + rows + "</table>"
    )


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # Suppress access logs for the dashboard itself

    def do_GET(self):
        if self.path == "/metrics":
            self._serve_json()
        else:
            self._serve_html()

    def _serve_html(self):
        with _lock:
            s = dict(_state)
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory().percent
        body = _HTML.format(
            uptime=_fmt_uptime(s["uptime_start"]),
            global_rps=s["global_rps"],
            banned_count=len(s["banned_ips"]),
            mean=s["mean"],
            std=s["std"],
            cpu=cpu,
            mem=mem,
            banned_table=_banned_table(s["banned_ips"]),
            top_table=_top_table(s["top_ips"]),
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_json(self):
        with _lock:
            s = dict(_state)
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory().percent
        data = json.dumps({
            "global_rps": s["global_rps"],
            "banned_ips": list(s["banned_ips"].keys()),
            "top_ips": s["top_ips"],
            "mean": s["mean"],
            "std": s["std"],
            "cpu_percent": cpu,
            "mem_percent": mem,
            "uptime_seconds": int(time.time() - s["uptime_start"]),
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def update_state(banned_ips: dict, global_rps: float, top_ips: list,
                 mean: float, std: float):
    with _lock:
        _state["banned_ips"] = banned_ips
        _state["global_rps"] = global_rps
        _state["top_ips"] = top_ips
        _state["mean"] = mean
        _state["std"] = std


def start_dashboard(port: int):
    server = HTTPServer(("", port), _Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    print(f"[dashboard] Live metrics at http://0.0.0.0:{port}", flush=True)
