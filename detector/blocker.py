import re
import subprocess
import time

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# ip -> {"banned_at": float, "ban_index": int, "duration_min": int}
_ban_state: dict = {}

AUDIT_LOG = "/app/audit.log"


def _valid_ip(ip: str) -> bool:
    return bool(_IP_RE.match(ip))


def _write_audit(entry: str):
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    line = f"[{ts}] {entry}\n"
    try:
        with open(AUDIT_LOG, "a") as f:
            f.write(line)
    except Exception as e:
        print(f"[audit] write error: {e}", flush=True)
    print(f"[AUDIT] {line.strip()}", flush=True)


def _iptables(args: list):
    try:
        subprocess.run(["/sbin/iptables"] + args, check=True,
                       capture_output=True, text=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"[blocker] iptables error: {e.stderr.strip()}", flush=True)
        return False


def block_ip(ip: str, rate: int, mean: float, condition: str,
             duration_min: int, ban_index: int):
    if not _valid_ip(ip):
        print(f"[blocker] Invalid IP skipped: {ip}", flush=True)
        return

    # Check if rule already exists
    result = subprocess.run(
        ["/sbin/iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        _iptables(["-A", "INPUT", "-s", ip, "-j", "DROP"])

    dur_label = "permanent" if duration_min == -1 else f"{duration_min}m"
    _ban_state[ip] = {
        "banned_at": time.time(),
        "ban_index": ban_index,
        "duration_min": duration_min,
    }
    _write_audit(
        f"BAN {ip} | {condition} | rate={rate} | baseline_mean={mean:.2f} | duration={dur_label}"
    )


def unblock_ip(ip: str, condition: str, rate: int, mean: float, duration_min: int):
    if not _valid_ip(ip):
        return
    _iptables(["-D", "INPUT", "-s", ip, "-j", "DROP"])
    dur_label = "permanent" if duration_min == -1 else f"{duration_min}m"
    _write_audit(
        f"UNBAN {ip} | {condition} | rate={rate} | baseline_mean={mean:.2f} | prev_duration={dur_label}"
    )
    _ban_state.pop(ip, None)


def write_baseline_audit(mean: float, std: float, data_points: int, source: str):
    _write_audit(
        f"BASELINE_RECALC | mean={mean:.4f} | std={std:.4f} | "
        f"data_points={data_points} | source={source}"
    )


def get_ban_state() -> dict:
    return _ban_state
