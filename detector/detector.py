import time
from collections import deque, defaultdict


class AnomalyDetector:
    """
    Tracks per-IP and global request rates using deque-based sliding windows.
    Detects anomalies via z-score > threshold OR rate > N x baseline mean.
    Requires confirm_strikes consecutive anomaly checks before issuing a ban,
    so a single page-load burst never triggers a false positive.
    """

    def __init__(self, cfg):
        self.ip_window_secs = cfg["detection"]["ip_window_seconds"]
        self.global_window_secs = cfg["detection"]["global_window_seconds"]
        self.z_threshold = cfg["detection"]["z_score_threshold"]
        self.rate_multiplier = cfg["detection"]["rate_multiplier_threshold"]
        self.error_multiplier = cfg["detection"]["error_rate_multiplier"]
        self.min_requests_to_ban = cfg["detection"]["min_requests_to_ban"]
        self.confirm_strikes = cfg["detection"]["confirm_strikes"]
        self.warmup_seconds = cfg["detection"]["warmup_seconds"]
        self._start_time = time.time()

        # deque of timestamps per IP for the sliding window
        self._ip_windows: dict[str, deque] = defaultdict(deque)
        # deque of timestamps for global window
        self._global_window: deque = deque()
        # per-IP error timestamps
        self._ip_error_windows: dict[str, deque] = defaultdict(deque)
        # consecutive anomaly strike counter per IP — resets when IP calms down
        self._strikes: dict[str, int] = defaultdict(int)

    def record(self, ip: str, is_error: bool):
        now = time.time()
        cutoff_ip = now - self.ip_window_secs
        cutoff_global = now - self.global_window_secs

        dq = self._ip_windows[ip]
        dq.append(now)
        while dq and dq[0] < cutoff_ip:
            dq.popleft()

        if is_error:
            edq = self._ip_error_windows[ip]
            edq.append(now)
            while edq and edq[0] < cutoff_ip:
                edq.popleft()

        self._global_window.append(now)
        while self._global_window and self._global_window[0] < cutoff_global:
            self._global_window.popleft()

    def _evict(self, ip: str):
        now = time.time()
        cutoff = now - self.ip_window_secs
        dq = self._ip_windows.get(ip)
        if dq:
            while dq and dq[0] < cutoff:
                dq.popleft()

    def ip_rate(self, ip: str) -> int:
        self._evict(ip)
        return len(self._ip_windows.get(ip, deque()))

    def global_rate(self) -> int:
        return len(self._global_window)

    def ip_error_rate(self, ip: str) -> int:
        now = time.time()
        cutoff = now - self.ip_window_secs
        edq = self._ip_error_windows.get(ip, deque())
        while edq and edq[0] < cutoff:
            edq.popleft()
        return len(edq)

    def top_ips(self, n: int = 10) -> list:
        now = time.time()
        cutoff = now - self.ip_window_secs
        counts = []
        for ip, dq in self._ip_windows.items():
            while dq and dq[0] < cutoff:
                dq.popleft()
            if dq:
                counts.append((ip, len(dq)))
        counts.sort(key=lambda x: x[1], reverse=True)
        return counts[:n]

    def check_ip(self, ip: str, mean: float, std: float,
                 error_mean: float, error_std: float) -> tuple[bool, str]:
        """
        Returns (should_ban, condition_string).

        An IP is only banned after confirm_strikes consecutive anomaly detections.
        If the IP calms down between checks, the strike counter resets to zero.
        This prevents page-load bursts and brief spikes from causing false bans.
        """
        # No bans during warmup — baseline hasn't learned real traffic yet
        if time.time() - self._start_time < self.warmup_seconds:
            return False, ""

        rate = self.ip_rate(ip)

        # Not enough requests to be statistically meaningful
        if rate < self.min_requests_to_ban:
            # IP has calmed down — reset its strike counter
            self._strikes[ip] = 0
            return False, ""

        err_rate = self.ip_error_rate(ip)

        # Tighten z threshold if this IP has an error surge
        effective_z = self.z_threshold
        if error_mean > 0 and err_rate >= self.error_multiplier * error_mean:
            effective_z = max(2.0, self.z_threshold - 1.0)

        z = (rate - mean) / std if std > 0 else 0.0

        # Determine if this check is anomalous
        anomalous = False
        condition = ""
        if z > effective_z:
            anomalous = True
            condition = f"z_score={z:.2f} > {effective_z}"
        elif mean > 0 and rate > self.rate_multiplier * mean:
            anomalous = True
            condition = f"rate={rate} > {self.rate_multiplier}x mean={mean:.1f}"

        if anomalous:
            self._strikes[ip] += 1
            print(
                f"[detector] STRIKE {self._strikes[ip]}/{self.confirm_strikes} "
                f"for {ip} | {condition}",
                flush=True,
            )
            if self._strikes[ip] >= self.confirm_strikes:
                # Confirmed — reset strikes and signal ban
                self._strikes[ip] = 0
                return True, condition
        else:
            # IP is behaving — reset its strike counter
            self._strikes[ip] = 0

        return False, ""

    def check_global(self, mean: float, std: float) -> tuple[bool, str]:
        rate = self.global_rate()
        z = (rate - mean) / std if std > 0 else 0.0
        if z > self.z_threshold:
            return True, f"global z_score={z:.2f} > {self.z_threshold}"
        if mean > 0 and rate > self.rate_multiplier * mean:
            return True, f"global rate={rate} > {self.rate_multiplier}x mean={mean:.1f}"
        return False, ""
