import time
from collections import deque, defaultdict


class AnomalyDetector:
    """
    Tracks per-IP and global request rates using deque-based sliding windows.
    Detects anomalies via z-score > threshold OR rate > 5x baseline mean.
    Tightens thresholds for IPs with high error rates.
    """

    def __init__(self, cfg):
        self.ip_window_secs = cfg["detection"]["ip_window_seconds"]
        self.global_window_secs = cfg["detection"]["global_window_seconds"]
        self.z_threshold = cfg["detection"]["z_score_threshold"]
        self.rate_multiplier = cfg["detection"]["rate_multiplier_threshold"]
        self.error_multiplier = cfg["detection"]["error_rate_multiplier"]

        # deque of timestamps per IP for the sliding window
        self._ip_windows: dict[str, deque] = defaultdict(deque)
        # deque of timestamps for global window
        self._global_window: deque = deque()
        # per-IP error timestamps
        self._ip_error_windows: dict[str, deque] = defaultdict(deque)

    def record(self, ip: str, is_error: bool):
        now = time.time()
        cutoff_ip = now - self.ip_window_secs
        cutoff_global = now - self.global_window_secs

        # Per-IP window
        dq = self._ip_windows[ip]
        dq.append(now)
        while dq and dq[0] < cutoff_ip:
            dq.popleft()

        # Per-IP error window
        if is_error:
            edq = self._ip_error_windows[ip]
            edq.append(now)
            while edq and edq[0] < cutoff_ip:
                edq.popleft()

        # Global window
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
        Returns (is_anomalous, condition_string).
        Tightens z_threshold if the IP has an error surge.
        """
        rate = self.ip_rate(ip)
        err_rate = self.ip_error_rate(ip)

        # Error surge: tighten threshold
        effective_z = self.z_threshold
        if error_mean > 0 and err_rate >= self.error_multiplier * error_mean:
            effective_z = max(1.5, self.z_threshold - 1.0)

        z = (rate - mean) / std if std > 0 else 0.0

        if z > effective_z:
            return True, f"z_score={z:.2f} > {effective_z}"
        if mean > 0 and rate > self.rate_multiplier * mean:
            return True, f"rate={rate} > {self.rate_multiplier}x mean={mean:.1f}"
        return False, ""

    def check_global(self, mean: float, std: float) -> tuple[bool, str]:
        rate = self.global_rate()
        z = (rate - mean) / std if std > 0 else 0.0
        if z > self.z_threshold:
            return True, f"global z_score={z:.2f} > {self.z_threshold}"
        if mean > 0 and rate > self.rate_multiplier * mean:
            return True, f"global rate={rate} > {self.rate_multiplier}x mean={mean:.1f}"
        return False, ""
