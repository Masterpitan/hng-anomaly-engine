import time
import numpy as np
from collections import deque, defaultdict


class TrafficBaseline:
    """
    Maintains a rolling 30-minute baseline of per-second request counts.
    Recalculates mean/stddev every 60 seconds.
    Tracks per-hour slots and prefers the current hour's data when sufficient.
    """

    def __init__(self, cfg):
        self.history_minutes = cfg["baseline"]["history_minutes"]
        self.recalc_interval = cfg["baseline"]["recalculation_interval_seconds"]
        self.min_std = cfg["baseline"]["min_std"]
        self.min_mean = cfg["baseline"]["min_mean"]
        self.min_points = cfg["baseline"]["min_data_points"]
        self.hourly_min = cfg["baseline"]["hourly_min_data_points"]

        # Rolling window: one entry per second bucket, maxlen = history_minutes * 60
        self._window = deque(maxlen=self.history_minutes * 60)
        # Per-hour slots: hour_int -> list of per-second counts
        self._hourly = defaultdict(list)

        self.mean = float(cfg["baseline"]["min_mean"])
        self.std = float(cfg["baseline"]["min_std"])
        self.error_mean = 1.0
        self.error_std = 1.0
        self._warmed_up = False

        self._last_recalc = time.time()
        self._current_second = int(time.time())
        self._second_count = 0
        self._second_error_count = 0

        # Per-second error counts rolling window
        self._error_window = deque(maxlen=self.history_minutes * 60)

    def record(self, is_error: bool):
        """Called for every request. Buckets into per-second slots."""
        now_sec = int(time.time())
        if now_sec != self._current_second:
            # Flush the completed second bucket
            self._window.append(self._second_count)
            self._error_window.append(self._second_error_count)
            hour = time.localtime(self._current_second).tm_hour
            self._hourly[hour].append(self._second_count)
            # Keep hourly list bounded to history_minutes entries
            if len(self._hourly[hour]) > self.history_minutes:
                self._hourly[hour] = self._hourly[hour][-self.history_minutes:]
            self._current_second = now_sec
            self._second_count = 0
            self._second_error_count = 0

        self._second_count += 1
        if is_error:
            self._second_error_count += 1

        if time.time() - self._last_recalc >= self.recalc_interval:
            self._recalculate()

    def _recalculate(self):
        current_hour = time.localtime().tm_hour
        hourly_data = self._hourly.get(current_hour, [])

        if len(hourly_data) >= self.hourly_min:
            data = hourly_data
        elif len(self._window) >= self.min_points:
            data = list(self._window)
        else:
            self._last_recalc = time.time()
            return

        self.mean = max(float(np.mean(data)), self.min_mean)
        self.std = max(float(np.std(data)), self.min_std)
        self._warmed_up = True

        if len(self._error_window) >= self.min_points:
            edata = list(self._error_window)
            self.error_mean = max(float(np.mean(edata)), 0.1)
            self.error_std = max(float(np.std(edata)), 0.1)

        self._last_recalc = time.time()
        return {
            "mean": self.mean,
            "std": self.std,
            "error_mean": self.error_mean,
            "data_points": len(data),
            "source": "hourly" if len(hourly_data) >= self.hourly_min else "rolling",
        }

    def get_stats(self):
        return self.mean, self.std

    def get_error_stats(self):
        return self.error_mean, self.error_std

    def force_recalculate(self):
        """Called externally every 60s; returns stats dict or None."""
        return self._recalculate()
