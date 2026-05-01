import numpy as np
from collections import deque
import time

class TrafficTracker:
    def __init__(self):
        # Current active window (last 60 seconds)
        self.ip_windows = {} 
        # History of Global RPM for the last 30 minutes (30 data points)
        self.history = deque(maxlen=30) 
        
        self.mean = 20.0  # Default starting mean
        self.std = 5.0    # Default starting standard deviation
        self.last_baseline_update = time.time()

    def add_request(self, ip):
        now = time.time()
        if ip not in self.ip_windows:
            self.ip_windows[ip] = deque()
        self.ip_windows[ip].append(now)
        
        # Cleanup old data and check if it's time to update the baseline
        self._cleanup(now)
        if now - self.last_baseline_update > 60:
            self.update_baseline()

    def _cleanup(self, now):
        cutoff = now - 60
        for ip in list(self.ip_windows.keys()):
            while self.ip_windows[ip] and self.ip_windows[ip][0] < cutoff:
                self.ip_windows[ip].popleft()
            if not self.ip_windows[ip]:
                del self.ip_windows[ip]

    def update_baseline(self):
        # Total global requests in the last minute
        current_global_rpm = sum(len(window) for window in self.ip_windows.values())
        self.history.append(current_global_rpm)
        
        if len(self.history) >= 2:
            self.mean = float(np.mean(self.history))
            self.std = float(np.std(self.history))
            if self.std < 1.0: self.std = 1.0 # Prevent division by zero
            print(f"[BASELINE] Updated: Mean={self.mean:.2f}, Std={self.std:.2f}", flush=True)
        
        self.last_baseline_update = time.time()

    def get_z_score(self, ip_rpm):
        return (ip_rpm - self.mean) / self.std
