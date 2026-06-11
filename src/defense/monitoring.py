"""
Monitoring & Alerts — Tracks guardrail metrics and fires alerts when thresholds exceed.

Why needed: Detects attacks in real-time by surfacing anomalous patterns (spike in
block rate, repeated rate-limit hits). Without monitoring, you only know about attacks
after the damage is done.
"""
from collections import deque
import time


class MonitoringAlert:
    """
    Tracks metrics across all guardrail plugins and alerts when thresholds are exceeded.

    Alert thresholds:
    - block_rate > 0.5:  More than 50% of recent requests blocked (possible attack)
    - rate_limit_spike:  5+ rate-limit blocks in 60s (possible DoS)
    - judge_fail_rate > 0.3:  LLM Judge failing too often (possible degradation)
    """

    def __init__(self, plugins: list = None):
        self.plugins = plugins or []
        self.alert_history = []
        self.metric_window = deque()
        self.rate_limit_timestamps = deque()

    def check_metrics(self) -> list:
        alerts = []
        now = time.time()

        for p in self.plugins:
            name = getattr(p, "name", str(p))

            if name == "rate_limiter" and hasattr(p, "blocked_count") and p.blocked_count > 0:
                self.rate_limit_timestamps.append(now)
            while self.rate_limit_timestamps and self.rate_limit_timestamps[0] < now - 60:
                self.rate_limit_timestamps.popleft()
            if len(self.rate_limit_timestamps) >= 5:
                alerts.append({
                    "severity": "CRITICAL",
                    "message": f"Rate-limit spike: {len(self.rate_limit_timestamps)} blocks in 60s - possible DoS attack",
                    "plugin": name,
                })
                self.rate_limit_timestamps.clear()

            if name == "input_guardrail" and hasattr(p, "total_count") and p.total_count > 0:
                rate = p.blocked_count / p.total_count
                if rate > 0.5:
                    alerts.append({
                        "severity": "WARNING",
                        "message": f"Input guardrail block rate {rate:.0%} exceeds 50% threshold",
                        "plugin": name,
                    })

            if name == "output_guardrail" and hasattr(p, "total_count") and p.total_count > 0:
                rate = (p.blocked_count + p.redacted_count) / p.total_count
                if rate > 0.3:
                    alerts.append({
                        "severity": "INFO",
                        "message": f"Output guardrail intervention rate {rate:.0%} exceeds 30% threshold",
                        "plugin": name,
                    })

        if alerts:
            self.alert_history.extend(alerts)
            for a in alerts:
                print(f"[{a['severity']}] {a['message']}")

        return alerts

    def get_report(self) -> dict:
        return {
            "total_alerts": len(self.alert_history),
            "alerts": self.alert_history,
            "plugin_count": len(self.plugins),
        }
