"""Tests for the resource monitor module."""
import sys
import os

# Ensure hooks dir is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "plugins", "leak-guard", "hooks"))

from monitor import (
    Breach,
    ResourceMonitor,
    Thresholds,
    evaluate_thresholds,
)


class TestEvaluateThresholds:
    def test_no_breach(self):
        metrics = {"rss_mb": 100, "threads": 10, "fds": 20, "fd_limit": 1024}
        assert evaluate_thresholds(metrics, Thresholds()) is None

    def test_rss_exceeded(self):
        metrics = {"rss_mb": 600, "threads": 10, "fds": 20, "fd_limit": 1024}
        breach = evaluate_thresholds(metrics, Thresholds(rss_mb=512))
        assert breach is not None
        assert breach.reason == "rss_exceeded"
        assert breach.value == 600
        assert breach.threshold == 512

    def test_threads_exceeded(self):
        metrics = {"rss_mb": 100, "threads": 250, "fds": 20, "fd_limit": 1024}
        breach = evaluate_thresholds(metrics, Thresholds(threads=200))
        assert breach is not None
        assert breach.reason == "threads_exceeded"

    def test_fds_near_limit(self):
        metrics = {"rss_mb": 100, "threads": 10, "fds": 900, "fd_limit": 1024}
        breach = evaluate_thresholds(metrics, Thresholds(fd_pct=0.8))
        assert breach is not None
        assert breach.reason == "fds_near_limit"
        # threshold = int(1024 * 0.8) = 819
        assert breach.threshold == 819

    def test_priority_rss_first(self):
        """RSS check comes before threads check."""
        metrics = {"rss_mb": 600, "threads": 250, "fds": 20, "fd_limit": 1024}
        breach = evaluate_thresholds(metrics, Thresholds(rss_mb=512, threads=200))
        assert breach.reason == "rss_exceeded"


class TestResourceMonitor:
    def _make_monitor(self, metrics=None, clock_start=0.0):
        clock_val = [clock_start]

        def clock():
            return clock_val[0]

        def advance(seconds):
            clock_val[0] += seconds

        default_metrics = {"rss_mb": 100, "threads": 10, "fds": 20, "fd_limit": 1024}
        mon = ResourceMonitor(
            clock=clock,
            metrics_source=lambda: metrics or default_metrics,
        )
        return mon, advance

    def test_no_breach_when_healthy(self):
        mon, _ = self._make_monitor()
        assert mon.should_recycle() is None

    def test_breach_detected(self):
        high = {"rss_mb": 600, "threads": 10, "fds": 20, "fd_limit": 1024}
        mon, _ = self._make_monitor(metrics=high)
        breach = mon.should_recycle()
        assert breach is not None
        assert breach.reason == "rss_exceeded"

    def test_cooldown_prevents_rapid_recycle(self):
        high = {"rss_mb": 600, "threads": 10, "fds": 20, "fd_limit": 1024}
        mon, advance = self._make_monitor(metrics=high, clock_start=0.0)

        # First breach
        breach = mon.should_recycle()
        assert breach is not None
        mon.mark_recycled(breach.reason)

        # Immediately after — cooldown blocks
        advance(10)
        assert mon.should_recycle() is None

        # After cooldown expires (600s default)
        advance(600)
        assert mon.should_recycle() is not None

    def test_disabled_via_env(self, monkeypatch):
        high = {"rss_mb": 600, "threads": 10, "fds": 20, "fd_limit": 1024}
        mon, _ = self._make_monitor(metrics=high)
        monkeypatch.setenv("LEAK_GUARD_MONITOR", "off")
        assert mon.should_recycle() is None

    def test_snapshot_healthy(self):
        mon, _ = self._make_monitor()
        snap = mon.snapshot()
        assert snap["rss_mb"] == 100
        assert snap["threads"] == 10
        assert snap["fds"] == 20
        assert snap["warnings"] == []
        assert snap["last_recycle"] is None

    def test_snapshot_with_warnings(self):
        near_cap = {"rss_mb": 450, "threads": 10, "fds": 20, "fd_limit": 1024}
        mon, _ = self._make_monitor(metrics=near_cap)
        snap = mon.snapshot()
        assert len(snap["warnings"]) == 1
        assert "rss" in snap["warnings"][0]
