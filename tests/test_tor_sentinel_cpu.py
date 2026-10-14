"""Regression tests for metrics gaps and Tor CPU accounting (no relay access)."""
import importlib.util
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "tor-begindir-sentinel.py"
spec = importlib.util.spec_from_file_location("tor_begin_dir_sentinel", SOURCE)
monitor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(monitor)


class CpuTrackerTests(unittest.TestCase):
    def test_independent_cpu_baseline_across_invalid_metrics(self):
        cpu = monitor.CpuTracker(clk_tck=100)
        self.assertEqual(cpu.observe(10, 999, 100, 50, 0.0), (None, None))
        # Imagine the scrape was invalid, but /proc sampling still succeeded.
        total, main = cpu.observe(10, 999, 200, 100, 2.0)
        self.assertAlmostEqual(total, 50.0)
        self.assertAlmostEqual(main, 25.0)
        # Following successful scrape must use the latest CPU sample, not
        # the last successful MetricsPort timestamp.
        total, main = cpu.observe(10, 999, 320, 180, 4.0)
        self.assertAlmostEqual(total, 60.0)
        self.assertAlmostEqual(main, 40.0)

    def test_pid_reuse_starttime_and_missing_proc_reset_cpu_baseline(self):
        cpu = monitor.CpuTracker(clk_tck=100)
        cpu.observe(77, 100, 500, 400, 10.0)
        self.assertEqual(cpu.observe(77, 101, 800, 600, 12.0), (None, None))
        total, _ = cpu.observe(77, 101, 850, 620, 14.0)
        self.assertAlmostEqual(total, 25.0)
        self.assertEqual(cpu.observe(None, None, None, None, 16.0), (None, None))
        self.assertEqual(cpu.observe(77, 101, 900, 650, 18.0), (None, None))

    def test_missing_main_thread_is_not_zero(self):
        cpu = monitor.CpuTracker(clk_tck=100)
        cpu.observe(10, 100, 100, None, 0.0)
        self.assertEqual(cpu.observe(10, 100, 200, None, 2.0), (50.0, None))

    def test_start_ticks_from_proc_stat(self):
        fields = ["S"] + ["0"] * 49
        fields[11], fields[12], fields[19] = "200", "50", "123456"
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "stat"
            path.write_text("77 (tor strange) name) " + " ".join(fields))
            self.assertEqual(monitor.read_cpu_stat(path), (250, 123456))


class IntegrationTests(unittest.TestCase):
    def test_metrics_timeout_does_not_distort_cpu_or_counter_intervals(self):
        counter_keys = (
            "begin_dir", "ntor_processed", "ntor_dropped",
            "ntor_v3_processed", "ntor_v3_dropped",
            "read_bytes", "written_bytes"
        )
        def metrics(v):
            result = {key: (v if key == "begin_dir" else 0) for key in counter_keys}
            result.update(guard=1, hsdir=1, open_circuits=3, open_sockets=4)
            return "test raw", result
        side_effects = [metrics(100), TimeoutError("slow MetricsPort"), metrics(400)]
        times = iter([
            0.0, 0.1, 0.2, 0.3,       # first success
            30.0, 34.0, 34.1,       # invalid scrape
            60.0, 60.1, 60.2, 60.3  # recovery
        ])
        rows, events = [], []
        calls = [0]
        def no_sleep(_):
            calls[0] += 1
            if calls[0] >= 3:
                monitor.running = False

        with tempfile.TemporaryDirectory() as td, \
             patch.object(monitor, "OUTPUT_DIR", Path(td)), \
             patch.object(monitor, "scrape", side_effect=side_effects), \
             patch.object(monitor, "housekeeping"), \
             patch.object(monitor, "event", side_effect=events.append), \
             patch.object(monitor, "append_csv", side_effect=lambda now, row: rows.append(dict(row))), \
             patch.object(monitor, "find_tor_pid", return_value=4321), \
             patch.object(monitor, "read_cpu_stat", side_effect=[(100, 900), (400, 900), (500, 900)]), \
             patch.object(monitor, "read_cpu_ticks", side_effect=[50, 300, 350]), \
             patch.object(monitor, "read_rss_mb", return_value=40), \
             patch.object(monitor, "utc_now", return_value=datetime(2026, 10, 14, tzinfo=timezone.utc)), \
             patch.object(monitor.time, "monotonic", side_effect=lambda: next(times)), \
             patch.object(monitor.time, "sleep", side_effect=no_sleep):
            monitor.running = True
            try:
                monitor.main()
            finally:
                monitor.running = True

        self.assertEqual([r["sample_valid"] for r in rows], [1, 0, 1])
        self.assertEqual(rows[1]["begin_dir_per_sec"], "")
        self.assertEqual(rows[1]["interval_sec"], "")
        # 300 new BEGIN_DIRs / 60 s between *successful* snapshots.
        self.assertEqual(rows[2]["begin_dir_per_sec"], "5.00")
        # CPU rate uses previous /proc measurement (34.0s), not previous
        # *successful* scrape (0.1s): 100 ticks / 26.2s.
        self.assertAlmostEqual(float(rows[2]["tor_cpu_pct"]), 3.82, places=2)
        self.assertTrue(any("METRICS_UNAVAILABLE" in e for e in events))
        self.assertTrue(any("METRICS_RECOVERED" in e for e in events))
        self.assertFalse(any("STORM_START" in e for e in events))


if __name__ == "__main__":
    unittest.main()
