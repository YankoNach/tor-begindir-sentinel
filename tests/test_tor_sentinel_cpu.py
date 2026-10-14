"""Regression tests for metrics gaps and Tor CPU accounting (no relay access)."""
import csv
import importlib.util
import json
import subprocess
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
            0.0, 0.1, 0.2, 0.3, 0.4,        # first successful scrape
            30.0, 30.1, 34.0, 34.1, 34.2, 34.3,  # timed-out scrape
            60.0, 60.1, 60.2, 60.3, 60.4   # successful recovery
        ])
        rows, events = [], []
        calls = [0]
        def no_sleep(_):
            calls[0] += 1
            if calls[0] >= 3:
                monitor.running = False

        with tempfile.TemporaryDirectory() as td, \
             patch.object(monitor, "OUTPUT_DIR", Path(td)), \
             patch.object(monitor, "fetch_snapshot", side_effect=side_effects), \
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
        # CPU ticks advanced across the invalid scrape: 100 ticks / 26.1s.
        self.assertAlmostEqual(float(rows[2]["tor_cpu_pct"]), 3.83, places=2)
        self.assertEqual([r["rate_scope"] for r in rows],
                         ["baseline", "unavailable", "recovery_avg"])
        self.assertEqual(rows[1]["metrics_status"], "TIMEOUT")
        self.assertEqual(rows[2]["metrics_status"], "OK")
        self.assertGreater(float(rows[1]["scrape_duration_ms"]), 3800)
        self.assertEqual(rows[2]["failed_scrapes_before_sample"], 1)
        self.assertTrue(any("METRICS_UNAVAILABLE" in e for e in events))
        self.assertTrue(any("METRICS_RECOVERED" in e for e in events))
        self.assertFalse(any("STORM_START" in e for e in events))



class ScrapeDeadlineTests(unittest.TestCase):
    def test_child_process_has_strict_deadline(self):
        with patch.object(monitor.subprocess, "run",
                          side_effect=subprocess.TimeoutExpired("sentinel", 5)) as run:
            with self.assertRaisesRegex(TimeoutError, "deadline"):
                monitor.fetch_snapshot()
        self.assertEqual(run.call_args.kwargs["timeout"], monitor.SCRAPE_DEADLINE)
        self.assertIn("--scrape-child", run.call_args.args[0])

    def test_child_json_round_trip(self):
        payload = {"raw": "tor_relay_streams_total 12", "values": {"begin_dir": 12}}
        complete = subprocess.CompletedProcess(
            args=["python"], returncode=0, stdout=json.dumps(payload), stderr=""
        )
        with patch.object(monitor.subprocess, "run", return_value=complete):
            self.assertEqual(monitor.fetch_snapshot(),
                             (payload["raw"], payload["values"]))

    def test_worker_failure_propagates_as_error(self):
        failed = subprocess.CompletedProcess(
            args=["python"], returncode=2, stdout="", stderr="bad MetricsPort"
        )
        with patch.object(monitor.subprocess, "run", return_value=failed):
            with self.assertRaisesRegex(RuntimeError, "bad MetricsPort"):
                monitor.fetch_snapshot()


class CsvCompatibilityTests(unittest.TestCase):
    def test_new_schema_never_appends_under_legacy_header(self):
        with (tempfile.TemporaryDirectory() as td,
              patch.object(monitor, "OUTPUT_DIR", Path(td))):
            dt = datetime(2026, 10, 14, tzinfo=timezone.utc)
            standard = monitor.csv_path_for(dt)
            original_header = monitor.CSV_HEADER[:21]
            with standard.open("w", newline="") as out:
                w = csv.writer(out)
                w.writerow(original_header)
                w.writerow(["2026-10-14T01:00:00Z"] + [""] * 20)
            original = standard.read_bytes()

            sample = {key: "" for key in monitor.CSV_HEADER}
            sample["utc_time"] = "2026-10-14T01:00:30Z"
            sample["metrics_status"] = "OK"
            monitor.append_csv(dt, sample)
            monitor.append_csv(dt, sample)

            self.assertEqual(standard.read_bytes(), original)
            upgraded = Path(td) / "begindir-20261014-v02.csv"
            with upgraded.open(newline="") as inp:
                data = list(csv.DictReader(inp))
            self.assertEqual(len(data), 2)
            self.assertEqual(data[0]["metrics_status"], "OK")
            self.assertEqual(data[1]["utc_time"], "2026-10-14T01:00:30Z")

    def test_fresh_day_uses_regular_filename(self):
        with (tempfile.TemporaryDirectory() as td,
              patch.object(monitor, "OUTPUT_DIR", Path(td))):
            dt = datetime(2026, 10, 15, tzinfo=timezone.utc)
            sample = {key: "" for key in monitor.CSV_HEADER}
            monitor.append_csv(dt, sample)
            with monitor.csv_path_for(dt).open(newline="") as inp:
                self.assertEqual(next(csv.reader(inp)), monitor.CSV_HEADER)

if __name__ == "__main__":
    unittest.main()
