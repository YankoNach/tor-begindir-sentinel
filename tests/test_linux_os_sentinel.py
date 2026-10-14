"""Standard library unit tests for Linux OS Sentinel, no relay access needed."""
import importlib.util
import tempfile
import time
import threading
import http.server
import unittest
from pathlib import Path
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "linux-os-sentinel.py"
spec = importlib.util.spec_from_file_location("linux_os_sentinel", SOURCE)
los = importlib.util.module_from_spec(spec)
spec.loader.exec_module(los)


class ParserTests(unittest.TestCase):
    def test_proc_stat_fields_and_comm_with_parentheses(self):
        # Fields 3..52, utime=f14=11th zero-based, stime=f15, start=f22.
        fields = ["S"] + ["0"] * 49
        fields[11], fields[12], fields[19] = "15", "5", "98765"
        parsed = los.parse_proc_stat("12345 (tor weird) name) " + " ".join(fields))
        self.assertEqual(parsed, {"state": "S", "ticks": 20, "start_ticks": 98765})

    def test_parse_pressure(self):
        parsed = los.parse_pressure("some avg10=0.25 avg60=1.11 avg300=0.04 total=123456\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=111\n")
        self.assertEqual(parsed["some"]["total"], 123456)
        self.assertEqual(parsed["full"]["avg10"], 0.0)

    def test_network_parser(self):
        raw = "Inter-| Receive | Transmit\n face | bytes...\n eth0: 123 0 0 0 0 0 0 0 456 0 0 0 0 0 0 0\n lo: 2 0 0 0 0 0 0 0 2 0 0 0 0 0 0 0\n"
        self.assertEqual(los.parse_netdev(raw)["eth0"], (123, 456))
        self.assertEqual(los.choose_interface("eth0", {"eth0": (1, 2)}), "eth0")

    def test_default_route(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d)/"route"
            f.write_text("Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n"
                         "eth1 00000000 00000000 0001 0 0 200 00000000 0 0 0\n"
                         "eth0 00000000 00000000 0003 0 0 100 00000000 0 0 0\n")
            self.assertEqual(los.default_interface(f), "eth0")

    def test_rate_and_percentage(self):
        self.assertEqual(los.rate(2_000_000, 2, 1_000_000), 1.0)
        self.assertEqual(los.percentage(200, 2, 100), 100.0)
        self.assertIsNone(los.rate(-1, 2))

    def test_reject_nonlocal_metrics_urls(self):
        self.assertEqual(los.validated_metrics_url("http://127.0.0.1:9035/metrics"), "http://127.0.0.1:9035/metrics")
        self.assertEqual(los.validated_metrics_url("http://[::1]:9035/metrics"), "http://[::1]:9035/metrics")
        for invalid in ("https://127.0.0.1/metrics", "http://1.1.1.1:9035/metrics", "http://localhost:9035/metrics"):
            with self.assertRaises(ValueError):
                los.validated_metrics_url(invalid)

    def test_pid_change_clears_cpu_baseline(self):
        counter = iter([({"ticks": 10, "start_ticks": 100, "state": "S"}, 4),
                        ({"ticks": 1000, "start_ticks": 200, "state": "S"}, 4)])
        def fake_find():
            proc, pid = next(counter)
            return pid, proc
        with patch.object(los, "find_tor_process", side_effect=fake_find), \
                patch.object(los, "read_netdev", return_value={"eth0": (100, 200)}), \
                patch.object(los, "default_interface", return_value="eth0"), \
                patch.object(los, "read_host_cpu", return_value=(500, 100)), \
                patch.object(los, "read_meminfo", return_value={}), \
                patch.object(los, "read_pressure", return_value={}), \
                patch.object(los, "read_proc_stat", return_value=None), \
                patch.object(los, "read_status_memory", return_value=(12, 0)):
            sampler = los.Sampler("auto", clk_tck=100)
            sampler.collect(100.)
            nextrow = sampler.collect(102.)
            self.assertIsNone(nextrow["tor_cpu_pct"])
            self.assertEqual(nextrow["tor_start_ticks"], 200)

    def test_bad_proc_is_absent_not_fatal(self):
        self.assertIsNone(los.read_proc_stat(Path("/no/such/proc")))
        self.assertEqual(los.read_meminfo(Path("/no/such/proc")), {})


class ProbeIsolationTests(unittest.TestCase):
    def test_slow_local_http_does_not_block_sampling(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                time.sleep(0.8)
                try:
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"ok")
                except (BrokenPipeError, ConnectionResetError):
                    pass
            def log_message(self, *args):
                pass
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            probe = los.MetricsProbe(f"http://127.0.0.1:{server.server_address[1]}/metrics", timeout=0.2)
            t0 = time.monotonic()
            self.assertTrue(probe.maybe_start())
            for _ in range(5):
                # Main collection loop does not wait on HTTP.
                self.assertIsNone(probe.poll())
                time.sleep(0.02)
            self.assertLess(time.monotonic() - t0, 0.18)
            time.sleep(0.16)
            result = probe.poll()
            self.assertIsNotNone(result)
            self.assertEqual(result[0], "timeout")
        finally:
            server.shutdown()


if __name__ == "__main__":
    unittest.main()
