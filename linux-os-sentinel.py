#!/usr/bin/env python3
"""Linux OS Sentinel: passive, independent host observability for Tor relays.

Only Linux /proc and /sys are sampled. An optional, bounded background probe
checks localhost Tor MetricsPort without ever blocking host sampling.
This program does not require, control, restart, or configure Tor.
Standard-library only, no privileges or inbound network ports required.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import ipaddress
import os
import queue
import shutil
import socket
import signal
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

VERSION = "0.1.0"
UTC = timezone.utc
HEADER = [
    "utc_time", "elapsed_sec", "lag_ms", "collect_ms", "interface",
    "rx_MBps", "tx_MBps", "tx_rx_ratio", "iface_rx_bytes", "iface_tx_bytes",
    "host_cpu_pct", "cpu_psi_some_avg10", "cpu_psi_some_pct",
    "mem_available_MB", "mem_total_MB", "swap_used_MB", "swap_total_MB",
    "mem_psi_some_avg10", "mem_psi_full_avg10", "mem_psi_some_pct",
    "io_psi_some_avg10", "io_psi_full_avg10",
    "tor_pid", "tor_start_ticks", "tor_cpu_pct", "tor_main_cpu_pct",
    "tor_rss_MB", "tor_swap_MB", "tor_state",
    "metrics_probe_status", "metrics_probe_ms", "metrics_probe_error",
]
STOP = False


def stop_handler(_signum, _frame):
    global STOP
    STOP = True


def utc_now() -> datetime:
    return datetime.now(UTC)


def parse_proc_stat(line: str) -> dict[str, int | str]:
    """Process fields from /proc/PID/stat; comm may contain parentheses/spaces."""
    close = line.rfind(")")
    if close < 0 or "(" not in line[:close]:
        raise ValueError("invalid process stat")
    fields = line[close + 1:].split()  # starts at Linux stat field 3
    return {
        "state": fields[0],
        "ticks": int(fields[11]) + int(fields[12]),  # utime+stime, fields 14/15
        "start_ticks": int(fields[19]),              # starttime, field 22
    }


def read_proc_stat(path: Path) -> dict[str, int | str] | None:
    try:
        return parse_proc_stat(path.read_text())
    except (OSError, ValueError, IndexError):
        return None


def find_tor_process(proc_dir: Path = Path("/proc")) -> tuple[int, dict] | tuple[None, None]:
    candidates = []
    try:
        with os.scandir(proc_dir) as entries:
            for entry in entries:
                if not entry.name.isdecimal():
                    continue
                try:
                    if (proc_dir / entry.name / "comm").read_text().strip() != "tor":
                        continue
                    stat = read_proc_stat(proc_dir / entry.name / "stat")
                    if stat:
                        candidates.append((int(entry.name), stat))
                except (OSError, ValueError):
                    continue
    except OSError:
        return None, None
    if not candidates:
        return None, None
    return min(candidates, key=lambda item: item[1]["start_ticks"])


def read_status_memory(path: Path) -> tuple[float | None, float | None]:
    rss = swap = None
    try:
        for line in path.read_text().splitlines():
            if line.startswith("VmRSS:"):
                rss = int(line.split()[1]) / 1024
            elif line.startswith("VmSwap:"):
                swap = int(line.split()[1]) / 1024
    except (OSError, ValueError, IndexError):
        pass
    return rss, swap


def read_meminfo(path: Path = Path("/proc/meminfo")) -> dict:
    mem = {}
    try:
        for line in path.read_text().splitlines():
            name, value = line.split(":", 1)
            mem[name] = int(value.strip().split()[0]) / 1024
    except (OSError, ValueError, IndexError):
        return {}
    total_swap = mem.get("SwapTotal")
    free_swap = mem.get("SwapFree")
    return {
        "mem_available_MB": mem.get("MemAvailable"),
        "mem_total_MB": mem.get("MemTotal"),
        "swap_used_MB": max(0, total_swap - free_swap) if total_swap is not None and free_swap is not None else None,
        "swap_total_MB": total_swap,
    }


def read_host_cpu(path: Path = Path("/proc/stat")) -> tuple[int, int] | None:
    try:
        with path.open() as handle:
            line = handle.readline().split()
        if line[0] != "cpu":
            return None
        nums = [int(v) for v in line[1:]]
        # user nice system idle iowait irq softirq steal guest guest_nice
        idle = nums[3] + (nums[4] if len(nums) > 4 else 0)
        total = sum(nums[:8])  # do not double-count guest time
        return total, idle
    except (OSError, ValueError, IndexError):
        return None


def parse_pressure(raw: str) -> dict:
    result = {}
    for line in raw.splitlines():
        parts = line.split()
        if not parts or parts[0] not in ("some", "full"):
            continue
        values = dict(field.split("=", 1) for field in parts[1:] if "=" in field)
        try:
            result[parts[0]] = {
                "avg10": float(values["avg10"]),
                "total": int(values["total"]),  # microseconds
            }
        except (ValueError, KeyError):
            continue
    return result


def read_pressure(kind: str, root: Path = Path("/proc/pressure")) -> dict:
    try:
        return parse_pressure((root / kind).read_text())
    except OSError:
        return {}


def parse_netdev(raw: str) -> dict[str, tuple[int, int]]:
    result = {}
    for line in raw.splitlines()[2:]:
        if ":" not in line:
            continue
        iface, values = line.rsplit(":", 1)
        fields = values.split()
        if len(fields) < 16:
            continue
        try:
            result[iface.strip()] = (int(fields[0]), int(fields[8]))
        except ValueError:
            continue
    return result


def read_netdev(path: Path = Path("/proc/net/dev")) -> dict:
    try:
        return parse_netdev(path.read_text())
    except OSError:
        return {}


def default_interface(route_path: Path = Path("/proc/net/route")) -> str | None:
    """Choose the lowest-metric usable IPv4 default route, without commands."""
    try:
        choices = []
        for line in route_path.read_text().splitlines()[1:]:
            cols = line.split()
            if len(cols) < 8 or cols[1] != "00000000":
                continue
            if not (int(cols[3], 16) & 0x1):  # RTF_UP
                continue
            choices.append((int(cols[6]), cols[0]))
        return min(choices)[1] if choices else None
    except (OSError, ValueError, IndexError):
        return None


def choose_interface(explicit: str, values: dict) -> str | None:
    if explicit != "auto":
        return explicit if explicit in values else None
    preferred = default_interface()
    if preferred in values:
        return preferred
    physical = [name for name in values if name != "lo" and not name.startswith(("veth", "docker", "br-"))]
    return sorted(physical)[0] if physical else None


def rate(delta: int, elapsed: float, divisor: float = 1.0) -> float | None:
    if elapsed <= 0 or delta < 0:
        return None
    return delta / elapsed / divisor


def percentage(delta: int, elapsed: float, ticks_per_second: int) -> float | None:
    return rate(delta, elapsed, ticks_per_second) * 100 if elapsed > 0 and delta >= 0 else None


def fmt(value):
    if value is None:
        return ""
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value)


def validated_metrics_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "http" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("MetricsPort probe requires a plaintext localhost HTTP URL")
    try:
        if not ipaddress.ip_address(parsed.hostname).is_loopback:
            raise ValueError("MetricsPort probe must target loopback only")
    except ValueError as exc:
        raise ValueError("MetricsPort probe must target numeric loopback (e.g. 127.0.0.1)") from exc
    return url


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Reject redirects: a MetricsPort probe must never leave loopback."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class MetricsProbe:
    """Single background worker; timeouts/errors never block host collection."""

    def __init__(self, url: str, timeout: float):
        self.url = validated_metrics_url(url)
        self.timeout = timeout
        self._thread: threading.Thread | None = None
        self._done = queue.Queue(maxsize=1)

    def maybe_start(self):
        if self._thread is not None and self._thread.is_alive():
            return False
        # Drain any old completion before scheduling again.
        self._thread = threading.Thread(target=self._probe, daemon=True)
        self._thread.start()
        return True

    def _probe(self):
        begin = time.monotonic()
        status, err = "ok", ""
        try:
            req = urllib.request.Request(self.url, headers={"User-Agent": "linux-os-sentinel/" + VERSION})
            # urllib may follow redirects; no redirects expected for Tor MetricsPort.
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
            with opener.open(req, timeout=self.timeout) as response:
                response.read(4096)
                if response.status != 200:
                    raise OSError(f"HTTP {response.status}")
        except Exception as exc:
            reason = getattr(exc, "reason", None)
            status = "timeout" if isinstance(exc, (TimeoutError, socket.timeout)) or isinstance(reason, (TimeoutError, socket.timeout)) else "error"
            err = type(exc).__name__  # bounded category; no external response content
        elapsed_ms = (time.monotonic() - begin) * 1000
        try:
            self._done.put_nowait((status, elapsed_ms, err))
        except queue.Full:
            pass

    def poll(self):
        try:
            return self._done.get_nowait()
        except queue.Empty:
            return None


class Sampler:
    def __init__(self, interface: str, clk_tck: int | None = None):
        self.interface = interface
        self.clk_tck = clk_tck or os.sysconf("SC_CLK_TCK")
        self.previous = None

    def collect(self, monotonic: float | None = None) -> dict:
        tick = time.monotonic() if monotonic is None else monotonic
        row = {field: None for field in HEADER}
        row["utc_time"] = utc_now().strftime("%Y-%m-%dT%H:%M:%SZ")
        row["elapsed_sec"] = None
        interface_counters = read_netdev()
        iface = choose_interface(self.interface, interface_counters)
        row["interface"] = iface or ""
        iface_values = interface_counters.get(iface) if iface else None
        if iface_values:
            row["iface_rx_bytes"], row["iface_tx_bytes"] = iface_values
        cpu = read_host_cpu()
        pressure = {kind: read_pressure(kind) for kind in ("cpu", "memory", "io")}
        mem = read_meminfo()
        row.update(mem)
        row["cpu_psi_some_avg10"] = pressure["cpu"].get("some", {}).get("avg10")
        row["mem_psi_some_avg10"] = pressure["memory"].get("some", {}).get("avg10")
        row["mem_psi_full_avg10"] = pressure["memory"].get("full", {}).get("avg10")
        row["io_psi_some_avg10"] = pressure["io"].get("some", {}).get("avg10")
        row["io_psi_full_avg10"] = pressure["io"].get("full", {}).get("avg10")

        pid, proc = find_tor_process()
        row["tor_pid"] = pid
        main = None
        if pid is not None:
            main = read_proc_stat(Path(f"/proc/{pid}/task/{pid}/stat"))
            row["tor_start_ticks"] = proc["start_ticks"]
            row["tor_state"] = proc["state"]
            rss, swap = read_status_memory(Path(f"/proc/{pid}/status"))
            row["tor_rss_MB"] = rss
            row["tor_swap_MB"] = swap
        previous = self.previous
        if previous:
            elapsed = tick - previous["tick"]
            row["elapsed_sec"] = elapsed
            if iface == previous["iface"] and iface_values and previous["net"]:
                rx = rate(iface_values[0] - previous["net"][0], elapsed, 1_000_000)
                tx = rate(iface_values[1] - previous["net"][1], elapsed, 1_000_000)
                row["rx_MBps"], row["tx_MBps"] = rx, tx
                row["tx_rx_ratio"] = tx / rx if rx is not None and tx is not None and rx > 0 else None
            if cpu and previous["cpu"]:
                delta_total = cpu[0] - previous["cpu"][0]
                delta_idle = cpu[1] - previous["cpu"][1]
                row["host_cpu_pct"] = 100 * (1 - delta_idle / delta_total) if delta_total > 0 and 0 <= delta_idle <= delta_total else None
            if pid is not None and (pid, proc["start_ticks"]) == previous["process"]:
                row["tor_cpu_pct"] = percentage(proc["ticks"] - previous["proc_ticks"], elapsed, self.clk_tck)
                if main and previous["main_ticks"] is not None:
                    row["tor_main_cpu_pct"] = percentage(main["ticks"] - previous["main_ticks"], elapsed, self.clk_tck)
            for kind, field in (("cpu", "cpu_psi_some_pct"), ("memory", "mem_psi_some_pct")):
                now_val = pressure[kind].get("some", {}).get("total")
                prev_val = previous["pressure"][kind].get("some", {}).get("total")
                if now_val is not None and prev_val is not None:
                    row[field] = rate(now_val - prev_val, elapsed, 1_000_000) * 100 if now_val >= prev_val and elapsed > 0 else None
        self.previous = {
            "tick": tick, "iface": iface, "net": iface_values, "cpu": cpu,
            "process": (pid, proc["start_ticks"]) if proc else None,
            "proc_ticks": proc["ticks"] if proc else None,
            "main_ticks": main["ticks"] if main else None,
            "pressure": pressure,
        }
        return row


def cleanup_old_csv(directory: Path, now: datetime, compress_days: int = 2, retention_days: int = 30):
    """Compress closed UTC days and delete old compressed days only."""
    for file in directory.glob("linux-os-*.csv"):
        try:
            date = datetime.strptime(file.stem.removeprefix("linux-os-"), "%Y%m%d").replace(tzinfo=UTC)
        except ValueError:
            continue
        if date >= now - timedelta(days=compress_days):
            continue
        target = Path(str(file) + ".gz")
        if target.exists():
            continue
        with file.open("rb") as src, gzip.open(target, "wb", compresslevel=6) as dst:
            shutil.copyfileobj(src, dst)
        file.unlink()
    for file in directory.glob("linux-os-*.csv.gz"):
        try:
            date = datetime.strptime(file.name.split(".")[0].removeprefix("linux-os-"), "%Y%m%d").replace(tzinfo=UTC)
        except ValueError:
            continue
        if date < now - timedelta(days=retention_days):
            file.unlink()


def append_csv(directory: Path, row: dict):
    now = utc_now()
    path = directory / f"linux-os-{row['utc_time'][:10].replace('-', '')}.csv"
    exists = path.exists()
    with path.open("a", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=HEADER)
        if not exists:
            writer.writeheader()
        writer.writerow({key: fmt(row.get(key)) for key in HEADER})


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path.home() / "linux-os-sentinel")
    parser.add_argument("--interface", default="auto", help="Interface name or auto (default route)")
    parser.add_argument("--interval", type=float, default=2.0, help="Host sample cadence, seconds (default: 2)")
    parser.add_argument("--metrics-url", default="http://127.0.0.1:9035/metrics")
    parser.add_argument("--metrics-probe-interval", type=float, default=60.0, help="0 disables probes")
    parser.add_argument("--metrics-timeout", type=float, default=2.0)
    parser.add_argument("--samples", type=int, default=0, help="0 means run until stopped")
    args = parser.parse_args(argv)
    if args.interval < 0.1 or args.metrics_probe_interval < 0 or args.metrics_timeout <= 0 or args.samples < 0:
        parser.error("interval >=0.1, probe interval >=0, timeout >0, samples >=0 required")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(args.output_dir, 0o700)
    signal.signal(signal.SIGTERM, stop_handler)
    signal.signal(signal.SIGINT, stop_handler)
    sampler = Sampler(args.interface)
    probe = MetricsProbe(args.metrics_url, args.metrics_timeout) if args.metrics_probe_interval else None
    last_probe_started = float("-inf")
    last_cleanup_day = None
    sample = 0
    scheduled = time.monotonic()
    while not STOP and (args.samples == 0 or sample < args.samples):
        start = time.monotonic()
        if probe and start - last_probe_started >= args.metrics_probe_interval:
            if probe.maybe_start():
                last_probe_started = start
        row = sampler.collect(start)
        completion = probe.poll() if probe else None
        if completion:
            row["metrics_probe_status"], row["metrics_probe_ms"], row["metrics_probe_error"] = completion
        row["lag_ms"] = max(0, (start - scheduled) * 1000)
        row["collect_ms"] = (time.monotonic() - start) * 1000
        append_csv(args.output_dir, row)
        now = utc_now()
        if last_cleanup_day != now.date():
            cleanup_old_csv(args.output_dir, now)
            last_cleanup_day = now.date()
        sample += 1
        scheduled += args.interval
        # If a schedule was missed, don't busy-loop to catch up.
        if scheduled < time.monotonic():
            scheduled = time.monotonic()
        remaining = scheduled - time.monotonic()
        if remaining > 0:
            time.sleep(remaining)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
