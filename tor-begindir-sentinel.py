#!/usr/bin/env python3
"""
Tor BEGIN_DIR Storm Sentinel
============================

A passive monitoring tool for Tor relays.

Purpose
-------
Detect unusually high rates of RELAY_COMMAND_BEGIN_DIR streams ("BEGIN_DIR
storms") directly from Tor's MetricsPort, before secondary symptoms such as
traffic asymmetry, high CPU load, circuit-creation overload, or Tor warnings
become obvious.

The sentinel:

  * NEVER changes Tor configuration.
  * NEVER reloads or restarts Tor.
  * NEVER blocks connections.
  * NEVER uses the ControlPort.
  * Only reads Tor's local MetricsPort and Linux /proc data.
  * Writes one CSV file per UTC day.
  * Writes a compact event log for interesting transitions.
  * Takes raw MetricsPort snapshots at storm start/end.
  * Uses a faster sampling interval while suspicious activity is present.

It is intended primarily as an observability / evidence-gathering tool.

Requirements
------------
  * Python 3 (standard library only)
  * Linux /proc
  * Tor MetricsPort enabled on localhost, for example:

        MetricsPort 127.0.0.1:9035

Default thresholds are intentionally conservative and are NOT Tor protocol
limits. They are heuristic detector thresholds and should be adjusted if a
relay has a significantly different normal BEGIN_DIR baseline.
"""

import csv
import gzip
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import urllib.request

from datetime import datetime, timezone, timedelta
from pathlib import Path


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

METRICS_URL = os.environ.get(
    "TOR_METRICS_URL",
    "http://127.0.0.1:9035/metrics",
)

OUTPUT_DIR = Path(
    os.environ.get(
        "TOR_SENTINEL_DIR",
        str(Path.home() / "tor-begindir-sentinel"),
    )
)

# Normal monitoring frequency.
NORMAL_INTERVAL = 30

# Used while activity is suspicious or a storm is active.
FAST_INTERVAL = 10

# Enter WATCH mode after BEGIN_DIR reaches this rate.
WATCH_THRESHOLD = 10.0

# Declare a storm after this rate is seen repeatedly.
STORM_THRESHOLD = 50.0

# Number of consecutive fast samples >= STORM_THRESHOLD needed
# before declaring STORM.
STORM_CONFIRM_SAMPLES = 2

# A storm is considered gone once BEGIN_DIR remains below this value.
CLEAR_THRESHOLD = 5.0

# Number of consecutive fast samples below CLEAR_THRESHOLD before
# declaring the storm ended.
CLEAR_CONFIRM_SAMPLES = 6

# Return from WATCH to NORMAL after this many quiet fast samples.
WATCH_CLEAR_SAMPLES = 3

HTTP_TIMEOUT = 4
# A subprocess isolates a misbehaving local MetricsPort: 4-second socket
# timeout is NOT an overall read deadline, especially with trickle responses.
# Hard wall-clock deadline includes Python child startup and JSON transport.
SCRAPE_DEADLINE = 5.0

# Compress daily CSV files after this many days.
COMPRESS_AFTER_DAYS = 2

# Delete compressed monitoring files older than this.
RETENTION_DAYS = 30


# ---------------------------------------------------------------------------
# Prometheus text parser
# ---------------------------------------------------------------------------

LABEL_RE = re.compile(
    r'([A-Za-z_][A-Za-z0-9_]*)="((?:\\.|[^"])*)"'
)


def parse_metrics(text):
    """
    Parse the small subset of Prometheus exposition format needed here.

    Returns:
        list of (metric_name, labels_dict, numeric_value)
    """
    result = []

    for line in text.splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        parts = line.split()

        if len(parts) < 2:
            continue

        identity = parts[0]

        try:
            value = float(parts[1])
        except ValueError:
            continue

        if "{" in identity:
            name, label_part = identity.split("{", 1)
            label_part = label_part.rsplit("}", 1)[0]

            labels = {}
            for match in LABEL_RE.finditer(label_part):
                key = match.group(1)
                val = match.group(2)
                val = val.replace(r"\\", "\\").replace(r"\"", '"')
                labels[key] = val
        else:
            name = identity
            labels = {}

        result.append((name, labels, value))

    return result


def metric_value(metrics, suffix, required_labels=None):
    """
    Return a metric value matching a metric name and a subset of labels.

    Tor normally prefixes relay metrics with "tor_".  Supporting both forms
    makes the parser slightly more tolerant of exposition-format changes.
    """
    if required_labels is None:
        required_labels = {}

    possible_names = {
        suffix,
        "tor_" + suffix,
    }

    for name, labels, value in metrics:
        if name not in possible_names:
            continue

        if all(labels.get(k) == v for k, v in required_labels.items()):
            return value

    return None


# ---------------------------------------------------------------------------
# Tor / Linux process information
# ---------------------------------------------------------------------------

def find_tor_pid():
    """
    Find the main Tor process.

    pgrep -xo selects the oldest exact process named "tor", which is normally
    the relay daemon rather than an unrelated shell command.
    """
    try:
        output = subprocess.check_output(
            ["pgrep", "-xo", "tor"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()

        return int(output) if output else None

    except (subprocess.CalledProcessError, ValueError, FileNotFoundError):
        return None


def read_cpu_stat(path):
    """Read (utime+stime, kernel starttime) from a /proc/.../stat entry."""
    try:
        content = Path(path).read_text()
        fields = content.rsplit(")", 1)[1].strip().split()
        # After removing pid and comm, utime=11, stime=12, starttime=19.
        return int(fields[11]) + int(fields[12]), int(fields[19])
    except (OSError, ValueError, IndexError):
        return None


def read_cpu_ticks(path):
    """Read utime+stime from /proc/<pid>/[task/<pid>/]stat."""
    stat = read_cpu_stat(path)
    return stat[0] if stat is not None else None


def read_rss_mb(pid):
    """Read resident memory size from /proc/<pid>/status."""
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                kb = float(line.split()[1])
                return kb / 1024.0
    except (OSError, ValueError, IndexError):
        pass

    return None


class CpuTracker:
    """Track CPU deltas on every loop, independently of MetricsPort validity.

    Whole-process CPU is measured as a percentage of one logical CPU.
    Kernel starttime guards against PID recycling and reset across restarts.
    """

    def __init__(self, clk_tck):
        self.clk_tck = clk_tck
        self.previous = None

    def observe(self, pid, start_ticks, proc_ticks, main_ticks, sampled_at):
        previous = self.previous
        self.previous = None

        if pid is None or start_ticks is None or proc_ticks is None:
            return None, None

        self.previous = (pid, start_ticks, proc_ticks, main_ticks, sampled_at)
        if previous is None or (pid, start_ticks) != previous[:2]:
            return None, None

        elapsed = sampled_at - previous[4]
        if elapsed <= 0:
            return None, None

        def percent(current, old):
            if current is None or old is None or current < old:
                return None
            return (current - old) / self.clk_tck / elapsed * 100.0

        return percent(proc_ticks, previous[2]), percent(main_ticks, previous[3])


# ---------------------------------------------------------------------------
# Files and event logging
# ---------------------------------------------------------------------------

CSV_HEADER = [
    "utc_time",
    "state",
    "pid",
    "guard",
    "hsdir",
    "interval_sec",
    "begin_dir_per_sec",
    "ntor_processed_per_sec",
    "ntor_dropped_per_sec",
    "ntor_v3_processed_per_sec",
    "ntor_v3_dropped_per_sec",
    "open_circuits",
    "open_sockets",
    "read_MBps",
    "write_MBps",
    "write_read_ratio",
    "tor_cpu_pct",
    "tor_main_cpu_pct",
    "rss_MB",
    "counter_reset",
    "sample_valid",
    # Appended columns preserve the historical CSV prefix and existing readers.
    "metrics_status",
    "metrics_error_type",
    "metrics_age_sec",
    "scrape_duration_ms",
    "rate_scope",
    "failed_scrapes_before_sample",
]


def utc_now():
    return datetime.now(timezone.utc)


def iso_time(dt=None):
    if dt is None:
        dt = utc_now()

    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def event(message):
    """Append one human-readable line to events.log."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    line = f"{iso_time()} {message}"

    with (OUTPUT_DIR / "events.log").open("a") as f:
        f.write(line + "\n")

    print(line, flush=True)


def csv_path_for(dt):
    return OUTPUT_DIR / f"begindir-{dt.strftime('%Y%m%d')}.csv"


def append_csv(dt, row):
    path = csv_path_for(dt)
    if path.exists() and path.stat().st_size:
        with path.open(newline="") as source:
            existing_header = next(csv.reader(source), [])
        if existing_header != CSV_HEADER:
            # Do not append a newer CSV layout under an older header.
            # Both filenames retain the YYYYMMDD token for housekeeping and
            # are picked up by the existing private publisher's CSV glob.
            path = path.with_name(path.stem + "-v02.csv")
            if path.exists() and path.stat().st_size:
                with path.open(newline="") as source:
                    alternate_header = next(csv.reader(source), [])
                if alternate_header != CSV_HEADER:
                    raise RuntimeError(
                        f"Refusing to append incompatible CSV layout: {path}"
                    )

    new_file = not path.exists() or not path.stat().st_size
    with path.open("a", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_HEADER)
        if new_file:
            writer.writeheader()
        writer.writerow(row)


def save_raw_snapshot(kind, raw_metrics):
    """
    Save the complete Tor MetricsPort response around important transitions.
    This can later be compared with Tor logs or shared with developers.
    """
    snapshot_dir = OUTPUT_DIR / "snapshots"
    snapshot_dir.mkdir(parents=True, exist_ok=True)

    stamp = utc_now().strftime("%Y%m%d-%H%M%S")
    path = snapshot_dir / f"{stamp}-{kind}.metrics.txt"

    path.write_text(raw_metrics)


def housekeeping():
    """
    Compress old CSVs and remove monitoring data older than RETENTION_DAYS.
    """
    now = utc_now()
    compress_before = now - timedelta(days=COMPRESS_AFTER_DAYS)
    delete_before = now - timedelta(days=RETENTION_DAYS)

    for path in OUTPUT_DIR.glob("begindir-*.csv"):
        try:
            stamp = path.stem.split("-")[1]
            file_date = datetime.strptime(stamp, "%Y%m%d").replace(
                tzinfo=timezone.utc
            )
        except (ValueError, IndexError):
            continue

        if file_date < compress_before:
            gz_path = Path(str(path) + ".gz")

            if not gz_path.exists():
                with path.open("rb") as src, gzip.open(gz_path, "wb") as dst:
                    shutil.copyfileobj(src, dst)

                path.unlink()

    for path in OUTPUT_DIR.glob("begindir-*.csv.gz"):
        try:
            stamp = path.name.split("-")[1].split(".")[0]
            file_date = datetime.strptime(stamp, "%Y%m%d").replace(
                tzinfo=timezone.utc
            )
        except (ValueError, IndexError):
            continue

        if file_date < delete_before:
            path.unlink()

    snapshot_dir = OUTPUT_DIR / "snapshots"

    if snapshot_dir.exists():
        for path in snapshot_dir.glob("*.metrics.txt"):
            try:
                mtime = datetime.fromtimestamp(
                    path.stat().st_mtime,
                    tz=timezone.utc,
                )
                if mtime < delete_before:
                    path.unlink()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Metrics collection
# ---------------------------------------------------------------------------

def scrape():
    """
    Read Tor MetricsPort and extract counters/gauges relevant to a
    BEGIN_DIR storm.
    """
    request = urllib.request.Request(
        METRICS_URL,
        headers={"User-Agent": "tor-begindir-sentinel/1.0"},
    )

    with urllib.request.urlopen(
        request,
        timeout=HTTP_TIMEOUT,
    ) as response:
        raw = response.read().decode("utf-8", errors="replace")

    metrics = parse_metrics(raw)

    values = {
        "begin_dir": metric_value(
            metrics,
            "relay_streams_total",
            {"type": "BEGIN_DIR"},
        ),

        "ntor_processed": metric_value(
            metrics,
            "relay_load_onionskins_total",
            {"type": "ntor", "action": "processed"},
        ),

        "ntor_dropped": metric_value(
            metrics,
            "relay_load_onionskins_total",
            {"type": "ntor", "action": "dropped"},
        ),

        "ntor_v3_processed": metric_value(
            metrics,
            "relay_load_onionskins_total",
            {"type": "ntor_v3", "action": "processed"},
        ),

        "ntor_v3_dropped": metric_value(
            metrics,
            "relay_load_onionskins_total",
            {"type": "ntor_v3", "action": "dropped"},
        ),

        "open_circuits": metric_value(
            metrics,
            "relay_circuits_total",
            {"state": "opened"},
        ),

        "open_sockets": metric_value(
            metrics,
            "relay_load_socket_total",
            {"state": "opened"},
        ),

        "read_bytes": metric_value(
            metrics,
            "relay_traffic_bytes",
            {"direction": "read"},
        ),

        "written_bytes": metric_value(
            metrics,
            "relay_traffic_bytes",
            {"direction": "written"},
        ),

        "guard": metric_value(
            metrics,
            "relay_flag",
            {"type": "Guard"},
        ),

        "hsdir": metric_value(
            metrics,
            "relay_flag",
            {"type": "HSDir"},
        ),
    }

    required = [
        "begin_dir",
        "ntor_processed",
        "ntor_dropped",
        "ntor_v3_processed",
        "ntor_v3_dropped",
        "open_circuits",
        "open_sockets",
        "read_bytes",
        "written_bytes",
    ]

    missing = [name for name in required if values[name] is None]

    if missing:
        raise RuntimeError(
            "Required MetricsPort values missing: "
            + ", ".join(missing)
        )

    return raw, values


def fetch_snapshot():
    """Fetch in a killable child so MetricsPort never blocks this main loop.

    A daemon thread cannot safely be killed if the HTTP response trickles forever.
    A short-lived local child process keeps the original Tor observer passive and
    guarantees a bounded scrape wall time. It inherits only the local environment.
    """
    try:
        completed = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--scrape-child"],
            capture_output=True, text=True, timeout=SCRAPE_DEADLINE,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(
            f"MetricsPort scrape exceeded {SCRAPE_DEADLINE:g}s deadline"
        ) from exc
    if completed.returncode != 0:
        error = (completed.stderr or "").strip()[-350:]
        raise RuntimeError(
            f"MetricsPort child failed exit={completed.returncode}: {error}"
        )
    try:
        payload = json.loads(completed.stdout)
        return payload["raw"], payload["values"]
    except (ValueError, KeyError, TypeError) as exc:
        raise RuntimeError("Invalid MetricsPort child response") from exc


def counter_rate(current, previous, elapsed):
    """
    Calculate delta/second for a monotonically increasing Tor counter.

    Returns (rate, reset_detected).
    """
    if previous is None or elapsed <= 0:
        return None, False

    if current < previous:
        return None, True

    return (current - previous) / elapsed, False


def fmt(value, digits=2):
    if value is None:
        return ""

    return f"{value:.{digits}f}"


# ---------------------------------------------------------------------------
# Main state machine
# ---------------------------------------------------------------------------

running = True


def stop_handler(signum, frame):
    global running
    running = False


signal.signal(signal.SIGTERM, stop_handler)
signal.signal(signal.SIGINT, stop_handler)


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    state = "NORMAL"

    storm_confirm = 0
    clear_confirm = 0
    watch_clear = 0

    storm_started_at = None
    storm_peak_rate = 0.0
    storm_peak_time = None

    previous = None
    previous_monotonic = None
    invalid_since_good = 0
    expected_interval = NORMAL_INTERVAL

    previous_process = None
    cpu_tracker = CpuTracker(os.sysconf(os.sysconf_names["SC_CLK_TCK"]))

    last_error = None
    metrics_unavailable_since = None
    last_housekeeping_day = None

    event(
        "SENTINEL_START "
        f"normal_interval={NORMAL_INTERVAL}s "
        f"fast_interval={FAST_INTERVAL}s "
        f"watch_threshold={WATCH_THRESHOLD}/s "
        f"storm_threshold={STORM_THRESHOLD}/s "
        f"clear_threshold={CLEAR_THRESHOLD}/s"
    )

    while running:
        loop_started = time.monotonic()
        now = utc_now()

        if last_housekeeping_day != now.date():
            housekeeping()
            last_housekeeping_day = now.date()

        sample_valid = 1
        counter_reset = 0
        metrics_scraped_at = None
        scrape_duration_ms = None
        metrics_error_type = ""
        metrics_status = "OK"
        rate_scope = "unavailable"
        scrape_started = time.monotonic()

        try:
            raw, current = fetch_snapshot()
            metrics_scraped_at = time.monotonic()
            scrape_duration_ms = (metrics_scraped_at - scrape_started) * 1000
            if metrics_unavailable_since is not None:
                gap = metrics_scraped_at - metrics_unavailable_since
                event(
                    f"METRICS_RECOVERED gap={gap:.1f}s "
                    f"failed_samples={invalid_since_good} "
                    "counters_averaged_over_successful_scrape_interval"
                )
                metrics_unavailable_since = None
            last_error = None

        except Exception as exc:
            sample_valid = 0
            invalid_since_good += 1
            current = None
            raw = ""
            scrape_duration_ms = (time.monotonic() - scrape_started) * 1000
            metrics_error_type = type(exc).__name__
            metrics_status = (
                "TIMEOUT" if isinstance(exc, TimeoutError) else "ERROR"
            )
            if metrics_unavailable_since is None:
                metrics_unavailable_since = loop_started
                event("METRICS_UNAVAILABLE")

            error_text = f"{type(exc).__name__}: {exc}"

            # Avoid repeated identical errors during a prolonged outage.
            if error_text != last_error:
                event(f"METRICS_ERROR {error_text}")
                last_error = error_text

            # A failed scrape breaks a sequence of consecutive storm samples.
            storm_confirm = 0
            clear_confirm = 0
            watch_clear = 0

        # CSV time is assigned after the scrape, not before a slow HTTP read.
        now = utc_now()
        metrics_age_sec = (
            max(0.0, time.monotonic() - previous_monotonic)
            if not sample_valid and previous_monotonic is not None
            else (0.0 if sample_valid else None)
        )
        if (
            not sample_valid
            and (metrics_age_sec is None
                 or metrics_age_sec > 2.5 * expected_interval)
        ):
            metrics_status = "STALE"

        pid = find_tor_pid()

        proc_ticks = None
        proc_start_ticks = None
        main_ticks = None
        rss_mb = None

        if pid is not None:
            proc_stat = read_cpu_stat(f"/proc/{pid}/stat")
            if proc_stat is not None:
                proc_ticks, proc_start_ticks = proc_stat
            main_ticks = read_cpu_ticks(f"/proc/{pid}/task/{pid}/stat")
            rss_mb = read_rss_mb(pid)

        cpu_sampled_at = time.monotonic()
        tor_cpu_pct, tor_main_cpu_pct = cpu_tracker.observe(
            pid, proc_start_ticks, proc_ticks, main_ticks, cpu_sampled_at
        )

        current_process = (
            (pid, proc_start_ticks)
            if pid is not None and proc_start_ticks is not None
            else None
        )
        if previous_process is not None and current_process != previous_process:
            if current_process is None:
                event(f"TOR_PROCESS_MISSING old={previous_process}")
            elif previous_process[0] != current_process[0]:
                # Keep the original event name for downstream consumers.
                event(
                    f"TOR_PID_CHANGE old={previous_process[0]} "
                    f"new={current_process[0]}"
                )
            else:
                event(
                    f"TOR_PROCESS_RESTART pid={pid} "
                    f"old_start={previous_process[1]} "
                    f"new_start={proc_start_ticks}"
                )
            previous = None
            previous_monotonic = None

        elapsed = None
        if sample_valid and previous_monotonic is not None:
            elapsed = metrics_scraped_at - previous_monotonic

        if sample_valid:
            if previous is None or elapsed is None or elapsed <= 0:
                rate_scope = "baseline"
            elif invalid_since_good:
                rate_scope = "recovery_avg"
            elif elapsed > 2.5 * expected_interval:
                rate_scope = "extended_avg"
            else:
                rate_scope = "regular"

        rates = {
            "begin_dir": None,
            "ntor_processed": None,
            "ntor_dropped": None,
            "ntor_v3_processed": None,
            "ntor_v3_dropped": None,
            "read_bytes": None,
            "written_bytes": None,
        }

        if (
            sample_valid
            and previous is not None
            and elapsed is not None
        ):
            for key in rates:
                rates[key], reset = counter_rate(
                    current[key],
                    previous[key],
                    elapsed,
                )

                if reset:
                    counter_reset = 1

        if counter_reset:
            rate_scope = "reset"
            storm_confirm = 0
            clear_confirm = 0
            watch_clear = 0

        read_mbps = (
            rates["read_bytes"] / 1_000_000
            if rates["read_bytes"] is not None
            else None
        )

        write_mbps = (
            rates["written_bytes"] / 1_000_000
            if rates["written_bytes"] is not None
            else None
        )

        write_read_ratio = None

        if (
            read_mbps is not None
            and write_mbps is not None
            and read_mbps > 0
        ):
            write_read_ratio = write_mbps / read_mbps

        begin_rate = rates["begin_dir"]

        # ---------------------------------------------------------------
        # Detector state machine
        # ---------------------------------------------------------------

        # Recovery/extended averages do not reveal the real instantaneous
        # peak or event boundary. Do NOT drive detector transitions with them.
        if begin_rate is not None and rate_scope == "regular":

            if state == "NORMAL":

                if begin_rate >= WATCH_THRESHOLD:
                    state = "WATCH"
                    watch_clear = 0

                    storm_confirm = (
                        1 if begin_rate >= STORM_THRESHOLD else 0
                    )

                    event(
                        "WATCH_START "
                        f"begin_dir={begin_rate:.2f}/s "
                        f"write_read_ratio={fmt(write_read_ratio)} "
                        f"pid={pid}"
                    )

                    save_raw_snapshot("watch-start", raw)

            elif state == "WATCH":

                if begin_rate >= STORM_THRESHOLD:
                    storm_confirm += 1
                    watch_clear = 0

                    if storm_confirm >= STORM_CONFIRM_SAMPLES:
                        state = "STORM"

                        storm_started_at = now
                        storm_peak_rate = begin_rate
                        storm_peak_time = now
                        clear_confirm = 0

                        event(
                            "STORM_START "
                            f"begin_dir={begin_rate:.2f}/s "
                            f"read={fmt(read_mbps, 3)}MB/s "
                            f"write={fmt(write_mbps, 3)}MB/s "
                            f"ratio={fmt(write_read_ratio)} "
                            f"circuits={int(current['open_circuits'])} "
                            f"sockets={int(current['open_sockets'])} "
                            f"cpu={fmt(tor_cpu_pct)}% "
                            f"main_cpu={fmt(tor_main_cpu_pct)}%"
                        )

                        save_raw_snapshot("storm-start", raw)

                elif begin_rate < WATCH_THRESHOLD:
                    storm_confirm = 0
                    watch_clear += 1

                    if watch_clear >= WATCH_CLEAR_SAMPLES:
                        event(
                            "WATCH_END "
                            f"begin_dir={begin_rate:.2f}/s"
                        )

                        state = "NORMAL"
                        watch_clear = 0

                else:
                    storm_confirm = 0
                    watch_clear = 0

            elif state == "STORM":

                if begin_rate > storm_peak_rate:
                    storm_peak_rate = begin_rate
                    storm_peak_time = now

                if begin_rate < CLEAR_THRESHOLD:
                    clear_confirm += 1
                else:
                    clear_confirm = 0

                if clear_confirm >= CLEAR_CONFIRM_SAMPLES:

                    duration = None

                    if storm_started_at is not None:
                        duration = (
                            now - storm_started_at
                        ).total_seconds()

                    event(
                        "STORM_END "
                        f"begin_dir={begin_rate:.2f}/s "
                        f"duration={fmt(duration, 0)}s "
                        f"peak={storm_peak_rate:.2f}/s "
                        f"peak_time={iso_time(storm_peak_time)} "
                        f"read={fmt(read_mbps, 3)}MB/s "
                        f"write={fmt(write_mbps, 3)}MB/s"
                    )

                    save_raw_snapshot("storm-end", raw)

                    state = "NORMAL"
                    storm_confirm = 0
                    clear_confirm = 0
                    watch_clear = 0
                    storm_started_at = None
                    storm_peak_rate = 0.0
                    storm_peak_time = None

        # ---------------------------------------------------------------
        # CSV record
        # ---------------------------------------------------------------

        row = {
            "utc_time": iso_time(now),
            "state": state,
            "pid": pid if pid is not None else "",
            "guard": (
                int(current["guard"])
                if sample_valid and current["guard"] is not None
                else ""
            ),
            "hsdir": (
                int(current["hsdir"])
                if sample_valid and current["hsdir"] is not None
                else ""
            ),
            "interval_sec": fmt(elapsed, 1),
            "begin_dir_per_sec": fmt(rates["begin_dir"]),
            "ntor_processed_per_sec": fmt(
                rates["ntor_processed"]
            ),
            "ntor_dropped_per_sec": fmt(
                rates["ntor_dropped"]
            ),
            "ntor_v3_processed_per_sec": fmt(
                rates["ntor_v3_processed"]
            ),
            "ntor_v3_dropped_per_sec": fmt(
                rates["ntor_v3_dropped"]
            ),
            "open_circuits": (
                int(current["open_circuits"])
                if sample_valid
                else ""
            ),
            "open_sockets": (
                int(current["open_sockets"])
                if sample_valid
                else ""
            ),
            "read_MBps": fmt(read_mbps, 3),
            "write_MBps": fmt(write_mbps, 3),
            "write_read_ratio": fmt(write_read_ratio),
            "tor_cpu_pct": fmt(tor_cpu_pct),
            "tor_main_cpu_pct": fmt(tor_main_cpu_pct),
            "rss_MB": fmt(rss_mb, 1),
            "counter_reset": counter_reset,
            "sample_valid": sample_valid,
            "metrics_status": metrics_status,
            "metrics_error_type": metrics_error_type,
            "metrics_age_sec": fmt(metrics_age_sec, 1),
            "scrape_duration_ms": fmt(scrape_duration_ms, 1),
            "rate_scope": rate_scope,
            "failed_scrapes_before_sample": (
                invalid_since_good if sample_valid else ""
            ),
        }

        append_csv(now, row)

        # Metrics counter baseline advances only on valid scrapes.
        # CPU baseline is independent and was updated by CpuTracker above.
        if sample_valid:
            previous = current
            previous_monotonic = metrics_scraped_at
            invalid_since_good = 0

        previous_process = current_process

        interval = (
            FAST_INTERVAL
            if state in ("WATCH", "STORM")
            else NORMAL_INTERVAL
        )

        expected_interval = interval
        spent = time.monotonic() - loop_started
        sleep_for = max(0.0, interval - spent)

        time.sleep(sleep_for)

    event("SENTINEL_STOP")


if __name__ == "__main__":
    if sys.argv[1:] == ["--scrape-child"]:
        # Internal worker entrypoint, not a standalone monitoring service.
        try:
            raw, values = scrape()
            sys.stdout.write(json.dumps({"raw": raw, "values": values}))
        except Exception as exc:
            sys.stderr.write(f"{type(exc).__name__}: {exc}\n")
            sys.exit(2)
    elif len(sys.argv) > 1:
        sys.stderr.write("Unknown arguments to Sentinel\n")
        sys.exit(2)
    else:
        try:
            main()
        except Exception as exc:
            event(f"FATAL_ERROR {type(exc).__name__}: {exc}")
            raise