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


def read_cpu_ticks(path):
    """
    Read utime + stime from /proc/.../stat.

    /proc/<pid>/stat is used for total Tor process CPU.
    /proc/<pid>/task/<pid>/stat is used for Tor's main thread.
    """
    try:
        text = Path(path).read_text()

        # The process name in parentheses may theoretically contain spaces.
        # Everything after the final ')' has stable field positions.
        after_name = text.rsplit(")", 1)[1].strip().split()

        # Original proc fields 14 and 15 become indexes 11 and 12 here
        # because fields 1 and 2 were removed above.
        utime = int(after_name[11])
        stime = int(after_name[12])

        return utime + stime

    except (OSError, ValueError, IndexError):
        return None


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
    new_file = not path.exists()

    with path.open("a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADER)

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

    previous_pid = None
    previous_proc_ticks = None
    previous_main_ticks = None

    clk_tck = os.sysconf(os.sysconf_names["SC_CLK_TCK"])

    last_error = None
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

        try:
            raw, current = scrape()
            last_error = None

        except Exception as exc:
            sample_valid = 0
            current = None
            raw = ""

            error_text = f"{type(exc).__name__}: {exc}"

            # Do not write the same network/metrics error every few seconds.
            if error_text != last_error:
                event(f"METRICS_ERROR {error_text}")
                last_error = error_text

        pid = find_tor_pid()

        proc_ticks = None
        main_ticks = None
        rss_mb = None

        if pid is not None:
            proc_ticks = read_cpu_ticks(f"/proc/{pid}/stat")
            main_ticks = read_cpu_ticks(
                f"/proc/{pid}/task/{pid}/stat"
            )
            rss_mb = read_rss_mb(pid)

        if (
            previous_pid is not None
            and pid is not None
            and pid != previous_pid
        ):
            event(f"TOR_PID_CHANGE old={previous_pid} new={pid}")

            previous = None
            previous_monotonic = None
            previous_proc_ticks = None
            previous_main_ticks = None

        elapsed = None

        if previous_monotonic is not None:
            elapsed = loop_started - previous_monotonic

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

        tor_cpu_pct = None
        tor_main_cpu_pct = None

        if (
            elapsed
            and proc_ticks is not None
            and previous_proc_ticks is not None
            and proc_ticks >= previous_proc_ticks
        ):
            tor_cpu_pct = (
                (proc_ticks - previous_proc_ticks)
                / clk_tck
                / elapsed
                * 100.0
            )

        if (
            elapsed
            and main_ticks is not None
            and previous_main_ticks is not None
            and main_ticks >= previous_main_ticks
        ):
            tor_main_cpu_pct = (
                (main_ticks - previous_main_ticks)
                / clk_tck
                / elapsed
                * 100.0
            )

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

        if begin_rate is not None and not counter_reset:

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
        }

        append_csv(now, row)

        # Update baselines only from a valid scrape.
        if sample_valid:
            previous = current
            previous_monotonic = loop_started

        previous_pid = pid

        if proc_ticks is not None:
            previous_proc_ticks = proc_ticks

        if main_ticks is not None:
            previous_main_ticks = main_ticks

        interval = (
            FAST_INTERVAL
            if state in ("WATCH", "STORM")
            else NORMAL_INTERVAL
        )

        spent = time.monotonic() - loop_started
        sleep_for = max(0.0, interval - spent)

        time.sleep(sleep_for)

    event("SENTINEL_STOP")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        event(
            f"FATAL_ERROR {type(exc).__name__}: {exc}"
        )
        raise