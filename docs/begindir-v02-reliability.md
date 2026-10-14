# BEGIN_DIR Sentinel v0.2 reliability proposal (not deployed)

This document describes **proposed changes in PR #2**, not the current deployed
v0.1 monitor. The three active Tor relays, their systemd services, the independent
Linux OS Sentinel and the private fleet publisher remain unchanged.

## What v0.2 addresses

1. **CPU accounting**: process and main-thread CPU percentages use Linux
   `/proc` ticks with their own monotonic sample times, updated every loop,
   including during failed MetricsPort scrapes. PID plus kernel process start
   time identifies an instance of Tor, avoiding accidentally mixing values
   after a restart or PID reuse. CPU is percent of **one logical CPU**.
2. **Bounded MetricsPort scrapes**: each normal/fast sample uses a short-lived
   Python subprocess, which performs the same local HTTP request with the
   original 4-second per-socket timeout. The parent enforces a **5-second
   total wall-clock deadline** and terminates the child on timeout. This avoids
   a continuously trickling HTTP response blocking the main monitoring loop.
   A subprocess has startup and IPC overhead; verify overhead on each host
   before any rollout.
3. **Missing-data semantics**: a failed scrape has `sample_valid=0`, blank
   Tor counter rates, and a `metrics_status` of `TIMEOUT`, `ERROR` or
   `STALE`; no missing value is silently treated as zero. The separate
   `state` column retains the last confirmed `NORMAL`/`WATCH`/`STORM`
   detector state, but is not a current assessment when metrics are stale.
4. **No false peak from recovery averages**: after one or more missed
   scrapes, the total counter change divided by the elapsed time is a valid
   **average over the entire missing interval**, not a measured instantaneous
   peak. A `recovery_avg` or `extended_avg` rate is retained for research,
   but is **not allowed to trigger state transitions**. A good consecutive
   pair of samples is required to resume `WATCH`/`STORM` decisions.
   Confirmation streaks are reset when the scrape fails or a counter resets.
5. **Counter and data validation**: non-finite metrics (NaN/Infinity) are
   rejected. Metrics counter reset detection is explicit. The measured
   counter interval uses successive completed successful HTTP scrapes, rather
   than the loop-start timestamp; actual Tor snapshot times lie within the
   corresponding request windows.
6. **Compatible daily CSVs**: the v0.1 header and column order are kept as
   an exact prefix. If a daily `begindir-YYYYMMDD.csv` still has an old
   header at rollout time, it is **never rewritten**; new rows go into
   `begindir-YYYYMMDD-v02.csv` for that day. Both match the existing
   `begindir-*.csv` glob. Future UTC days use the normal filename.
   The schema version must be considered by any external CSV readers.

## Added CSV columns (at the end)

| Column | Meaning |
| --- | --- |
| `metrics_status` | `OK`, `TIMEOUT`, `ERROR` or `STALE`. `STALE` indicates no recent successful scrape. |
| `metrics_error_type` | Python exception type on failures (empty on success). |
| `metrics_age_sec` | Approximate seconds since the previous successful scrape when a scrape fails; 0 for success, blank if none has ever succeeded. |
| `scrape_duration_ms` | Measured subprocess scrape duration, including child startup and response handling. |
| `rate_scope` | Interpret the **Tor counter rates**: `unavailable`, `baseline`, `regular`, `recovery_avg`, `extended_avg`, `reset`. |
| `failed_scrapes_before_sample` | Number of failed scrapes before a successful recovery; blank on a failure. |

A completed MetricsPort HTTP request can still return a stale view of Tor
statistics, depending on Tor's internal update semantics. The v0.2 collector
cannot infer the true second-by-second Tor activity during an outage. The
independent Linux OS Sentinel provides separate 2-second host-level evidence.

## Reviewer checklist before any merge or server rollout

- Run Python compilation and all tests in GitHub Actions. Regression tests
  include PID recycling, CPU after invalid scrapes, real local HTTP trickle,
  child timeouts, and preservation of old daily CSV headers.
- Check the relative sampling overhead of spawning a Python process every
  30 seconds (or every 10 seconds during `WATCH`/`STORM`) on the constrained
  2-vCPU Oracle AMD host.
- Ensure the private `tor-begindir-fleet-data` rolling summary does **not**
  interpret a `recovery_avg` or `extended_avg` as a verified short-lived
  peak, and does not report an old valid `NORMAL` state as current while
  new samples are invalid. This is **not yet implemented** in the publisher.
- Plan a staged, explicitly operator-approved deployment to one relay,
  check both collectors' timing, and only then consider the others.
- **PR #2 is a draft.** No changes to live Tor, `torrc`, systemd, or private
  publishing should happen from opening or reviewing this PR.

Other relay flags and additional Tor overload counters are a separate
next-stage proposal; do not mix them into this reliability review.
