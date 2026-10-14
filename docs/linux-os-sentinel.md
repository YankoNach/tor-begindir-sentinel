# Linux OS Sentinel (experimental v0.1)

**Linux OS Sentinel complements, and never replaces, the existing Tor BEGIN_DIR Sentinel.** It records system-level evidence even when Tor's local MetricsPort is temporarily unresponsive. Linux standard library only, Python 3.10+, designed for Ubuntu 24.04 x86_64 and aarch64. No Tor configuration, control port, privileged access or inbound firewall changes required.

## Design and evidence boundaries

- **Independent collection loop:** the main process reads Linux `/proc` every 2 seconds (configurable). The optional MetricsPort health probe runs in a single daemon thread, at most once per minute. A delayed, timed-out or failed probe does not block OS measurements. `lag_ms` records scheduling delay and `collect_ms` measures sampling overhead.
- **Host interface rates** from `/proc/net/dev`: decimal MB/s (1 MB = 1,000,000 bytes), and **TX/RX ratio** (`tx_rx_ratio`). These are entire-interface measurements, **not** Tor's own MetricsPort traffic counters and **not** a provider billing meter. Default interface is selected using `/proc/net/route` (lowest-metric IPv4 default route), with fallback to a non-loopback interface. Use `--interface eth0` or a different explicit name when necessary.
- **Tor process CPU and main-thread CPU** from `/proc/<pid>/stat` and `/proc/<pid>/task/<pid>/stat`, expressed as `% of one CPU core`. Whole-process CPU may exceed 100%. CPU deltas use their **own monotonic timestamps** and are updated on every OS sample whether Tor MetricsPort answers or not. The (PID, kernel starttime) pair prevents false rates across process restarts and PID recycling. Tor RSS and VmSwap are from `/proc/<pid>/status`.
- **System CPU utilization** from `/proc/stat`; memory availability and total/swap from `/proc/meminfo`; CPU, memory and I/O pressure 10-second averages from `/proc/pressure/{cpu,memory,io}`. The interval-derived `*_psi_some_pct` uses successive kernel `total` microsecond counters. Blank fields mean a metric was inaccessible/unavailable, not zero.
- **MetricsPort latency:** optional GET to `http://127.0.0.1:9035/metrics`; connection is restricted to numeric loopback, proxies and redirects disabled, reads only a small prefix of response, records status (`ok`, `timeout`, `error`) and latency on completion. Because Tor must process the HTTP request, this does cause a small *additional* probe workload; disable for initial validation or overload-sensitive tests with `--metrics-probe-interval 0`. It never opens a listening port.
- **No sensitive traffic collection:** no remote endpoints, packets, user IPs, circuit identifiers, relay control commands or payloads are recorded.

CSV schema: 

```text
utc_time,elapsed_sec,lag_ms,collect_ms,interface,rx_MBps,tx_MBps,tx_rx_ratio,iface_rx_bytes,iface_tx_bytes,host_cpu_pct,cpu_psi_some_avg10,cpu_psi_some_pct,mem_available_MB,mem_total_MB,swap_used_MB,swap_total_MB,mem_psi_some_avg10,mem_psi_full_avg10,mem_psi_some_pct,io_psi_some_avg10,io_psi_full_avg10,tor_pid,tor_start_ticks,tor_cpu_pct,tor_main_cpu_pct,tor_rss_MB,tor_swap_MB,tor_state,metrics_probe_status,metrics_probe_ms,metrics_probe_error
```

Note: If Tor is not installed in a test environment, Tor-specific fields remain blank; OS fields still record. The first sample after startup has blank rate fields by design. CSV rows are emitted every 2 seconds into `~/linux-os-sentinel/linux-os-YYYYMMDD.csv` (UTC day), old files are gzip-compressed after two days and pruned after 30 days. The script does **not** upload its files anywhere. An uploader integration must be reviewed separately.

## Read-only manual smoke test (before installing a service)

These commands run on the relay as the unprivileged user who will own the CSVs. Obtain the script from the **reviewed GitHub commit** before proceeding. Download/install steps have deliberately been left to the operator, who can verify code and commit contents.

```bash
python3 -m py_compile ~/linux-os-sentinel.py
python3 ~/linux-os-sentinel.py --samples 10 --interval 2 --metrics-probe-interval 0
head -n 3 ~/linux-os-sentinel/linux-os-$(date -u +%Y%m%d).csv
```

Ten samples take about 20 seconds. Check that `utc_time`, `interface`, `elapsed_sec`, memory, `rx_MBps`/`tx_MBps` and Tor PID are plausible. `tor_main_cpu_pct` should be non-blank on later samples if kernel permissions permit. If no route interface is found, identify the correct interface and pass `--interface YOUR_IFACE`.

After OS collection is validated, manually test the **optional** MetricsPort latency probe at a cautious interval, e.g.:

```bash
python3 ~/linux-os-sentinel.py --samples 40 --interval 2 --metrics-probe-interval 60
```

Stop with Ctrl-C if Tor shows any unexpected performance effect. Check `metrics_probe_status` in the appended CSV. A failed probe is diagnostic; it must not interrupt the host measurements.

## Proposed systemd unit (NOT installed automatically)

`linux-os-sentinel.service.example` is a generic template. Replace `YOUR_USER` with `ubuntu` on Cloud1/Cloud3 or `khankrum` on Cloud2, verify the script's absolute path and permissions, and install only after testing and explicit operator approval.

Suggested validation before enabling a service (operator actions, *not* already executed):

```bash
sudo systemd-analyze verify /etc/systemd/system/linux-os-sentinel.service
sudo systemctl daemon-reload
sudo systemctl start linux-os-sentinel.service
systemctl status linux-os-sentinel.service --no-pager
journalctl -u linux-os-sentinel.service -n 30 --no-pager
```

For unattended startup **only after approval**: `sudo systemctl enable linux-os-sentinel.service`. To stop only the OS monitor: `sudo systemctl disable --now linux-os-sentinel.service`. Tor and the existing BEGIN_DIR Sentinel remain untouched.

## Before production deployment

1. Run the standard-library tests: `python3 -m unittest discover -s tests -v` from the repo root.
2. Test smoke sampling on an unprivileged user, including no Tor process, Tor PID changes/restarts, missing PSI, unavailable MetricsPort and interrupted network read.
3. Ensure the main loop is not blocked by HTTP timeouts. Review overhead and UTC timestamps on Cloud1 first; then deploy Cloud2, Cloud3 separately.
4. Compare overlapping Tor process CPU and local network rates with the original Sentinel. These measure different traffic scopes and use different clocks.
5. Design a separate, opt-in addition to the existing **private** `tor-begindir-fleet-data` publisher; do not automatically upload high-frequency OS CSVs until cadence, retention, repository size and privacy have been reviewed.

This initial implementation has **not** been exercised on the live Tor relays. GitHub publication of a development branch is not an installation and does not prove systemd state on any relay.
