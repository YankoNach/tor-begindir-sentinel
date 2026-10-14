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

## Installation and manual validation

Run these commands as the ordinary, unprivileged Linux account that will own the CSVs. Review the code and GitHub commit before installation. The following steps use the repository's public `main` branch **after this release is merged**; while reviewing a proposed change, check out the corresponding proposal branch instead.

```bash
git clone https://github.com/YankoNach/tor-begindir-sentinel.git ~/tor-begindir-sentinel-source
install -m 755 ~/tor-begindir-sentinel-source/linux-os-sentinel.py ~/linux-os-sentinel.py
```

On systems with an existing checkout, update/review that checkout rather than attempting to clone over it. Python 3.10+ and Linux `/proc`/`/sys` are required; there are no third-party Python dependencies. The Tor MetricsPort probe is optional: the monitor works even when Tor is not installed or MetricsPort is not enabled.

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

## Optional systemd service (manual opt-in)

The repository includes `linux-os-sentinel.service.example`. Installing the service requires `sudo`, but the monitor itself runs as your chosen non-root Linux user. **Never leave `YOUR_USER` in an installed unit.** Review and edit all paths and the interface as needed; the example assumes a user home directory under `/home`.

```bash
sudo install -m 644 ~/tor-begindir-sentinel-source/linux-os-sentinel.service.example /etc/systemd/system/linux-os-sentinel.service
sudoedit /etc/systemd/system/linux-os-sentinel.service
# Replace YOUR_USER throughout with your account; inspect ExecStart and WorkingDirectory.
sudo systemd-analyze verify /etc/systemd/system/linux-os-sentinel.service
sudo systemctl daemon-reload
sudo systemctl start linux-os-sentinel.service
systemctl status linux-os-sentinel.service --no-pager -l
sudo journalctl -u linux-os-sentinel.service -n 30 --no-pager
```

Confirm that new UTC-dated CSV rows appear in `~/linux-os-sentinel/` (for the service user) and that `tor_pid` and the network interface are correct. The first row intentionally has blank rate fields. Probe results are **sparse**: blank probe fields mean no probe finished on that sample, not necessarily a failure. When satisfied, enable startup after reboot:

```bash
sudo systemctl enable linux-os-sentinel.service
```

To stop and disable only this monitor: `sudo systemctl disable --now linux-os-sentinel.service`. To diagnose errors: `sudo journalctl -u linux-os-sentinel.service -n 100 --no-pager`. Remove its systemd unit and local data only if you actually intend to uninstall them. These steps do not modify Tor, the existing BEGIN_DIR Sentinel, firewall rules, or relay bandwidth limits.

## Validation status (2026-10-14)

Experimental v0.1 has been exercised on **three live, non-exit Tor relays**: an Oracle AMD x86_64 VM, a Hetzner ARM VM and an Oracle Ampere ARM VM. On each host, short manual smoke tests produced independent `/proc`/network measurements and successful optional local MetricsPort probes; the collector was subsequently installed and observed running as a systemd service. Nine standard-library unit tests exercise parsing, PID/start-time changes, unavailable metrics, and a deliberately delayed local HTTP endpoint. This is useful operational validation, **not** a claim of production hardening or a controlled replay of a BEGIN_DIR storm. Longer-term storm behaviour has not yet been established.

For an offline test of a checkout:

```bash
cd ~/tor-begindir-sentinel-source
python3 -m unittest discover -s tests -p 'test_linux_os_sentinel.py' -v
```

## Important interpretation limits

- `tor_cpu_pct` is a percentage of **one logical CPU**, so whole-process values can exceed 100% when multiple CPU threads execute. If a transient sample exceeds the host's physical/logical capacity, investigate timing, virtualization and sampling artifacts; do not treat that number as a proven sustained load.
- Interface RX/TX covers **all traffic on the selected interface**, not just Tor. Tor's own relay traffic counters and Linux interface counters are not interchangeable.
- `host_cpu_pct` reflects total logical CPU capacity; PSI metrics may not be available on every Linux kernel. Missing values remain blank, not zero.
- The optional background MetricsPort check is a **health/latency probe**, not a stream-counter collector. It does not reconstruct BEGIN_DIR/s while MetricsPort is unresponsive. The independent Linux samples remain available in that situation.
- CPU/process observations are best compared across the two monitors using close UTC timestamps, allowing for different sampling cadences and scopes.
- MetricsPort must never be exposed to external networks for this monitor. The Linux agent's optional probe permits only numeric loopback addresses.

## Publishing and privacy

The public Linux OS Sentinel stores measurements **locally only**. It never publishes or uploads them to GitHub or any other server. The project operator uses separate, private, opt-in tooling to publish rolling summaries from the three test hosts; that infrastructure is **not required or installed** by these instructions. Inspect CSV rows, paths, hostname/interface information and raw logs before sharing data publicly. The monitor does not record packet payloads, user IP addresses or circuit identifiers.
