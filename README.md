# Tor BEGIN_DIR Storm Sentinel

A passive, high-resolution monitor for unusual `BEGIN_DIR` activity on Tor relays.

The Sentinel watches Tor's MetricsPort and Linux `/proc`, records normal relay behaviour, and switches to faster sampling when `BEGIN_DIR` activity rises sharply. It is intended to help relay operators capture precise start/stop timing and correlate the event with traffic, circuit load, socket count, onion-skin processing, Tor CPU usage, and relay flags.

> **Experimental monitoring tool.** This project is not affiliated with or endorsed by the Tor Project. It does **not** mitigate, block, throttle, reload, restart, or otherwise modify Tor.

## Why this exists

During October 2026, several relay observations showed short-lived but severe waves of abnormal `BEGIN_DIR` activity. In affected periods, relays could show hundreds or thousands of `BEGIN_DIR` requests per second, highly asymmetric traffic, and heavy Tor main-thread CPU load. The phenomenon could then stop abruptly without a Tor restart.

The Sentinel was built to capture those transitions with enough resolution to make later analysis useful.

The project deliberately uses the neutral term **BEGIN_DIR storm**. A high `BEGIN_DIR` rate is an observable condition; this tool does not attempt to determine intent or attribute the cause.

## What it records

By default the Sentinel records:

- UTC timestamp and state: `NORMAL`, `WATCH`, or `STORM`
- Tor PID
- Guard and HSDir flags
- `BEGIN_DIR` rate
- ntor / ntor_v3 processed and dropped rates
- open circuits
- open sockets
- read and written traffic rates
- write/read traffic ratio
- total Tor CPU
- Tor main-thread CPU
- RSS memory
- counter-reset and sample-validity markers

The CSV header is:

```text
utc_time,state,pid,guard,hsdir,interval_sec,begin_dir_per_sec,ntor_processed_per_sec,ntor_dropped_per_sec,ntor_v3_processed_per_sec,ntor_v3_dropped_per_sec,open_circuits,open_sockets,read_MBps,write_MBps,write_read_ratio,tor_cpu_pct,tor_main_cpu_pct,rss_MB,counter_reset,sample_valid
```

## Tor metrics used

The monitor reads these MetricsPort series:

```text
tor_relay_streams_total{type="BEGIN_DIR"}
tor_relay_load_onionskins_total{type="ntor",action="processed"}
tor_relay_load_onionskins_total{type="ntor",action="dropped"}
tor_relay_load_onionskins_total{type="ntor_v3",action="processed"}
tor_relay_load_onionskins_total{type="ntor_v3",action="dropped"}
tor_relay_circuits_total{state="opened"}
tor_relay_load_socket_total{state="opened"}
tor_relay_traffic_bytes{direction="read"}
tor_relay_traffic_bytes{direction="written"}
tor_relay_flag{type="Guard"}
tor_relay_flag{type="HSDir"}
```

The default endpoint is:

```text
http://127.0.0.1:9035/metrics
```

## Detection logic

Default thresholds:

- normal sampling: 30 s
- fast sampling: 10 s
- enter `WATCH`: `BEGIN_DIR >= 10/s`
- enter `STORM`: `BEGIN_DIR >= 50/s` for 2 consecutive samples
- leave storm after sustained quiet below `5/s`
- HTTP timeout: 4 s

The state machine is intentionally simple and conservative:

```text
NORMAL -> WATCH -> STORM
                   |
                   v
               quiet period
                   |
                   v
                 NORMAL
```

Interesting transitions are also written to `events.log`, and raw MetricsPort snapshots are preserved around state changes.

## Output

Default output directory:

```text
~/tor-begindir-sentinel/
```

Files include:

```text
begindir-YYYYMMDD.csv
events.log
... raw metrics snapshots for interesting transitions ...
```

Old CSV files are compressed after 2 days. Default retention is 30 days.

The first sample after a Sentinel start has intentionally blank rate fields because there is no previous counter baseline yet.

## Requirements

- Linux
- Python 3
- Tor MetricsPort enabled and reachable locally
- no third-party Python packages

The monitor uses only the Python standard library.

## Tor configuration

A local MetricsPort is required. For example:

```text
MetricsPort 127.0.0.1:9035
```

Check your Tor configuration before reloading it.

## Installation

Place the script in the relay user's home directory:

```bash
chmod +x ~/tor-begindir-sentinel.py
python3 -m py_compile ~/tor-begindir-sentinel.py
```

Run it manually first and confirm that it produces CSV samples before enabling the systemd service.

A generic systemd example is provided as:

```text
tor-begindir-sentinel.service.example
```

Edit the username and home directory in the example before installing it.

## Important limitations

This is a **detector and recorder**, not a mitigation tool.

It does not:

- use Tor's ControlPort
- change `torrc`
- reload or restart Tor
- reduce relay bandwidth
- block peers or addresses
- infer whether the observed workload is intentional
- prove that `BEGIN_DIR` itself is the root cause of a relay slowdown

A temporal correlation can be strong without proving causation. The collected data is meant to make that distinction easier to investigate.

## Sharing event data

Before publishing CSV extracts or raw snapshots, review them for information you do not want to expose. Small, focused examples are usually more useful than full operational logs.

For a useful event report, include at least:

- approximate start and end time in UTC
- peak `BEGIN_DIR/s`
- Tor CPU and main-thread CPU
- read/write MB/s and write/read ratio
- open circuits and sockets
- Guard / HSDir state
- whether the Tor PID changed

## License

MIT. See [LICENSE](LICENSE).
