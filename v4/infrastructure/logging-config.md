# v4 logging and sensor configuration

This file records the logging-stack changes v4 makes, with before/after and why,
as each is built. It is not complete — the Zeek JSON switch and the Splunk
per-channel sourcetypes are later steps and are marked pending below.

## Sensor persistence — the NDR capture interface and Zeek autostart

**Status: done and verified across a reboot, 30 Oct 2026.**

This is step zero of v4 for the reason the [v4 README addendum](../README.md) gives:
v4 runs the kill chain twice, before and after hardening, and the v3 re-run found
Zeek on `security-vm` had been dead for six days because its capture interface came
up `DOWN` after a reboot. A dead NDR sensor during either run makes the coverage
matrix worthless, so the sensor has to survive a reboot before any hardening begins.

Two independent faults, both reboot-triggered, both silent:

### 1. The capture interface came up administratively DOWN

`security-vm` has two NICs: `ens33` (management, DHCP, where SSH lives) and `ens37`
(a monitor NIC with no IP that Zeek opens for capture). Cloud-init's netplan
configured only `ens33`, so `ens37` was unmanaged and came up `DOWN` on every boot.
Zeek then crashed on start with:

```
fatal error: problem with interface ens37
(pcap_error: That device is not up (pcap_activate))
```

`zeekctl` had been logging that crash the whole time; nothing surfaced it because
Suricata, bound to a different interface, kept the host reporting healthy in Splunk.

Fixed with a dedicated netplan file (cloud-init only manages `ens33`, and its own
file warns that edits to it do not persist):

`/etc/netplan/60-zeek-capture.yaml` (mode `600`):

```yaml
# Zeek capture interface. ens37 is a monitor NIC with no IP; Zeek opens it for
# packet capture. Without this it comes up admin-DOWN after every reboot and
# Zeek crashes on start with "pcap_activate: device is not up". Bringing it up
# is all that is needed here; Zeek's libpcap sets promiscuous mode itself when
# it opens the interface. cloud-init only configures ens33.
network:
  version: 2
  ethernets:
    ens37:
      dhcp4: no
      dhcp6: no
      optional: true
      accept-ra: no
```

**No `promiscuous:` key.** netplan 0.106.1 (this host) rejects it —
`netplan generate` failed with `unknown key 'promiscuous'`, which is why the config
was validated with `netplan generate` before `netplan apply` rather than applied
blind. It is not needed: the `pcap_activate` error is about the interface's
*admin-up* state, not promiscuous mode. Zeek's libpcap sets promiscuous itself via
`AF_PACKET` when it opens the device, confirmed by `ip -d link show ens37` reading
`promiscuity 3` (one per capture handle) while Zeek runs — the flag does not appear
in `ip -br` output because `AF_PACKET` promisc is a socket-level request, not the
`IFF_PROMISC` interface flag.

### 2. Zeek did not start on boot at all

Separately, `zeekctl` had no boot mechanism — no systemd unit, no `@reboot` cron,
no `zeekctl cron` entry. Bringing `ens37` up persistently would have left the
interface ready and Zeek still stopped until someone ran `zeekctl deploy` by hand.

Fixed with a systemd unit, ordered after the network so the interface is up first:

`/etc/systemd/system/zeek.service`:

```ini
[Unit]
Description=Zeek network security monitor (zeekctl)
Documentation=https://docs.zeek.org
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/opt/zeek/bin/zeekctl deploy
ExecStop=/opt/zeek/bin/zeekctl stop
TimeoutStartSec=120

[Install]
WantedBy=multi-user.target
```

`systemctl enable zeek`.

### Verified across a reboot

A reboot is the only real test, since a reboot is what broke it. After
`sudo reboot`, with no manual steps:

| Check | Command | Result |
| ----- | ------- | ------ |
| Interface up | `ip -br link show ens37` | `UP` |
| Service started | `systemctl is-active zeek` | `active` |
| Zeek running | `zeekctl status` | `running`, started 22:30:44 — before the login at 22:30:56 |
| Promiscuous | `ip -d link show ens37` | `promiscuity 3` |
| Actually writing | `ls -l …/logs/current/conn.log` | fresh timestamp, not just alive |

The last row is the point. A service can be `active` while capturing nothing — the
same way filebeat was `active` while reading a stale file in the v3 EDR outage. The
test is that `conn.log` is being written, not that the process is up.

### Still not covered

The `Purple - Telemetry Gap` search is gated to Windows hosts by `windows_hosts.csv`
and cannot see a Linux sensor going dark — which is exactly how this stayed hidden
for six days. A cross-sensor liveness check that spans the NDR hosts is the next
logging item.

## Cross-sensor liveness check — covers the Linux sensors

**Status: written, verified by trigger, and deployed 31 Oct 2026.**

The `Purple - Telemetry Gap` search is gated to Windows hosts, so it is blind to a Linux
sensor going dark — the exact gap that hid the six-day Zeek outage. Its sibling,
`Purple - Sensor Feed Stale (NDR/EDR host, cross-feed)`, watches the sensor feeds instead: it
fires when a host sends two or more of `{zeek, suricata, wazuh}` and one feed has delivered
nothing for over 20 minutes while another from the same host is fresh under 10 — which proves
the host and forwarder are up and one sensor specifically stopped. Keyed on `_indextime`, like
Telemetry Gap, so a forwarder backfill cannot erase the gap retroactively.

Verified the same way the EDR rules were: baseline empty with both `security-vm` feeds at
`0.0m`; `systemctl stop zeek`, and at a 2-minute threshold the rule returned `security-vm`
with `stale_feeds=zeek` (3.1m) against Suricata still at `0.0m`, while at the shipped
20-minute threshold it stayed empty — a 3-minute gap is not an outage; `systemctl start zeek`
cleared it within a minute.

It covers `security-vm` because that host has two independent feeds (Zeek and Suricata) to
cross-check. It does **not** cover `wazuh-vm`, which sends only `wazuh` alerts and only when
an alert fires — a single, event-driven feed cannot be told apart from a dead host from the
indexer alone. Closing that needs a second heartbeat feed on `wazuh-vm`; scoped below.

## Pending

- ~~**A second heartbeat feed on `wazuh-vm`**~~ — **done 2 Nov 2026**, and the remedy as
  written here was wrong. See "Single-feed sensor host" below.
- ~~**Forwarder hygiene on `security-vm`**~~ — **done 2 Nov 2026**. See "Zeek log filter" below.
- **Zeek JSON output** via the Splunk Add-on for Zeek, so fields are TA-extracted
  rather than parsed positionally from `_raw`. (v4 README, "Logging improvement".)
- **Per-channel Windows sourcetypes** in the forwarder so the Sysmon add-on's CIM
  mappings apply and `Network_Traffic` populates. (v4 README, "Forwarder sourcetypes
  and CIM".)

## Single-feed sensor host — a heartbeat for `wazuh-vm` (2 Nov 2026)

`Purple - Sensor Feed Stale` needs two independent feeds per host to cross-check one against
the other. `wazuh-vm` sends one (`wazuh`, from `alerts.json`), so from the indexer alone a quiet
sensor and a dead one are indistinguishable.

**The remedy first written down was wrong, and measuring it is what showed that.** Both this
file and the rule's own description said: add a second heartbeat feed so the cross-check covers
that host. It does not work, because `alerts.json` is event-driven and bursty. With
`wazuh-manager` active and healthy, it was measured going **431 seconds** with no write,
against readings of 0–8 seconds minutes earlier. Cross-checking a 60-second timer feed against a
feed that behaves like that turns legitimate quiet into an outage alert. The feed was the right
idea; the cross-check was the wrong instrument.

So the heartbeat got its own search instead — `Purple - Wazuh Sensor Health (single-feed host)`
— and `Purple - Sensor Feed Stale` stays scoped to hosts with two real sensor feeds.

`/opt/splunkforwarder/bin/scripts/wazuh_heartbeat.sh`, mode `755`:

```sh
#!/bin/sh
m=$(systemctl is-active wazuh-manager 2>/dev/null); [ -n "$m" ] || m=unknown
f=/var/ossec/logs/alerts/alerts.json
if [ -f "$f" ]; then age=$(( $(date +%s) - $(stat -c %Y "$f") )); else age=-1; fi
printf '%s host=%s heartbeat=1 manager=%s alerts_age_sec=%s\n' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(hostname)" "$m" "$age"
```

Added to `/opt/splunkforwarder/etc/apps/search/local/inputs.conf`:

```
[script:///opt/splunkforwarder/bin/scripts/wazuh_heartbeat.sh]
disabled = false
interval = 60
index = main
sourcetype = wazuh:heartbeat
```

Two details that cost a round of debugging each:

- **`systemctl is-active X || echo unknown` is a trap.** `is-active` prints the state *and*
  exits non-zero when the unit is inactive, so the fallback runs as well and the input emits two
  lines — the second with no timestamp, indexed as its own event. The script tests for an empty
  value instead.
- **The trailing `Z` on the timestamp matters.** With it, Splunk parses the time as UTC and
  renders it in the viewer's zone; without it, it guesses.

Verified by trigger, all three states: empty on a healthy stack; `systemctl stop wazuh-manager`
returned `wazuh-vm` with `manager=inactive` at `hb_age_min=0.7`, which is the proof it separates
a dead manager from a dead host rather than only reporting staleness; `systemctl start` cleared
it on the next run. `alerts_age_sec` ships as a field but is deliberately **not** a firing
condition — one sample is not a threshold, so the benign-baseline window measures the natural
quiet distribution before it is set.

## Zeek log filter — the forwarder was ingesting bookkeeping files (2 Nov 2026)

The stanza monitored the whole directory with no filter:

```
[monitor:///opt/zeek/logs/current]
disabled = false
index = main
sourcetype = zeek
```

**Before, measured over 24 hours:** 141 distinct `source` values from `security-vm`, of which
roughly **70 were not logs** — about 47 `.archive-log.running.*.tmp`, 22 `.rotated.*`, plus
`stderr.log`. They account for only ~92 events, under 1% of the 11,303 in that window, so this
was never a volume problem: it doubled the cardinality of every `stats count by source` while
hiding in the noise of a byte count.

**`*.log` alone is not the right filter**, which the file listing showed before anything was
changed. The `.rotated.*` files carry no extension (`.rotated.conn`, `.rotated.dns`) and a
`\.log$` whitelist excludes them correctly — but `stdout.log` and `stderr.log` do end in `.log`
and are Zeek's process output, not Zeek logs, so they would have passed straight through. A
whitelist alone would have left the second half of the problem in place.

`stderr.log` is also where the *reason* for a Zeek failure is written — the
`pcap_activate: device is not up` that kept the sensor dead for six days was sitting in it the
whole time. So it is routed to its own sourcetype rather than discarded, which keeps it
searchable without feeding non-TSV lines to the two searches that parse Zeek positionally.

```
[monitor:///opt/zeek/logs/current]
disabled = false
index = main
sourcetype = zeek
whitelist = \.log$
blacklist = (stdout|stderr)\.log$

[monitor:///opt/zeek/logs/current/stderr.log]
disabled = false
index = main
sourcetype = zeek:stderr
```

Deliberately **not** added to the sourcetype list in `Purple - Sensor Feed Stale`: `zeek:stderr`
is written only when Zeek has something to say, so as a third feed it would look permanently
stale and fire the rule — the same trap the `wazuh-vm` heartbeat would have sprung, avoided in
advance this time.

**Verified by probe, and the control is the part that makes it a proof.** Three files were
written into the log directory at once: `.rotated.TESTPROBE`, `.archive-log.running.99999.tmp`,
and `probe_control.log`. Querying on `_index_earliest` — delivery time, not `_time`, since the
question is what *arrived* — returned `probe_control.log` under `zeek` and nothing from the
other two. Without the positive control, two absences would equally have meant "the forwarder
stopped scanning the directory". A line appended to `stderr.log` arrived under `zeek:stderr`,
confirming that route as well. Legitimate traffic was unaffected across a five-minute window
after the restart: `conn.log` 197 events, `dns.log` 313, plus `files.log`, `http.log`,
`kerberos.log` and the rest.

The first attempt at this check queried on `_time` and proved nothing — a `.rotated.conn` from
before the restart still fell inside the window. That is the same `_time`-versus-`_indextime`
distinction `Purple - Telemetry Gap` was corrected for, walked into again here.

Previous config backed up to `inputs.conf.bak-zeekfilter` on the host.
