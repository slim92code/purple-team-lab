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

## Pending

- **Cross-sensor liveness check** — covers the Linux NDR/EDR hosts the telemetry-gap
  search does not.
- **Zeek JSON output** via the Splunk Add-on for Zeek, so fields are TA-extracted
  rather than parsed positionally from `_raw`. (v4 README, "Logging improvement".)
- **Per-channel Windows sourcetypes** in the forwarder so the Sysmon add-on's CIM
  mappings apply and `Network_Traffic` populates. (v4 README, "Forwarder sourcetypes
  and CIM".)
