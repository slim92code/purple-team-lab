# CASE-07 — Sliver C2 beaconing, found by JA4 rather than by filename

| | |
| --- | --- |
| Alert | `V3 - JA4 C2 Beacon` (Splunk, ad hoc) over Zeek `ssl.log` on 20 Oct; shipped as `Purple - Sliver C2 Beacon by JA4 Fingerprint`, which was not deployed until 30 Oct |
| Fired | 20 Oct 2026, across the whole run |
| Severity | High |
| MITRE | [T1071.001 — Web Protocols](https://attack.mitre.org/techniques/T1071/001/) |
| Verdict | True positive. Two compromised endpoints linked by one fingerprint. |
| Related | Spans [CASE-03](CASE-03-pass-the-ticket.md) to [CASE-06](CASE-06-persistence-scheduled-task.md) |

## 1. What the alert showed

TLS sessions from two internal hosts to `192.168.182.133`, sharing an identical JA4 client
fingerprint:

```
t13i131000_f57a46bbacb6_e5728521abd4
```

![JA4 fingerprint](../screenshots/09_c2_ja4_fingerprint.png)

| Source | Beacons |
| ------ | ------- |
| SPIDERMAN (`.138`) | 69 |
| THEPUNISHER (`.137`) | 27 |

## 2. Questions

1. What is `192.168.182.133` and does anything legitimate talk to it over TLS?
2. Why does TLS on 443 look like C2 rather than like ordinary browsing?
3. Can the two hosts be linked without relying on a filename or hash?
4. How long had this been running before anything else fired?

## 3. Queries

```spl
index=main source="*ssl.log*" NOT _raw="#*"
| search "t13i131000_f57a46bbacb6_e5728521abd4"
| rex field=_raw "^(?P<ts>\S+)\t\S+\t(?P<orig_h>\S+)\t\S+\t(?P<resp_h>\S+)"
| stats count earliest(_time) as first latest(_time) as last by orig_h, resp_h
```

Interval analysis, which is what separates a beacon from a session:

```spl
index=main source="*ssl.log*" NOT _raw="#*"
| search "t13i131000_f57a46bbacb6_e5728521abd4"
| rex field=_raw "^(?P<ts>\S+)\t\S+\t(?P<orig_h>\S+)"
| sort _time
| streamstats current=f last(_time) as prev by orig_h
| eval gap=_time-prev
| stats avg(gap) as avg_interval stdev(gap) as jitter count by orig_h
```

Endpoint side, which process is responsible:

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
  DestinationIp="192.168.182.133" DestinationPort=443
| table _time, host, Image, User
```

## 4. Findings

| | |
| --- | --- |
| Destination | `192.168.182.133`, the non-domain host from CASE-01 |
| Protocol | HTTPS on 443 — Sliver `https` listener, implant built with `--http` (attack screenshot 04) |
| JA4 | `t13i131000_f57a46bbacb6_e5728521abd4` on both hosts |
| Volume | 96 sessions total |
| Implant | Sliver, delivered as `MicrosoftEdgeUpdate.exe` (v2 used `GlobalProtect_Update.exe`) |

**One fingerprint linked two separate compromises.** The two implants were delivered at
different times through different routes, SPIDERMAN by payload delivery and THEPUNISHER by
the WinRM pivot in CASE-04. Nothing about the filenames or hashes tied them together. The
JA4 did, because it is derived from how the TLS client is built rather than from what the
file is called. Renaming the binary does not change it.

**TLS on 443 is not the signal. The shape of the traffic is.** The destination is inside
the estate, it has no machine account, and nothing else in the environment talks to it.
Regular intervals with jitter across 96 sessions is a beacon rather than a browsing pattern.

**JA4 is still an indicator, and that limit should be stated.** It is tied to this Sliver
build's TLS stack. A different C2, or a Sliver version with a changed client profile,
produces a different fingerprint and this rule misses it. It is more durable than a hash and
less durable than behaviour. The behavioural companion is the rule that keys on process
location plus egress, which catches a renamed implant from a user-writable path without
knowing anything about its TLS.

**The CIM version of the behavioural rule cannot run in this lab.** The shipped
`Purple - C2 Beacon from User-Writable Path (CIM tstats)` search queries
`Network_Traffic.All_Traffic`, which holds 0 events here. 444 Sysmon EID 3 events reach the
index in seven days with no `app`, `src`, `dest` or `dest_port` fields, because the
forwarder ships every Windows channel as a bare `WinEventLog` sourcetype and the Sysmon
add-on keys its CIM mappings on the per-channel sourcetype. The rule is correct and the data
never arrives in the shape it expects. It ships unscheduled with that written on it.

## 5. Verdict

True positive. Two endpoints beaconing to an internal non-domain host over HTTPS, from the
same C2 framework, for the duration of the run.

**On the protocol, because the wording changed.** This run used Sliver's `https` listener
with an `--http` implant, ordinary server-side TLS, which is what the JA4 ClientHello
fingerprint is taken from. v2 used Sliver's `mtls` listener, and any "mutual TLS" wording in
this case file was carried over from there. The attack screenshot settles it: `https --lport
443`, then `generate --http 192.168.182.133:443`. The distinction matters for recommendation
9 below.

## 6. Where this sits in the chain

C2 is not a phase, it is the channel the other phases ran over. The Pass-the-Ticket in
CASE-03, the pivot in CASE-04, the LSASS read in CASE-05 and the persistence in CASE-06 all
executed through these sessions. An analyst who finds the beacon first gets the whole chain;
one who finds it last is reading the aftermath.

## 7. Recommendations

Containment:

1. Block `192.168.182.133` at the egress point and hunt for any other host that has talked
   to it.
2. Rebuild both endpoints. Two implants and SYSTEM persistence on one of them.
3. Preserve the `ssl.log` and `conn.log` records before rotation, since the network layer is
   the only place the full beacon history exists.

Detection tuning:

4. Keep the JA4 rule, and know that it is an indicator. Alert on it, do not rely on it.
5. The behavioural rule is the durable half. Fix the forwarder sourcetypes so
   `Network_Traffic` populates, then re-test it. An empty data model and a broken rule look
   identical from the alert list.
6. Alert on any internal host with no machine account receiving TLS from several endpoints.
   That is a stronger structural signal than any single fingerprint.
7. Add interval and jitter analysis as a scheduled hunt rather than an alert. It is slow and
   it finds beacons that match no known fingerprint.

Hardening:

8. Egress filtering. In this lab the C2 destination is internal, which a flat network
   permits and segmentation would not.
9. TLS inspection at the perimeter. This channel is server-side HTTPS, not mutual TLS, so
   it does not have the client-certificate barrier that mTLS puts in the way, but whether an
   inline proxy can actually read it still depends on whether the implant validates or pins
   the server certificate. The listener choice decides how much this control can see, and it
   is not the automatic dead end that "mutual TLS" would have made it.
10. Application allowlisting stops the implant before it beacons, which is the only control
    here that acts rather than observes.
