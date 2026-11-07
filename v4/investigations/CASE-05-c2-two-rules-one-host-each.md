# CASE-05 — Two C2 rules, one endpoint each, and neither covers both

| | |
| --- | --- |
| Alert | Both C2 rules fire. **Each names one host, and they are different hosts.** |
| Fired | 6 Nov 2026 — SPIDERMAN 12:04–12:09, THEPUNISHER 16:48 CET |
| Severity | Critical |
| MITRE | [T1071.001 — Web Protocols](https://attack.mitre.org/techniques/T1071/001/), [T1573 — Encrypted Channel](https://attack.mitre.org/techniques/T1573/) |
| Verdict | True positive on two hosts. Full coverage only when both rules are read together. |
| Cells | [`#2` and `#14` in the coverage matrix](../coverage-matrix.md) |

## 1. What the alerts showed

Two rules, both firing, on what an analyst would reasonably read as two separate incidents.

`Purple - Sliver C2 Beacon by JA4 Fingerprint`:

| Host | Handshakes | Window | Mean interval | Jitter |
| ---- | ---------- | ------ | ------------- | ------ |
| SPIDERMAN (`.138`) | 11 | 12:04:15–12:09:15 | 30.0 s | 23.9 s |

`Purple - C2 Beacon from User-Writable Path`:

| Host | Beacons | app | Window |
| ---- | ------- | --- | ------ |
| SPIDERMAN | 6 | `C:\Temp\GlobalProtect_Update.exe` | 12:04–12:09 |
| **THEPUNISHER** | **1** | `C:\Temp\GlobalProtect_Update.exe` | **16:48** |

The first names one host. The second names two. **The second host appears in only one of the two
alerts**, and the reason is not that the attack was different there.

## 2. Questions

1. Is the shipped JA4 fingerprint still the one this C2 produces, or has it drifted since v3?
2. `#14` names SPIDERMAN and `#2` names both. Why does `#14` miss THEPUNISHER?
3. Do the two rules agree on the SPIDERMAN beacon, or are they describing different traffic?
4. Does either rule's output say where the beacon was talking to?
5. Both rules carry allowlists. Did either leak?

## 3. Queries

`#14` verbatim, which matches the fingerprint as a bare string because there is no field to match
on — see 4.4:

```spl
source="*ssl.log*" NOT _raw="#*" "t13i131000_f57a46bbacb6_e5728521abd4" earliest=-7d latest=now
| rex field=_raw "^(?P<ts>\S+)\t\S+\t(?P<orig_h>\S+)\t\S+\t(?P<resp_h>\S+)"
| sort 0 _time
| streamstats current=f last(_time) as prev by orig_h resp_h
| eval gap=_time-prev
| stats count avg(gap) as avg_interval stdev(gap) as jitter min(_time) as firstTime max(_time) as lastTime by orig_h resp_h
| where count > 5
```

The same fingerprint without the threshold, which is the query that explains the cell:

```spl
source="*ssl.log*" NOT _raw="#*" "t13i131000_f57a46bbacb6_e5728521abd4" earliest=-7d latest=now
| rex field=_raw "^(?P<ts>\S+)\t\S+\t(?P<orig_h>\S+)\t\S+\t(?P<resp_h>\S+)"
| stats count by orig_h resp_h
```

`#2` verbatim, over the CIM model, including the `where NOT` allowlist:

```spl
| tstats summariesonly=false allow_old_summaries=true count values(All_Traffic.dest_port) as dest_ports
    from datamodel=Network_Traffic.All_Traffic
    where (All_Traffic.app="*\\Temp\\*" OR All_Traffic.app="*\\AppData\\*" OR All_Traffic.app="*\\ProgramData\\*" OR All_Traffic.app="*\\Users\\Public\\*")
    by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app _time span=1m
| rename "All_Traffic.*" AS *
| where NOT (like(app,"%\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe")
      OR like(app,"%\\AppData\\Local\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe")
      OR like(app,"%\\AppData\\Local\\Microsoft\\OneDrive\\%\\OneDrive.Sync.Service.exe"))
| stats count dc(_time) as beacons earliest(_time) as firstTime latest(_time) as lastTime by src dest dest_port app
```

And the control, because a `tstats` rule can return nothing for three different reasons:

```spl
index=main sourcetype=XmlWinEventLog EventCode=3 earliest=-1d latest=now
| stats count values(DestinationIp) as dests by Image
```

## 4. Findings

### 4.1 No fingerprint drift, and twelve handshakes to one address

```
t13i131000_f57a46bbacb6_e5728521abd4
```

The fingerprint hard-coded in `#14` is **exactly** the one this run produced. It has not moved
since v3, which matters more than it sounds: a JA4 rule is a hard-coded string, and a C2 rebuild
or a TLS library change silently retires it. This one still matches.

Twelve handshakes carry it in the window, and every single one goes to `192.168.182.133` — the
Sliver host. Not one goes anywhere else, which is what makes the fingerprint a usable pivot
rather than a classifier.

### 4.2 The threshold is why THEPUNISHER is missing, and the threshold is right

Without `where count > 5`:

| orig_h | resp_h | handshakes |
| ------ | ------ | ---------- |
| `192.168.182.138` | `192.168.182.133` | 11 |
| `192.168.182.137` | `192.168.182.133` | **1** |

One handshake has no interval, so there is nothing to measure a beacon period against and nothing
to call beaconing. Dropping the threshold to catch it would turn this rule into "any TLS
connection with this fingerprint", which is a different rule with a different false-positive
profile.

So `#14` is correct and incomplete at the same time, and that pair of properties is the case:
**the fingerprint is present on both endpoints and the alert covers one.** The v3 finding that a
single JA4 links both hosts still holds — it is visible in the evidence and invisible in the
alert. Read off the alert alone, half of it is gone.

### 4.3 The two rules agree where they overlap, from different telemetry

SPIDERMAN, both rules:

| Rule | Source | Window | Count |
| ---- | ------ | ------ | ----- |
| `#14` | Zeek `ssl.log`, TLS handshakes | 12:04:15–12:09:15 | 11 handshakes |
| `#2` | Sysmon `EventCode=3` via the CIM model | 12:04–12:09 | 6 one-minute buckets |

**The windows match to the minute, from two independent telemetry paths** — a network sensor
watching TLS and an endpoint agent watching process connections. Eleven handshakes inside six
minutes is consistent with six one-minute buckets. Nothing was correlated by hand; the two rules
were run separately and agree.

That is the corroboration an analyst wants and it is also what makes 4.2 solid rather than
suspicious: `#14`'s silence on THEPUNISHER is a threshold, not a disagreement between sensors.

**And `#2` has THEPUNISHER at 16:48**, four and a half hours after the SPIDERMAN activity, from
the same beacon path. (`#14`'s single THEPUNISHER handshake was counted but not timestamped in
this measurement, so the two are consistent rather than confirmed identical.)

**Together the two rules cover both endpoints. Neither covers both alone.** Worth knowing before
the hardening run, because a bundle that breaks one does not necessarily lose the host — and a
bundle that breaks the one carrying a host does.

### 4.4 `ja4` is not a field in this pipeline

This Zeek build ships `ja4d.log` (DHCP, 1,640 events) and `ja4ssh.log` (SSH, 69) and **no
`ja4.log`**. The TLS fingerprint is appended as a column to `ssl.log`, and the forwarder delivers
Zeek's TSV, so Splunk extracts no `ja4` field at all.

That explains the rule's shape. `#14` matches the fingerprint as a bare string in `_raw` because
there is nothing to compare a field against — not a stylistic choice, a constraint. Any search
that wants to **group** by fingerprint, including the one in 4.1 that proved the fingerprint goes
nowhere but the C2, needs a `rex` first.

The migration to JSON through the Splunk Add-on for Zeek, already noted in `savedsearches.conf`,
is what retires that. Until then this rule cannot be written any other way, and a reader
reviewing it should not read the string match as sloppiness.

### 4.5 The allowlist leaked, by one directory shape

`#2`'s three allowlist entries cover `OneDrive\OneDrive.exe`,
`OneDrive\OneDriveStandaloneUpdater.exe` and `OneDrive\<version>\OneDrive.Sync.Service.exe`. They
do not cover this:

| src | port | app | beacons | verdict |
| --- | ---- | --- | ------- | ------- |
| THEPUNISHER | 443 | `OneDrive\Update\OneDriveSetup.exe` | 2 | **false positive** |
| THEPUNISHER | 80 | `OneDrive\Update\OneDriveSetup.exe` | 1 | **false positive** |

A fourth OneDrive binary, in a fourth directory shape, and it fires.

The allowlist was measured against the benign window and **this binary did not run in it** —
`OneDriveSetup.exe` is an installer, so it appears when OneDrive updates itself and not
otherwise. That is the third rule in this column whose false-positive profile the benign window
was structurally unable to measure, alongside the Sysmon reader in `#10` and the real egress in
`#15`. One cause each time: **a false positive the baseline cannot see is one whose trigger the
baseline's conditions excluded.**

One more row is not a false positive and not the chain: `C:\Temp\nettest.exe` on SPIDERMAN,
port 8089, 31 October — a test binary from the lab's own work, six days before this run.

### 4.6 The alert names the process and not the destination

Every beacon row returns `dest = -`. The CIM model does not populate it.

The control shows Sysmon knows perfectly well:

```
C:\Temp\GlobalProtect_Update.exe    12 events    DestinationIp: 192.168.182.133
```

So `#2` tells an analyst which process beaconed, from which host, on which port, and **not what
it was talking to** — while the raw event two layers down has the address. Same defect class as
[CASE-04](CASE-04-lockout-alert-with-no-account.md): the rule fires, and the output is missing
the field the analyst asks for first.

Unlike CASE-04 this one is not a guessed field name. The `dest` field exists and is empty, which
points at the CIM mapping on the ingest path rather than at the rule.

### 4.7 Wazuh caught the drop, and the matrix has nowhere to put it

Measured independently, without reference to these cells:

| Wazuh rule | Level | What it saw |
| ---------- | ----- | ----------- |
| `92203` | 6 | *executable file created by powershell:* `C:\Temp\GlobalProtect_Update.exe` |
| `92213` | **15** | *executable file dropped in folder commonly used by malware* |

Level 15 is the highest severity anything in this chain produced, and it is the **drop** — the
implant being written to disk, before it ever beaconed.

**There is no cell for it.** Not in the before column, not anywhere, because the matrix was built
from the Splunk app's rule list and no Splunk search covers file creation in `C:\Temp`. Two Wazuh
rules caught the loudest event of the run and the table has no row to record it in.

This is the same structural gap as phase 7, found from the other direction, and it is the
strongest argument in this case for building the next column from the shipped detection content
rather than from one tool's view of it.

## 5. Verdict

**True positive on both endpoints. Correct on both rules. Complete on neither.**

- `#14` fires on SPIDERMAN, is right to stay silent on THEPUNISHER, and loses half the evidence
  in doing so.
- `#2` fires on both, leaks one false positive through an allowlist gap, and cannot say where the
  beacon connected.
- Together they cover the estate. Separately, each reads as a single-host incident.
- The loudest detection in the chain came from a third layer and has no cell at all.

## 6. What this changes

**Held until after the hardening run.**

| Owed | Detail |
| ---- | ------ |
| Extend `#2`'s allowlist to `OneDrive\Update\OneDriveSetup.exe` | A fourth binary in a fourth directory shape |
| Fix the `dest` mapping for `Network_Traffic` | The address is in Sysmon `EventCode=3`; the model drops it |
| Pair the two C2 rules in their descriptions | Neither says the other exists, and the coverage statement needs both |
| A cell for the implant drop | Wazuh `92203`/`92213` detect it at level 15 and the matrix cannot record it |

Nothing here is urgent and all of it is cheap, which is exactly why it is being held: the
before/after comparison is worth more than four small improvements applied at the wrong moment.

## 7. What a reader should take from this

**Two correct rules can produce an incorrect coverage picture.** Neither `#14` nor `#2` is wrong.
Both fire. A matrix that ticks each one and moves on records full coverage of a C2 that only one
rule saw on each host, and a reader checking "do we detect this beacon" gets yes from a table
where the honest answer is *yes, on this host, by this rule, for this reason*.

The habit that catches it is cheap: **when two rules cover the same technique, run both and
compare their host lists.** If the lists differ, the difference is the finding — and it will not
appear in either rule's own output.
