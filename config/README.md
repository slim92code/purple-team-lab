# config

`sysmonconfig.xml` is the Sysmon configuration for this lab, a SwiftOnSecurity-style
baseline with two lab-specific changes. Both exist because a detection was written first and
the telemetry to feed it turned out to be missing.

**Change 1 — `NetworkConnect` for `C:\Temp\` (T1071.001).** The baseline logs `C:\Users`,
`C:\ProgramData` and `C:\Windows\Temp` but not a bare `C:\Temp`, so the Sliver beacon went
unlogged until the `PurpleLab` rule was added. See the gap-and-fix pair in
[`v2/README.md`](../v2/README.md).

**Change 2 — `ProcessAccess` for `lsass.exe` (T1003.001).** The baseline ships this section
as an `onmatch="include"` with no rule lines, and an include with no rules logs nothing. So
the baseline produces **zero EID 10**, and the LSASS detections in
[`detections/`](../detections/): a Sigma rule, a Splunk search and three Wazuh rules, tuned
against 935 sampled reads — had nothing to match on a host running it unmodified. One
`TargetImage` line for `lsass.exe` closes it. The benign readers are filtered in the
detection rules rather than here, because excluding them at the sensor would also hide a
process masquerading as one of them.

The second one is the uncomfortable part. The detection was built, tuned and documented
before anyone checked whether the shipped config could feed it. The rule was correct and the
coverage was still zero.

Apply with:

```
sysmon64.exe -c sysmonconfig.xml
```

## This is the intended config, not what every host runs

The running config was read off all three hosts with `sysmon64 -c`, 25 Oct 2026, and this is
what they were actually running during v3:

| Host | `NetworkConnect` `C:\Temp\` | `ProcessAccess` lsass |
| ---- | --------------------------- | --------------------- |
| HYDRA-DC | yes | **no** |
| SPIDERMAN | yes | **no** |
| THEPUNISHER | yes | yes, added by hand |

**The v2 fix was deployed everywhere; the LSASS rule was nowhere except one host.** That is
the opposite of what a per-host blind spot would look like, and it points at this file rather
than at the estate: every host was running the config from this directory faithfully, and the
config had `ProcessAccess` as an empty `include`. THEPUNISHER produced LSASS telemetry only
because someone added the `TargetImage` line on that machine and never folded it back here.
The one host that worked was the exception, not the rule.

It also means the v3 write-up had the diagnosis right and the attribution wrong. SPIDERMAN
was not misconfigured. It was configured exactly as this repo said to configure it.

Worth separating from that: THEPUNISHER's hand-edit also added `C:\Users\` and
`C:\ProgramData\` to `NetworkConnect`, and both were redundant — the SwiftOnSecurity
baseline's include list already carries `C:\Users` (as `Usermode`), `C:\ProgramData` and
`C:\Windows\Temp`. Only `C:\Temp\` was a real gap, which is why that is the single line
this file adds, and why the v2 write-up can be that precise about which paths the baseline
covers.

**Deploying this file over THEPUNISHER loses nothing**, which was established by taking the
diff rather than by assuming it. Its `C:\Temp\` rule is kept as the `PurpleLab` line here,
its two redundant lines are covered by the baseline, and its `lsass` rule is now in this
file. The order matters and is worth copying: a running config is evidence, so dump it with
`sysmon64 -c > before.txt` and diff it before you overwrite it. THEPUNISHER's running config
was the only record of what produced the v3 LSASS events, and replacing it blind would have
destroyed that record to apply a change that turned out to be a no-op for that host.

SPIDERMAN therefore logged no EID 10 at all: 1,191 process-create events and zero
`ProcessAccess` events over the same period. An LSASS dump on that host would have left no
Sysmon trace. See screenshot 12 in [`v3/README.md`](../v3/README.md).

### Re-deployed and re-proven, 25 Oct 2026

I applied the config above with `sysmon64 -c` and measured the result in Splunk rather than
assuming it.

| Host | Before: EID 10 over 7 days | After: EID 10 in the first hour |
| ---- | -------------------------- | ------------------------------- |
| THEPUNISHER | 1,948 | 179 |
| SPIDERMAN | **0** | **60** |
| HYDRA-DC | **0** | **49** |

Two hosts that had produced nothing in a week started producing within minutes. The targeted
trigger (a PowerShell handle to `lsass.exe`) came back as
`powershell.exe` → `lsass.exe` at `GrantedAccess 0x1F3FFF` on SPIDERMAN, which is the same
mask SharpKatz used during the v3 run and is in the shipped detection mask list. So the
telemetry the LSASS rules were written against now exists on the host that was blind to it.

The benign traffic that came with it is worth reading too, because it is the exclusion list
proving itself: `MsMpEng.exe`, `svchost.exe`, `vmtoolsd.exe` and `wmiprvse.exe` all appear,
and all of them at `0x1000`, `0x1010`, `0x1400`, `0x1410`, masks that are not in the
detection list at all. The rules would stay silent on every one of them without the
exclusions even being consulted.

**HYDRA-DC was briefly written up as an anomaly, and that is worth keeping.** Its 20 events
looked unexplained because the deployment was believed to have run on SPIDERMAN only. Reading
the running config settled it: HYDRA-DC's `ProcessAccess` section held no rule at the first
check and holds the `lsass` rule now, so the config had in fact been applied there. Recollection
said one thing, `sysmon64 -c` said another, and the running config won, which is the same
lesson as the rest of this directory, applied to the person doing the deploying rather than to
the config.

THEPUNISHER was not redeployed. The diff predicts the change would be a no-op there, since it
is already running the `lsass` line by hand, and that prediction is on record here before the
test rather than after it.

### The prediction, tested 29 Oct 2026

Dumped the running config, applied this file, dumped again, diffed. `Compare-Object` returned
two lines, and both are the same field:

```
- Config file:   .\sysmonconfig_fixed_v3.xml
- Config file:   C:\Users\frankcastle\Desktop\UF_Sysmon\sysmon-config-master\sysmonconfig_fixed_v3.xml
```

Relative path before, absolute after: the same file, written differently depending on how it
was invoked. Not one rule, filter or exclusion changed. **The prediction holds.**

The diff against the hand-edited config still on that host was re-taken at the same time and
accounts for every line: 18 differences, 11 of them only in this file (the two `PurpleLab`
rules plus the nine comment lines that explain them) and 7 only in the hand-edit (the same
two rules unnamed, the two redundant `NetworkConnect` paths, two comments and a blank). No
unexplained drift in either direction, which is the claim above checked rather than repeated.

The before-dump also settles something this page had wrong. It names the running config as
`sysmonconfig_fixed_v3.xml` — the file shipped here — so by the time of the test THEPUNISHER
was not running a hand-edit at all. The hand-edited `lsass` line is what produced the v3
evidence on 20 October, and that stands; but at some point after this file was written it was
applied to that host too, and the table above kept describing a state that had already moved
on. The prediction was right for a reason other than the one recorded next to it, which is
worth more than being right for the stated one.

One thing the dump prints that is not a defect: the config declares `schemaversion 4.50`
while the installed Sysmon reports schema 4.90. Older schema on a newer binary is accepted
and loads as written, which is why this file is portable across the three hosts without a
per-host variant.

### What the redeployment turned up on the way

THEPUNISHER did not appear in Splunk after its trigger, which looked at first like the
deployment having broken the one host that worked. Reading its local Sysmon log directly
settled that: the events were there, at `01:16:58` and `01:20:58`, with the service running
and the rule loaded. Sysmon was fine. The events were not reaching the SIEM.

Grouping everything that host had ever sent, by source, showed why:

| Source | Last seen |
| ------ | --------- |
| `Perfmon:CPU Load` | 01:23:34 — current |
| `Perfmon:Available Memory` | 01:23:34 — current |
| `Perfmon:Network Interface` | 01:23:34 — current |
| `WinEventLog:Security` | **00:17:54 — stopped** |
| `WinEventLog:Microsoft-Windows-Sysmon/Operational` | **00:17:49 — stopped** |
| `WinEventLog:Microsoft-Windows-PowerShell/Operational` | **00:17:53 — stopped** |
| `WinEventLog:System` | **00:14:32 — stopped** |

**Every Windows event log channel had stopped about 68 minutes earlier while Perfmon kept
flowing.** The forwarder was alive; only its Windows Event Log inputs had wedged. It had
nothing to do with the Sysmon change, which came after. `Restart-Service SplunkForwarder`
cleared it and every channel resumed within a minute.

This is worse than the gap it was found chasing. A host whose security telemetry is dead but
whose performance counters keep arriving **looks healthy in every "is this host reporting?"
check there is.** Host count, event volume, agent status, the forwarder's own service state —
all green, for over an hour, with no Security, Sysmon, PowerShell or Defender events from a
domain endpoint. An attack on THEPUNISHER in that window would have left nothing in the SIEM.

The lesson is that liveness has to be measured per channel, not per host, and the detection
for it is in the Splunk app as `Purple - Telemetry Gap (Windows logs stale, host still
reporting)`. It is the only rule in this repo that watches the pipeline rather than the
attacker.

**This fixes the sensor, not the EDR.** The events above reached Splunk, which is what the
Sigma rule and the Splunk search need. They will still not reach Wazuh on SPIDERMAN or
HYDRA-DC, because only THEPUNISHER has a `Microsoft-Windows-Sysmon/Operational` block in its
`ossec.conf`: a separate gap, documented in [v3](../v3/README.md), and untouched by this
change. One blind spot had two independent causes stacked on top of each other, and clearing
the first did not clear the second.

The second was closed separately on 29 Oct 2026 by adding the missing
`Microsoft-Windows-Sysmon/Operational` block to `ossec.conf` on both agents and restarting
them. `100200` then fired at level 12 on SPIDERMAN and HYDRA-DC for the first time. Two fixes,
in two different files, on two different days, for what presented as a single symptom.

There was a third, found the same evening by opening the Wazuh console instead of reading the
log file. It had received nothing since 24 October: a corrupted translog had left one shard
unassigned, every filebeat bulk carried a document bound for that index and failed, and the
retry loop held five days of alerts behind it. The `100200` alerts above were real and were
never visible to an analyst. The whole chain is in
[CASE-05](../v3/investigations/CASE-05-lsass-access.md#45-and-the-alerts-never-reached-the-console).

Before reusing this file, compare it against what the host is actually running. The
deployed config is the one that decides what gets logged.
