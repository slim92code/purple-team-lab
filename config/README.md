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
[`detections/`](../detections/) — a Sigma rule, a Splunk search and three Wazuh rules, tuned
against 935 sampled reads — had nothing to match on a host running it unmodified. One
`TargetImage` line for `lsass.exe` closes it. The benign readers are filtered in the
detection rules rather than here, because excluding them at the sensor would also hide a
process masquerading as one of them.

That second one is worth being blunt about: the detection was built, tuned and documented
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

The config above was applied with `sysmon64 -c` on **SPIDERMAN only** so far, and the result
measured in Splunk rather than assumed.

| Host | Before: EID 10 over 7 days | After: EID 10 in 10 minutes | Config deployed |
| ---- | -------------------------- | --------------------------- | --------------- |
| THEPUNISHER | 1,948 | not in window | not yet |
| SPIDERMAN | **0** | **18** | yes |
| HYDRA-DC | **0** | **20** | **not yet — unexplained, see below** |

SPIDERMAN is the clean result: zero in a week, 18 within minutes of the config being applied.
The targeted trigger — a PowerShell handle to `lsass.exe` — came back as
`powershell.exe` → `lsass.exe` at `GrantedAccess 0x1F3FFF` on SPIDERMAN, which is the same
mask SharpKatz used during the v3 run and is in the shipped detection mask list. So the
telemetry the LSASS rules were written against now exists on the host that was blind to it.

The benign traffic that came with it is worth reading too, because it is the exclusion list
proving itself: `MsMpEng.exe`, `svchost.exe`, `vmtoolsd.exe` and `wmiprvse.exe` all appear,
and all of them at `0x1000`, `0x1010`, `0x1400`, `0x1410` — masks that are not in the
detection list at all. The rules would stay silent on every one of them without the
exclusions even being consulted.

**HYDRA-DC is an open question, not a result.** It also went from zero in seven days to 20
events in the same ten-minute window, but the config was never applied there, so the deploy
cannot be the cause. Something else changed on that host between the two measurements and
nothing here identifies it. It is recorded as an anomaly rather than folded into the result,
because attributing it to a change that did not happen is exactly the error this repo keeps
documenting in other people's rules. The before/after above rests on SPIDERMAN alone until
HYDRA-DC is explained.

THEPUNISHER has not been redeployed either. The diff predicts the change will be a no-op
there, since it is already running the `lsass` line by hand — but that is a prediction, and it
is on record here before the test rather than after it.

**This fixes the sensor, not the EDR.** The events above reached Splunk, which is what the
Sigma rule and the Splunk search need. They will still not reach Wazuh on SPIDERMAN or
HYDRA-DC, because only THEPUNISHER has a `Microsoft-Windows-Sysmon/Operational` block in its
`ossec.conf` — a separate gap, documented in [v3](../v3/README.md), and untouched by this
change. The Wazuh LSASS rules therefore remain single-host until the agent config is fixed
too. One blind spot had two independent causes stacked on top of each other, and clearing the
first does not clear the second.

Before reusing this file, compare it against what the host is actually running. The
deployed config is the one that decides what gets logged.
