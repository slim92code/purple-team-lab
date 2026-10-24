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

The two endpoints were running different `ProcessAccess` sections during the v3 run. Checked
with `sysmon64 -c` on each host:

| Host | `ProcessAccess` section during v3 | Relationship to this file |
| ---- | --------------------------------- | ------------------------- |
| THEPUNISHER | one rule, `TargetImage is C:\Windows\system32\lsass.exe` | hand-edited on the host |
| SPIDERMAN | `onmatch: include` with no rule lines, so it matches nothing | the shipped baseline, unmodified |

Note which way round that is. SPIDERMAN was not the drifted host — it was running the
baseline faithfully, and the baseline logs no EID 10. THEPUNISHER was the odd one out,
because someone had added the `lsass` line there by hand and never folded it back into this
file. The v3 finding was written up as a per-host blind spot; the cause was the config in
this directory, and change 2 above is that fix.

SPIDERMAN therefore logged no EID 10 at all: 1,191 process-create events and zero
`ProcessAccess` events over the same period. An LSASS dump on that host would have left no
Sysmon trace. See screenshot 12 in [`v3/README.md`](../v3/README.md).

The fix is in this file but has not been re-deployed and re-tested on both hosts, so the
before/after proof that the rest of the repo insists on is not here yet. That is carried
into [v4](../v4/README.md).

Before reusing this file, compare it against what the host is actually running. The
deployed config is the one that decides what gets logged.
