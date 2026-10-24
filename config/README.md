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

The running config was dumped off each host with `sysmon64 -c` and diffed against the
SwiftOnSecurity baseline. THEPUNISHER differed in **two** sections, not one:

| Section | THEPUNISHER (hand-edited) | SPIDERMAN | In this file |
| ------- | ------------------------- | --------- | ------------ |
| `NetworkConnect` | `C:\Temp\` + `C:\Users\` + `C:\ProgramData\` | baseline | `C:\Temp\` only |
| `ProcessAccess` | `TargetImage is C:\Windows\system32\lsass.exe` | empty `include` | same rule (change 2) |

Note which way round that is. SPIDERMAN was not the drifted host — it was running the
baseline faithfully, and the baseline logs no EID 10. THEPUNISHER was the odd one out,
because someone had added those lines on the host and never folded them back into this file.
The v3 finding was written up as a per-host blind spot; the cause was the config in this
directory, and change 2 above is that fix.

**Two of THEPUNISHER's three `NetworkConnect` additions were redundant.** The
SwiftOnSecurity baseline's include list already carries `C:\Users` (as `Usermode`),
`C:\ProgramData` and `C:\Windows\Temp`. Adding `C:\Users\` and `C:\ProgramData\` on top
of that changed nothing; only `C:\Temp\` was a real gap, and that is the one this file
ships. Whoever made the edit did not check what the baseline already covered — which is the
cheap version of the same mistake the rest of this repo keeps finding, and it is also why the
v2 write-up can say precisely that the baseline covers `C:\Users`, `C:\ProgramData` and
`C:\Windows\Temp` but not a bare `C:\Temp`.

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

The fix is in this file but has not been re-deployed and re-tested on both hosts, so the
before/after proof that the rest of the repo insists on is not here yet. That is carried
into [v4](../v4/README.md).

Before reusing this file, compare it against what the host is actually running. The
deployed config is the one that decides what gets logged.
