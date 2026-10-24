# config

`sysmonconfig.xml` is the Sysmon configuration for this lab, a SwiftOnSecurity-style
baseline with one lab-specific change.

**Lab-specific change (T1071.001).** One added `NetworkConnect` rule for `C:\Temp\` (the
`PurpleLab` rule). The baseline logs `C:\Users`, `C:\ProgramData` and `C:\Windows\Temp` but
not a bare `C:\Temp`, so the Sliver beacon went unlogged until this line was added. See the
gap-and-fix pair in [`v2/README.md`](../v2/README.md).

Apply with:

```
sysmon64.exe -c sysmonconfig.xml
```

## This is the intended config, not what every host runs

The hosts drifted, and that drift is one of the v3 findings rather than something to tidy
away. Checked with `sysmon64 -c` on each host:

| Host | `ProcessAccess` section |
| ---- | ----------------------- |
| THEPUNISHER | one rule, `TargetImage is C:\Windows\system32\lsass.exe` |
| SPIDERMAN | `onmatch: include` with no rule lines under it, so it matches nothing |

SPIDERMAN therefore logs no EID 10 at all: 1,191 process-create events and zero
`ProcessAccess` events over the same period. An LSASS dump on that host would leave no
Sysmon trace. See screenshot 12 in [`v3/README.md`](../v3/README.md).

Before reusing this file, compare it against what the host is actually running. The
deployed config is the one that decides what gets logged.
