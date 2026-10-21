# config

`sysmonconfig.xml` — Sysmon configuration used on all Windows hosts in the lab (SwiftOnSecurity-style baseline).

**Lab-specific change (T1071.001):** one added `NetworkConnect` rule for `C:\Temp\` (see the `PurpleLab` rule). The baseline logs `C:\Users`, `C:\ProgramData` and `C:\Windows\Temp`, but not a bare `C:\Temp`, so the Sliver beacon went unlogged until this line was added.

Apply with: `sysmon64.exe -c sysmonconfig.xml`
