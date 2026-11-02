# Benign baseline — false-positive rate per rule

Every detection in this repo has been tested against an attack. None had been measured against
normal activity, which is the first thing anyone running a SOC asks, because alert fatigue is
what kills detection programmes.

This file is written **before** the measurement, so the method is on record ahead of the
results — the same reason v4's predictions were committed before the hardening run. The results
section is empty until the window closes.

---

## Method

**Window:** 24 hours, no attack. `Kali` (192.168.182.133) stays powered off for the duration;
that is the one hard condition.

**Opened:** 2026-11-02 16:19 CET (15:19 UTC). **Closes:** 2026-11-03 16:19 CET.

The timestamp is the indexer's own clock, not a host's, so the window boundaries and the
`_indextime` values the results are drawn from come from the same source.

All five feeds were verified live immediately before opening the window — `WinEventLog`,
`XmlWinEventLog`, `zeek`, `suricata`, `wazuh`, plus the `wazuh:heartbeat` added in the step-2
logging pass — each under one minute stale.

### The activity is generated, not waited for

Seven VMs left powered on and idle produce near-silence, and a window of silence measures
nothing: it returns zero for every rule and invites exactly the wrong conclusion. The list below
is derived per rule from what that rule actually keys on, because under the convention further
down, a rule whose false-positive source was never touched is reported as **unmeasured** however
long the window ran.

| Rule being calibrated | Its false-positive source | Driven during the window |
| --------------------- | ------------------------- | ------------------------ |
| `Purple - C2 Beacon from User-Writable Path` | processes sending traffic from `Temp` / `AppData` / `ProgramData` / `Users\Public` | OneDrive running on SPIDERMAN and THEPUNISHER (see below) |
| `Purple - Kerberoasting User-SPN Ticket (etype-agnostic)` | legitimate service tickets for SPNs held by user accounts | repeated `klist get` against the `SQLService` SPN from two domain principals |
| `Purple - Large Outbound Transfer` | legitimate bulk **egress** (`orig_bytes`, what an internal host sends) | file uploads to the share and an initial sync of a sizeable folder. **Not downloads** — those are almost entirely `resp_bytes` and never touch this rule's source |

Plus ordinary use: Office documents opened and saved, files read from and written to the share,
browsing, logon and logoff cycles across the three Windows hosts, scheduled-task and update
activity left enabled.

### What was measured before the window opened

Two things were checked rather than assumed, and both changed the plan.

**The AppData egress population, measured over 24 hours before starting.** Two processes on one
host:

| Process | Events / 24h | Host |
| ------- | ------------ | ---- |
| `…\AppData\Local\Microsoft\OneDrive\26.189.0928.0009\OneDrive.Sync.Service.exe` | 9 | SPIDERMAN |
| `…\AppData\Local\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe` | 2 | SPIDERMAN |

Thin, and on one host out of three. OneDrive was started on THEPUNISHER so the allowlist would
cover two, which immediately produced a **third** binary name, `OneDrive.exe`. It was not started
on HYDRA-DC: OneDrive on a domain controller is not a realistic scenario, so that host's cell is
reported as not applicable rather than as a measured zero.

**The allowlist has to key on a path pattern, not a path.** The version number sits inside the
path — `…\OneDrive\26.189.0928.0009\…` — so an allowlist built on the full path would break
silently at the next OneDrive update, opening a gap with no alert to announce it. Three
different binary names across two hosts make the same point from the other side. The pattern is
therefore `*\AppData\Local\Microsoft\OneDrive\*`.

**Correction, recorded because it is the point of measuring.** The plan assumed OneDrive was not
running at all, inferred from `Get-Process OneDrive` returning nothing. That inference was wrong:
the processes generating the traffic are `OneDrive.Sync.Service.exe` and
`OneDriveStandaloneUpdater.exe`, which that query does not match. The Sysmon data had the answer
the whole time.

### The Kerberos ticket is the trap in this window

A `4769` for a user-held SPN does not occur spontaneously in a quiet lab, and
`Purple - Kerberoasting User-SPN Ticket (etype-agnostic)` is blocked specifically on "an
allowlist of routinely requested SPNs" — an allowlist that cannot be built from a window in
which no SPN was requested. Left alone, this window would run for 24 hours and leave that rule
exactly as unschedulable as before.

Four things about it were established by measurement before the window, each of which would
have wasted the window on its own:

- **The requestor must be a domain principal.** The rule excludes machine requestors twice over,
  `Account_Name!="*$"` and `Account_Name!="*$@*"`, because on `4769` the requestor arrives as
  `principal@REALM`. Authenticating from a machine or service context produces events the rule
  filters out, which is indistinguishable from having generated nothing.
- **The workstation users are local accounts, not domain accounts.** `whoami` on SPIDERMAN
  returns `spiderman\peterparker`, and `klist get` from that session fails with `0x8009030e`,
  "no credentials are available in the security package" — a local account has no TGT to request
  a service ticket with. The domain principals are `pparker`, `fcastle`, `tstark`,
  `Administrator` and `SQLService`; `peterparker` and `frankcastle` exist only locally on the
  workstations.
- **Kerberos caching suppresses repeats.** The first `klist get` retrieves the ticket and a
  second returns the cached copy with no new `4769`, for the ticket's full ~10-hour lifetime. A
  task scheduled every 15 minutes would have produced one event and then silence, and a
  "measured frequency" drawn from it would have been fiction. Requests are therefore preceded by
  `klist purge`, and spread across the window rather than repeated on a short interval.
- **Generate from a workstation, never from the DC.** Requests made on HYDRA-DC itself carry
  `Client_Address = ::1`; the one from SPIDERMAN carries `::ffff:192.168.182.138`. An allowlist
  built from loopback traffic would describe the DC talking to itself. This is the same hazard
  `Purple - Telemetry Gap` already documents, where four of five result groups were the DC's own
  loopback Kerberos.

The SPN is `HYDRA-DC/SQLService.MARVEL.local:60111`. A verification request from
`MARVEL\pparker` on SPIDERMAN produced the target event — `4769`, `Service_Name=SQLService`,
`Account_Name=pparker@MARVEL.LOCAL`, `Ticket_Encryption_Type=0x12`,
`Client_Address=::ffff:192.168.182.138` — and, usefully, two machine-account requests
(`HYDRA-DC$`, `SPIDERMAN$`) that the rule's `Service_Name!="*$"` filter correctly excludes.

---

## Conventions this measurement reports under

**A zero means one of two different things and they must not be collapsed.** Either the rule had
the opportunity to fire on benign activity and did not, or nothing in the window exercised its
false-positive source at all. The second is not a clean rule but an **unmeasured** one — the same
distinction the coverage matrix draws with `M` and `→`. Each rule below therefore records whether
the window actually exercised what it keys on, and a rule whose source was never exercised does
not graduate to "threshold measured" on the strength of a zero.

**Each rule ends in one of four states.** The first three were defined in the v4 plan; the fourth
was added here, because execution found a case none of them covered:

| End state | Meaning |
| --------- | ------- |
| Scheduled, threshold measured | the window exercised this rule's false-positive source and the number holds |
| Scheduled, threshold lab-specific | calibrated here, but the window could not represent a real estate — carries a note saying what to re-measure |
| Unscheduled, source not producible here | the rule is sound but this environment does not generate its false-positive class at all, measured rather than assumed |
| Deleted | the rule is wrong, not merely uncalibrated |

## What this measurement cannot claim

A false-positive rate measured here is **not** one measured in production, for a specific reason
rather than as a disclaimer: three Windows hosts and five domain accounts generate a fraction of
a real estate's benign noise. `Purple - C2 Beacon` is the clearest case — its false positives
come from legitimate `AppData` egress, and with two users and almost no SaaS traffic an allowlist
derived from this window is **incomplete by construction**. The same holds for
`Purple - Large Outbound Transfer`, whose threshold reflects this segment and nothing else.

The window is 24 hours rather than the full week the 24 October plan called for. That gives
roughly 144 ten-minute windows per host, so a 99th percentile would sit one or two samples from
the maximum — a near-maximum, not a tail estimate. The outbound-transfer threshold is therefore
taken from the **95th** percentile with the sample count recorded beside it, and ships in the
"threshold lab-specific" state.

---

## Results

_Empty until the window closes._
