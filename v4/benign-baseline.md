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

## Method revision, 2 Nov 2026 — two corrections made after the window opened

Both were found by review against the repo, before any result was computed. They are recorded
here rather than silently applied, because the method was committed first precisely so that
changes to it would be visible.

### 1. The Kerberos requestor must be `tstark`, not `pparker` or `fcastle`

The method as committed said to generate the benign `4769` from `MARVEL\pparker` on SPIDERMAN and
`MARVEL\fcastle` on THEPUNISHER. **Those are the attack's own credentials.**
`v2/02_attack_playbook.md` runs `impacket-GetUserSPNs MARVEL.LOCAL/fcastle:Password1 -request`,
and `v3/attack/README.md` records the roast as made "with the `pparker` credential".

An allowlist built on either principal would have suppressed the Kerberoasting detection in the
before-run and the after-run alike — the measurement `CASE-02` exists to make. The benign window
would have quietly disarmed the rule it was meant to calibrate.

`tstark` is the only enabled domain principal the attack never uses, so the benign requests come
from there:

```
runas /user:MARVEL\tstark cmd
klist purge
klist get HYDRA-DC/SQLService.MARVEL.local:60111
```

**And the allowlist keys on `Client_Address` as well as principal and SPN**, not on the principal
alone. A stolen credential used from another host should not inherit the allowance.

The one request made from `pparker` at 15:59:49 was a mechanism check taken **before** the window
opened at 16:19:07, so it falls outside the measured period. **Verified: zero `SQLService`
requests of any kind inside the window at the time the correction was made**, so nothing has to be
excluded and the allowlist starts clean. Had any arrived from `pparker` or `fcastle`, they would
have been set aside with the exclusion recorded rather than quietly dropped.

That zero covers only the first twenty minutes of the window, so it is re-checked twice before any
result is computed:

1. **Over the whole window, once it closes** — the same query bounded
   `earliest="11/02/2026:16:19:00" latest="11/03/2026:16:19:00"`.
2. **With a positive control, because a bare zero proves nothing.** The same query widened to
   `earliest="11/02/2026:15:50:00"` must return the `pparker` row from 15:59:49. If it does not,
   the zero was an artefact of the query — wrong field, wrong sourcetype, wrong bound — and not a
   fact about the window. This is the same discipline the Zeek filter check needed: there, two
   absent junk files meant nothing until a control file proved the forwarder was still scanning.

### 2. The C2 allowlist pins filenames; a folder wildcard would be a hole

The method called for `*\AppData\Local\Microsoft\OneDrive\*`, chosen to survive the version
number embedded in the path. It solves that and creates something worse: it trusts **anything** in
a directory the user can write to, so an implant dropped beside OneDrive would be allowlisted into
invisibility — by the very rule whose whole premise is that user-writable paths are suspicious.

The filenames are pinned and the wildcard is confined to the version folder:

```
*\AppData\Local\Microsoft\OneDrive\OneDrive.exe
*\AppData\Local\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe
*\AppData\Local\Microsoft\OneDrive\*\OneDrive.Sync.Service.exe
```

Version drift is still handled, and a new binary appearing in that folder alerts instead of
inheriting trust. If OneDrive later ships a fourth binary, the rule fires once and the allowlist
is extended deliberately — which is the correct failure direction.

### 3. How a false positive is counted — firings are not the unit

No search in the pack sets `alert.suppress`. The thirteen scheduled searches run eight every 10
minutes, four every 15, one every 5; the detection rules look back over `-24h@h`. A single benign event therefore satisfies its rule again at **every**
subsequent run for a full 24 hours — roughly 144 times for a 10-minute schedule.

So the false-positive rate is counted as **distinct events, or distinct result groups**, never as
firings. Counting firings would inflate every number by two orders of magnitude and make the
table meaningless.

The absence of any throttling is itself a finding about this pack, and belongs in the results
rather than in a footnote: as shipped, one benign event does not produce one alert, it produces a
day of them. Whatever the measured rates turn out to be, `alert.suppress` is a change every
scheduled rule here needs.

### 4. Measured during the window, 2 Nov 2026

**`tstark`'s password was unknown and was reset inside the window.** `v2/01_lab_setup.md` lists
it as unknown, and `runas` failed with `1326`. It was reset from HYDRA-DC by `Administrator`,
which writes one `4724` into the window: benign administrative activity, recorded here so it is
not mistaken for anything else. The new password is outside the spray's pattern, so the
before-run cannot recover `tstark` and turn the legitimate principal into a compromised one.

**The first benign request arrived as intended:** `4769`, `tstark@MARVEL.LOCAL`,
`Service_Name=SQLService`, `Client_Address=::ffff:192.168.182.138`, at 17:06:42. The same query
widened to 15:50 returned the `pparker` row from 15:59:49, so the query is proven to see these
events and the in-window zero before 17:06 is a real zero.

**Kali stayed off, with a control.** A search for `192.168.182.133` inside the window returns
nothing; the same search over the preceding seven days returns rows. Those rows are all
HYDRA-DC `EventCode=47` — its time service has `192.168.182.133` configured as a manual NTP peer
and logs that it is unreachable. So a mention of that address in a DC log is **not** evidence
that Kali is up; traffic sourced from it in `zeek` or `suricata` is.

---

## Results

_Empty until the window closes._
