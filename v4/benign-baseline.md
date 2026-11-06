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
**Superseded twice. The measured window is 2026-11-02 18:40 CET to 2026-11-03 18:40 CET** —
see section 6. The intermediate restart read: **the window was restarted at 2026-11-02 17:45 CET (16:45 UTC) and closes
2026-11-03 17:45 CET.** See section 5 below.

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

### 5. Window restarted, 2 Nov 2026 17:45 CET

**The first window had two ~20-minute gaps, one on each workstation.** Bucketing the window by
host in ten-minute steps showed SPIDERMAN with no data from 16:19 to about 16:40, and THEPUNISHER
with none from about 16:50 to 17:10. The other hosts kept reporting through both gaps, so it was
not the hypervisor host going to sleep. Neither workstation logged a shutdown (`1074`, `6008`,
`41`) or a sleep (`42`/`107`) inside the window; both had slept earlier the same day, and both
were on the Windows 10 default of sleeping after 30 minutes idle (`STANDBYIDLE` AC = `0x708`).
The cause is therefore probable rather than proven: idle sleep, or the VM being paused, in a way
whose timestamps the guest's own clock does not show.

**Sleep was disabled on all three Windows hosts** (`standby-timeout` AC and DC = 0, hibernate
off) and continuity was then checked before restarting: every five-minute bucket from 17:10
carried data for all five reporting hosts — HYDRA-DC, SPIDERMAN, THEPUNISHER, security-vm and
wazuh-vm.

Restarting cost one hour of calendar time and buys a window with no gap to explain. It also
moves the setup noise out of the measurement: the `tstark` password reset (`4724`) and the
17:06:42 `tstark` request now fall **before** the window. The benign `tstark` requests are
therefore made again inside it, and the clean-window check and its `pparker` positive control
run against the new bounds:
`earliest="11/02/2026:17:45:00" latest="11/03/2026:17:45:00"`.

### 6. Measured overnight, 2–3 Nov 2026 — the window bound moves to 18:40

**The whole lab froze from about 18:05 to 18:40.** Bucketing by host showed no data at all for
18:10, 18:20 and 18:30 — on all five reporting hosts at once, and never backfilled. A gap on
every guest simultaneously is the hypervisor host, not a guest. The cause was most likely the host's own
power management, as with the workstation gaps: idle sleep and background throttling of
`vmware-vmx.exe`. Fixed on the host by the High performance plan, sleep and hibernate off,
and `powercfg /powerthrottling disable` for `vmware-vmx.exe`.

From 18:40 every ten-minute bucket carries data for all five hosts through to the next morning,
unattended. **The measured window is therefore 18:40 to 18:40.** The bound is set by host
continuity, which is visible before any false-positive count is computed, not by the counts.
`Kali` stays off until the new close.

Separately, the earlier delivery lag on THEPUNISHER (9 minutes, events arriving late but with
their original `_time`) differed from these gaps, which never filled. One was a slow pipeline,
the other a frozen guest; only the second removes data.

**`tstark` requests inside the window:** 21:22 from SPIDERMAN (`::ffff:192.168.182.138`), 10:48
from SPIDERMAN, 10:53 from THEPUNISHER (`::ffff:192.168.182.137`). Two hosts, spread across the
day. A share, `BenignShare`, was created on SPIDERMAN at 23:51 (`5142`), benign administration.

**The window ran without internet egress.** The guests route to the VMware NAT gateway
(`192.168.182.2`, reachable) but nothing beyond it answers; the host itself has internet and
no VPN. The condition did not change during the window: Sysmon `EventCode=3` to non-RFC1918
addresses runs at a steady 2–8 attempts per hour per workstation from 18:40 onward, with no
step. So it is recorded as a condition of this window, not repaired mid-measurement.

> **Corrected, 6 Nov 2026 — the cause here is wrong, and the conclusion drawn from it is too
> strong.** "Nothing beyond the gateway answers" was inferred from Sysmon `EventCode=3` counts,
> and `EventCode=3` records that a process *opened* a connection, not that anything replied. The
> shipped Sysmon config logs NetworkConnect only for processes under `C:\Users`, `C:\ProgramData`,
> `C:\Temp\` and a few similar paths, so those 130 events were never the total — they were the
> suspicious-path subset. Zeek, which does see replies, records **137 MB returned to SPIDERMAN
> from 173 external addresses** inside this same window, and 19.7 MB to THEPUNISHER from 168.
>
> The window therefore had internet, and the real fault is narrower: IPv6 is advertised without a
> route out and Windows prefers it, while UDP/53 from the Windows hosts is lossy. Full
> measurements are in [`README.md`](README.md), under the 6 Nov note.
>
> **What survives unchanged is the number.** Outbound was ~1 MB per workstation per day and the
> largest ten-minute bucket was 0.29 MB, which is a real property of a two-user lab rather than a
> consequence of connectivity. So the threshold conclusion below stands; only its stated cause
> was wrong, and a second window will not move it by much.

**`C2 Beacon` was exercised anyway, because the rule keys on the attempt, not the session.** Of
130 external connection attempts in the window, 126 are OneDrive from `AppData` on both
workstations, all to Microsoft addresses on 443:
`…\OneDrive\OneDrive.exe` (THEPUNISHER) and `…\OneDrive\<version>\OneDrive.Sync.Service.exe`
(both). **The version folder differs by host** — `26.195.1006.0007` on THEPUNISHER,
`26.189.0928.0009` on SPIDERMAN — which is the case the version-folder wildcard exists for. Every
benign attempt matches the pinned allowlist. The remaining four are `powershell.exe` to
`8.8.8.8:53`: the diagnostic DNS tests made during the window, from `System32`, which the rule
does not key on. With real internet there would be more processes (browser updaters, Teams),
so the rule's end state can be at most **scheduled, threshold lab-specific**.

**`Large Outbound Transfer` was exercised and could not see it.** A 100 MB file was copied
from THEPUNISHER to `\\SPIDERMAN\BenignShare`. Three findings came out of that one copy:

- **The transfer went over IPv6.** Both workstations register a ULA address
  (`fd15:4ba5:5a2b:1008::/64`, the VMware NAT IPv6 prefix) in DNS, and addressing the share by
  name made SMB prefer it. Zeek logged three parallel SMB connections (multichannel,
  `krb,gssapi,smb`) totalling 53.5 MB `orig_bytes` within seconds — five times the rule's
  10 MB threshold. The rule filters `match(orig_h,"^192\.168\.182\.")` and never sees it. That
  is not a calibration gap; the rule is blind to an address family.
- **Zeek missed about a third of the bytes.** The same three connections carry 26.9 MB of
  `missed_bytes`: packets the sensor did not capture under a burst. A byte threshold derived
  from Zeek counts therefore under-reads exactly the large transfers it is meant to catch.
- **The workstations' IPv6 source addresses rotate.** THEPUNISHER sent from `…:5cc0` at 11:26 and
  from `…:91d0` at 11:39 (temporary addresses). An IPv6-aware rule cannot pin a host by address
  the way the IPv4 rules do.

So this rule ends the window **unscheduled, blind to IPv6**: it has to cover IPv6 before it can
be calibrated, and its threshold has to be read alongside `missed_bytes`.

**Wazuh stopped producing alerts at 17:52 and nothing said so.** The wazuh-vm root filesystem
was 100% full: Vulnerability Detection's feed directories (`/var/ossec/queue/vd` 4.8 GB,
`/var/ossec/queue/vd_updater` 5.5 GB) had filled a 24 GB disk. All three agents stayed
`Active`, `wazuh-manager` reported `active`, and `alerts.json` stayed at zero bytes. At midnight
the rotation wrote `ossec-alerts-02.json.gz` as a zero-byte file, so the 2 November alerts after
17:52 are lost; those before it are in Splunk. Fixed at 11:05 on 3 November by disabling
Vulnerability Detection (`ossec.conf`, backed up as `ossec.conf.bak-vd`) and clearing its
directories (disk 100% → 59%); alerts reached Splunk again from 11:12.

No Splunk detection reads the `wazuh` sourcetype — only the two pipeline-health searches do —
so the false-positive measurement of the Splunk rules is unaffected. Wazuh's own rules have no
data for this window and are measured separately.

The heartbeat reported wazuh-vm healthy the whole time, which it was: the heartbeat proves the
host and the forwarder are up, not that the manager is writing alerts or that the disk has
room. The convention "an hour without `wazuh` is not a gap, an hour without
`wazuh:heartbeat` is" missed sixteen hours of a dead EDR because of exactly that difference.
The heartbeat needs to carry disk use and the growth of `alerts.json` before it can stand for
sensor health.

**The SIEM was deleting its own evidence.** Found on 3 November while re-checking three rule
fixes against the v3 run: the 20 October data the repo cites (the spray `Purple - Spray Success`
was measured against, and the JA4 beacon) is gone from Splunk. The cause is in `_internal`, not
in a snapshot: `main` was capped at `maxTotalDataSizeMB = 500`, every other index on the box was
on the 488 GB default, and no frozen path was set, so each time the index reached 500 MB Splunk
deleted its oldest buckets — reason logged as `maxTotalDataSize=524288000 bytes`. Six freezes
ran inside this window (2 Nov 18:51, 18:57, 19:00, 20:55, 23:28; 3 Nov 10:52), the last one
taking the bucket that held 20 October.

None of them touched the window: every frozen bucket's latest event is 23 October or earlier.
The cap was raised to 20 GB at 12:30 on 3 November (Splunk VM has 48 GB free), which stops the
deletion without changing any stored event. What it cannot do is bring back 20 October, so any
claim in this repo that rests on that day's data can no longer be re-run, only read. The 30
October re-run is intact and is what the three rule fixes were verified against.

---

## Results

Measured 3 Nov 2026, after the window closed, with the queries and controls fixed in advance in
[`benign-baseline-queries.md`](benign-baseline-queries.md). Window: 2 Nov 18:40 to 3 Nov 18:40
CET. Continuity: all 144 ten-minute intervals present, no host missing from any of them.

**Unit:** distinct result rows the search returns over the window, never firings.
**Control:** the count of the events each rule keys on, inside the same window. A zero only
counts as clean where the control is non-zero.

| # | Rule | Rows in window | Control in window | End state |
| - | ---- | -------------- | ----------------- | --------- |
| 1 | LOLBin Execution (CIM) | 0 | `Endpoint.Processes`: ~140k events, all 3 hosts | scheduled, threshold measured |
| 2 | C2 Beacon from User-Writable Path | 4 groups, all OneDrive → **0 with the pinned allowlist** | 126 OneDrive egress attempts | scheduled, threshold lab-specific |
| 3 | Kerberoasting RC4 | 0 | 71 × `4769`, all AES | scheduled, threshold measured |
| 4 | Kerberoasting User-SPN (etype-agnostic) | 2 groups, both `tstark`→`SQLService` → **0 with the allowlist** | the 3 generated `tstark` requests, nothing from `pparker`/`fcastle` | scheduled, allowlist lab-specific |
| 5 | Password Spray | 0 | 2 × `4771` (`Administrator`, mistyped password) | scheduled, threshold measured |
| 6 | Spray Success | 0 | 2 × `4771`, 26 × `4768` | scheduled, threshold measured |
| 7 | SAM Hive Dump via reg save | 0 | 29,939 × `4688` | scheduled, threshold measured |
| 8 | DCSync from non-DC | 0 | 778 × `4662` | scheduled, threshold measured — still never fired on a true positive |
| 9 | Scheduled Task Persistence | 0 | 1 × `4698` (benign) | scheduled, threshold measured |
| 10 | LSASS Access | **0** | **78,495** Sysmon EID 10 reads of `lsass.exe` | scheduled, threshold measured |
| 11 | Kerbrute User Enumeration | 0 | 26 × `4768` | scheduled, threshold measured |
| 12 | Verify Account Lockout | 0 | lockout policy already in force (see README) | schedulable now |
| 13 | RC4 Anomaly | 0 | 71 × `4769`, zero RC4 | schedulable after AES-only |
| 14 | Sliver C2 Beacon by JA4 | 0 | Zeek continuous across the window | scheduled, threshold measured |
| 15 | Large Outbound Transfer | **4 rows** | see below | **unscheduled** |

**The strongest number is rule 10:** zero alerts across 78,495 benign reads of LSASS in a day.
The exclusions were tuned on 935 sampled reads in v3; they held at eighty times that volume.

> **Qualified, 6 Nov 2026 — the number is right and the claim built on it was too strong.** The
> same rule run over seven days returns two benign rows this window could not contain:
> `C:\Windows\Sysmon64.exe` reading `lsass.exe` with `0x1FFFFF` on HYDRA-DC, on 30 and 31 October.
> Both follow a Sysmon service start on the DC by about a minute, and this window contains no
> Sysmon restart — so a 24-hour sample was structurally unable to see a false positive whose
> trigger is an administrative event. Zero across 78,495 reads remains exactly what was measured.
> What it supports is **"none in twenty-four hours"**, not "zero false positives", and the
> difference matters because the hardening bundles restart Sysmon and reboot the DC repeatedly.
> The full measurement, including why the exclusion is not being added yet, is in
> [the before-run section of the v4 README](README.md#before-run-detection-measurement-6-nov-2026--two-cells-closed-and-a-false-positive-source-the-benign-window-could-not-see).
> This is a limit of the window's length, not an error in the count — but it is the second time
> on this page that a one-day sample has been read as a general property, and that pattern is the
> finding.

**The one rule that fired is the exfiltration rule, and it fired on the monitoring.** All four
rows are telemetry: forwarders to Splunk on `9997` and Wazuh agents on `1514`. Three of them sit
in the 18:40 interval — the backlog flush when the lab came back from the host-wide freeze — and
the fourth is HYDRA-DC at 21:20, shipping the 32,878-event spike it logged then. Excluding
`.131:9997` and `.150:1514`, the largest egress any host produced in a ten-minute bucket was
0.29 MB against a 10 MB threshold. So the rule needs a telemetry exclusion, it needs to see IPv6
(section 6), and its threshold cannot be calibrated from a window with no internet and no IPv4
bulk transfer. It stays unscheduled until a second window with internet measures it.

**Throttling, measured in effect:** as the pack ran live during this window, with no
`alert.suppress`, the four rule-15 rows and the six allowlistable rows of rules 2 and 4 would
have re-alerted at every scheduled run for 24 hours. The throttle settings now in the repo fix
that once they are deployed.

**Two observations recorded for later work:** the CIM `Endpoint.Processes` model carries 78,706
events with `dest=unknown`, matching the Sysmon EID 10 volume, so Sysmon process-access events
are being mapped into the model without a host; and HYDRA-DC renders event times one hour ahead
of Splunk's `_time`, which matters for any cross-host timeline.

**Snapshot after the window:** the three Windows hosts were snapshotted as
`v4-post-benign - bez interneta` before the 3 Nov app deployment, which only touched the Splunk
VM. It is the rollback point for the before-run and the hardening work; the name records that
the guests had no internet egress when it was taken.
