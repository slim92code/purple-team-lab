# Lab v4 — Hardened Baseline and Alert Triage Case Files

> ## Status: predictions written 24 Oct 2026, build in progress
>
> The plan below was written before the work started and its predictions are left unchanged, so
> they stay auditable. **Nothing in the plan is a result.** What has been measured since is in
> dated sections, each carrying the date it was measured — those are results. The distinction
> between the two is the point of this page. Last updated 6 Nov 2026.
>
> | | |
> | --- | --- |
> | Written 24 Oct | scope, hardening baseline, firewall GPO design, logging change, residual-gap risk register |
> | Measured since | sensor persistence (30 Oct), CIM sourcetype fix rolled out and verified (31 Oct), pre-hardening baseline verified across all five feeds and snapshotted on all seven VMs, both logging gaps closed and verified — `wazuh-vm` heartbeat with an 18th search, and the Zeek bookkeeping-file ingest (2 Nov), the benign baseline over a full 24h window (3 Nov), the guests' internet fault root-caused (6 Nov), the before-run chain executed and measured into [`coverage-matrix.md`](coverage-matrix.md) — twelve Splunk cells, three N/E, two phases that have no Splunk rule, the Wazuh/Suricata/Zeek layers for five phases, and the week's alert history (6 Nov) — and step 5 complete: eight [case files](investigations/), two [hunts](hunts/) and the [incident report](incident-report.md) (7 Nov) |
> | Next | revert the three Windows endpoints to `v4-post-benign`, then hardening bundle by bundle |
> | Not yet done | the hardening bundles, the after-run, the after columns of the matrix, the honeypot rule, the second benign window with internet |
> | Completed labs | [v2](../v2/) and [v3](../v3/) |
>
> It is published first on purpose. v4's deliverable is a before/after detection-coverage
> matrix, and a before/after written afterwards proves nothing, so the predictions have to be
> on record first. The residual gaps below work the same way: committing to them in advance
> is what makes them a risk register instead of a list written around whatever got through.
>
> Structured to be read at three levels: **L1 triage** (`investigations/`), **L2 hunting and
> incident response** (`hunts/`, `incident-report.md`), and **detection engineering**
> (`coverage-matrix.md`, `detections/`), so a reader can enter at whichever level matches
> their role. The layer breakdown is in [Revision, 2 Nov 2026](#revision-2-nov-2026--three-readable-layers-and-the-build-sequence) at the end of this page.
>
> Repo entry point: [root README](../README.md).

v4 keeps the [v3](../v3/) five-layer detection stack and changes two things: the Windows
estate is hardened to a CIS-aligned baseline before the kill chain runs, and the
output is a set of alert-triage case files rather than an attack narrative.

## Why

v3 ran against a near-default Windows baseline, so no attack had to work through a control.
That makes the detections easy and the result unrepresentative. v4 applies a hardened
baseline first, then re-runs the same chain, so each phase either gets blocked by a
control, or gets through a gap that is documented and deliberate.

## Hardening baseline

Applied as five GPO bundles across one domain controller and two endpoints.

| Bundle | Contents |
| ------ | -------- |
| Audit policy | Advanced audit policy across all categories, process creation with command line, SACLs on AdminSDHolder / GPO / OU |
| Credential protection | `WDigest=0`, LSA Protection (`RunAsPPL`), NTLMv2-only, LM hash disabled, Protected Users group, anonymous SAM enumeration restricted |
| Network protocols | LLMNR / NBT-NS / mDNS / WPAD disabled, SMB signing required, SMBv1 removed, LDAP signing and channel binding; host firewall replaced by one GPO (see Firewall baseline) |
| Account and Kerberos | Account lockout, 14-character minimum with complexity and history, AES-only Kerberos, `ms-DS-MachineAccountQuota=0`, LAPS, gMSA for service accounts (one legacy account excepted — see residual gaps) |
| Execution controls | PowerShell script-block / module / transcription logging, Defender ASR rules, tamper protection, Print Spooler disabled on the DC |

Plus a honeypot service account with an SPN that is never legitimately used: any Kerberos
request for it is malicious by definition.

Each control is recorded with what it was before, what it is now, and which detection it
enables or which attack phase it blocks.

## Firewall baseline (GPO)

v3 blocked the attacker and east-west SMB with six per-host rules added by hand. Accurate
in effect, but inconsistent: the DC defaulted inbound to `Allow` while the endpoints were
`NotConfigured`, and only the DC blocked Kali on SMB (the endpoints blocked it on WMI only).
v4 replaces the six rules with one GPO, `MARVEL-Firewall-Baseline`, on all three hosts:

- **Default inbound = Block** on every profile — removes the DC's `Allow` gap.
- **Non-domain hosts denied inbound 445 / 135 everywhere.** The gate is domain membership,
  not an IP: Kali is blocked because it has no domain Kerberos ticket, so a new non-domain
  host is denied on its first connection instead of waiting for someone to add its address.
- **Static SMB/WMI block between the two workstations** (THEPUNISHER ↔ SPIDERMAN), kept even
  though both are domain-joined — deliberate workstation isolation.
- **WinRM (5985) left reachable east-west on purpose** — the monitored pivot the
  lateral-movement case needs (Zeek `conn.log`, Sigma rule 12). Prevention narrows the lateral
  path to the one lane the detection already watches.

**Caveat — this is a real project, not one switch.** The non-domain gate is Windows *domain
isolation*: IPsec Connection Security Rules authenticated with Kerberos, plus firewall rules
set to "allow the connection if it is secure." v4 documents the CSR configuration as part of
the baseline rather than pretending it is a checkbox.

> **Measured, 3 Nov 2026 — the v3 east-west SMB block holds on IPv4 only.** From THEPUNISHER,
> `Test-NetConnection 192.168.182.138 -Port 445` fails and the same test against SPIDERMAN's
> IPv6 address (`fd15:4ba5:5a2b:1008::/64`, the VMware NAT ULA prefix) succeeds. The per-host
> rules are scoped by a single IPv4 address (`Block-SPIDERMAN-SMB`, remote `192.168.182.138`,
> port 445), and both workstations also register an IPv6 address in DNS, so addressing a host by
> name reaches it over IPv6 past the block. It was found by accident: a 100 MB copy to
> `\\SPIDERMAN\…` succeeded while the same copy to `\\192.168.182.138\…` was refused. A block
> written per address covers that address and that address family; the GPO's default-inbound
> Block, with no rule admitting 445 on the workstations, covers every source. The re-test after
> hardening checks both paths — by IP and by name.

## Forwarder sourcetypes and CIM

Measured on the v3 lab, so this is a known defect rather than a planned nicety. Every
Windows channel ends up under a single `WinEventLog` sourcetype at search time, with the
channel name surviving only in `source`:

```
sourcetype = WinEventLog
source     = WinEventLog:Microsoft-Windows-Sysmon/Operational
```

**The cause is not the forwarder, which was the first guess and is wrong.** Diagnosed on 31
October: the forwarder's `inputs.conf` already assigns the per-channel sourcetype
(`WinEventLog:Microsoft-Windows-Sysmon/Operational`), and `splunk btool inputs list --debug`
on the host confirms that is the effective value it sends. What collapses it is on the
indexer: the Splunk Add-on for Windows ships
`Splunk_TA_windows/default/props.conf` with a `rename = WinEventLog` directive on every
`[WinEventLog:*]` stanza, so all Windows channels are renamed into one `WinEventLog`
sourcetype by design — that add-on does its own CIM work keyed on `source` rather than on a
per-channel sourcetype. The side effect is that `TA-microsoft-sysmon`, which maps Sysmon EID 3
into `Network_Traffic` and keys on its own Sysmon sourcetype, never sees the events as that
sourcetype. Two add-ons want the same data under two different sourcetypes, and the Windows
one wins. So `Network_Traffic.All_Traffic` holds 0 events while 444 Sysmon EID 3 events sit in
the index with no `app`, `src`, `dest` or `dest_port`. `Endpoint.Processes` is populated,
because that one the Windows add-on fills from `4688`. Acceleration is also off on both data
models, so the `tstats` detections are raw scans rather than the millisecond lookups the pack
describes.

v4 fixes it on the ingest path, and the fix is larger than it first looked:

- Switch the Sysmon input to `renderXml = 1` so it arrives as
  `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`, which escapes the Windows add-on's
  `rename` and reaches `TA-microsoft-sysmon` for CIM mapping.
- **This changes the on-the-wire `source` for Sysmon**, so any shipped search that filters on
  `source="WinEventLog:Microsoft-Windows-Sysmon/Operational"` has to be widened to match the
  new `XmlWinEventLog:…` form as well. Change one host first, verify both the CIM model and the
  existing searches, then roll out. (Measured scope below: it is one search, not the whole set
  the first draft of this paragraph assumed.)
- Acceleration enabled with the shipped `detections/splunk/cim-acceleration/datamodels.conf`.
- Re-run both `tstats` detections and record before and after, since "the data model is
  empty" and "the rule is wrong" look identical from the alert list.

### Canary on SPIDERMAN, 31 Oct 2026 — the fix is proven, and so is the regression

`renderXml = 1` was applied to the Sysmon input on one host and measured before rolling it
anywhere else. Every link in the chain was verified against the live index rather than
assumed:

- **It escapes the rename.** New Sysmon events arrive under `source` and `sourcetype`
  `XmlWinEventLog:…`, not the `WinEventLog` the Windows add-on collapses everything else to.
- **Fields still extract.** EID 10 events carry `SourceImage`, `TargetImage`, `GrantedAccess`
  and `CallTrace`; `EventCode` resolves. The XML format is not a loss of fields.
- **`Network_Traffic.All_Traffic` populates.** A deterministic EID 3 — a copy of PowerShell
  run from `C:\Temp` connecting to an internal host — appeared in the data model as
  `All_Traffic.app = C:\Temp\nettest.exe`. The C2-beacon CIM detection that held zero rows for
  all of v3 can now return one. That is the whole point of the change.

And the regression the canary existed to find:

- **The `source` changes from `WinEventLog:…` to `XmlWinEventLog:…`.** A search that filters on
  the old `source` stops matching the switched host. This is not a field problem — the fields
  are intact — only the `source` filter. Grepping the shipped app for the Sysmon source put the
  scope at exactly **one** search, `Purple - LSASS Access`, not the whole Windows set an earlier
  draft of this section guessed: the Security-channel rules are untouched, and the two CIM
  searches key on data models rather than `source`. That one filter is widened to
  `(source="WinEventLog:…" OR source="XmlWinEventLog:…")` so it covers historical and new events,
  and the `Purple - C2 Beacon` CIM search goes from unschedulable to enabled once
  `Network_Traffic` is populated.

The canary was reverted from its per-file `inputs.conf` backup so the lab stayed on one
consistent format while the search change was prepared.

### Rolled out and verified, 31 Oct 2026 — the CIM gap is closed

The full pass was done the same evening, in the order that leaves no blind window: the
`Purple - LSASS Access` source filter was widened to
`(source="WinEventLog:…" OR source="XmlWinEventLog:…")` and deployed first — a no-op against
the then-current classic data, confirmed by re-running it to the same 19 historical hits —
and only then was `renderXml = 1` applied to all three hosts.

Verified against the live index afterwards:

- All three hosts send Sysmon as `XmlWinEventLog:…`; the bare-`WinEventLog` Sysmon stream
  stopped at the restart, a clean cutover.
- `Purple - LSASS Access` catches both: the historical classic events and a freshly triggered
  XML-format EID 10 at `GrantedAccess 0x1f3fff` on SPIDERMAN, with `SourceImage`,
  `TargetImage` and `GrantedAccess` all intact in the XML format.
- `Network_Traffic.All_Traffic` populates — a OneDrive EID 3 from `C:\Users\…\AppData` mapped
  into the model — and the C2 beacon CIM search, dead for all of v3, runs against it without
  error.

What remains is calibration, not plumbing: the C2 beacon stays unscheduled until it has a
per-environment allowlist for the legitimate software that also beacons from `AppData`
(OneDrive, Teams, browsers), which is the same posture as the uncalibrated byte-volume
threshold rather than a new blocker. Data-model acceleration is still off; the searches use
`summariesonly=false`, so it is a performance item, not a correctness one. The forwarder
`inputs.conf` change is the one line `renderXml = 1` on the Sysmon input, applied on each host
and backed up to `inputs.conf.bak-cim` there.

The two detections that ran in the v3 lab without becoming shipped content, the JA4 C2
beacon and a large-outbound-transfer check, were written into the
[Splunk app](../detections/splunk/purple_lab) after the run rather than being deferred to
here, and the naming is settled on `Purple - …` across the app, the Sigma pack and the case
files. What was not done is the part that needs data.

`Purple - Large Outbound Transfer` ships **unscheduled** with a placeholder threshold of
10 MB per ten minutes. That number is a guess. Windows Update, OneDrive and ordinary browser
traffic will all cross it, so enabling it as written would bury a real exfil event in its own
false positives.

v4 measures the baseline first: `orig_bytes` per internal host per ten-minute window across a
full week of normal operation, the 95th and 99th percentiles of that distribution, and the
threshold set from the result with the measurement recorded next to it. Then the chain is
re-run and the alert is checked against a transfer that is known to be real.

Shipping an uncalibrated threshold as an enabled alert is the same failure as shipping a rule
that cannot fire, pointed the other way: one reports coverage and never speaks, the other
speaks constantly and means nothing. v3 produced an example of each.

## Logging improvement over v3

Zeek is switched to JSON output and ingested through the Splunk Add-on for Zeek, so fields
(`id.orig_h`, `request_type`, `client`, JA4, …) are extracted by the TA instead of parsed
positionally from `_raw`. v3 queries parse the raw TSV with `rex` to show log structure;
v4 queries run against TA-extracted fields, which is the production form and survives empty
or shifted columns.

> **Deferred, 2 Nov 2026.** This is not done in v4. By the criterion below it moves no
> matrix cell — it is pipeline robustness, not a measurement — and inserting a second
> canary-and-rollout exercise ahead of the first delivered artefact is the wrong trade. The
> **unnamed risk it leaves** is recorded instead: `Purple - Sliver C2 Beacon by JA4` (scheduled)
> and `Purple - Large Outbound Transfer` both extract Zeek fields with a **positional** `rex`
> over raw TSV, so a change in Zeek's column order or output format breaks them silently rather
> than loudly. They work today and the dependency is deliberate, but it is a dependency.

## Deliberate residual gaps

Real environments are hardened unevenly. These gaps are chosen, documented as a risk
register, and are what the kill chain works through:

| Gap | Why it is realistic | Attack phase it leaves viable |
| --- | ------------------- | ----------------------------- |
| One legacy service account stays human-managed with an SPN | Applications that cannot use gMSA are the most common real exception | Kerberoasting |
| Lockout enforced, but spray stays under the threshold | One password per account per window is what real spray does | Password spray |
| WinRM left reachable east-west between workstations | the deliberate, monitored pivot the lateral-movement detection watches | Lateral movement |
| Credential Guard on one endpoint, not both | Uneven rollout is the norm | LSASS access |
| PowerShell logging on, application allowlisting off | Extremely common combination | PowerShell execution |

> **Measured, 2 Nov 2026 — the Credential Guard row cannot be built as written, and the reason
> is the one the row itself gives.** Both Windows endpoints were checked before scoping the
> control: both run **Windows 10 Pro**, and Credential Guard ships only on Enterprise and
> Education, which settles it on its own. The firmware confirms it twice over — one host is UEFI
> with Secure Boot disabled and reports `AvailableSecurityProperties {4,5,6}`, the other is on
> legacy BIOS (`Confirm-SecureBootUEFI` → `0xC0000002`) and reports `{0}`. Neither exposes
> property `1` (hypervisor support) or `2` (Secure Boot), so VBS — which Credential Guard
> requires — is unavailable on both without an edition change and a firmware conversion.
>
> The row above stands unchanged, because this is evidence **for** it rather than against it:
> Pro editions and legacy firmware are precisely why Credential Guard is not rolled out evenly
> in real estates. What changes is which control produces the split. **`RunAsPPL` (LSA
> Protection) replaces it** — a registry and GPO setting that works on Pro and on BIOS, needing
> only a restart. `CASE-04` keeps the same design, one endpoint protected and one not, and the
> question it asks gets sharper: on the protected host, does the LSASS rule still see the
> attempt, or does the attack fail while the alert stays silent?

## Planned contents

None of the files below exist yet. This is the target structure, listed so the scope is
explicit.

> **Superseded, 2 Nov 2026.** This tree is the 24 October target and is left as written. Two of
> its files now exist, and the scope has since gained two artefacts. The current structure is in
> [Revision, 2 Nov 2026](#revision-2-nov-2026--three-readable-layers-and-the-build-sequence) at
> the end of this page.

```
v4/
├── README.md                      <- this page (the only file that exists)
├── infrastructure/
│   ├── topology.md
│   ├── hardening-baseline.md      <- before / after / why, per control
│   └── logging-config.md
├── investigations/                <- the deliverable
│   ├── CASE-01-password-spray.md
│   ├── CASE-02-kerberoasting.md
│   ├── CASE-03-lateral-movement.md
│   ├── CASE-04-lsass-false-positive.md
│   ├── CASE-05-persistence.md
│   └── CASE-06-c2-beaconing.md
├── coverage-matrix.md             <- before / after hardening, per phase
└── risk-register.md               <- the residual gaps above, with rationale
```

Each case file follows one format: what the alert showed, the questions asked, the queries
run, the finding, the verdict, and the tuning or remediation recommendation.

## Addendum — reconciled from the 30 Oct 2026 v3 re-run

Everything above was written on 24 October, before the work, and is left unchanged so the
predictions stay auditable. A full live re-run of the v3 chain on 30 October surfaced two
things that change how v4 must start, neither of which is a v4 result — they are corrections
to the starting state the plan assumed.

**The NDR sensor is not reliably up, and that is a prerequisite, not a detail.** Zeek on
`security-vm` had been dead since 24 October: its capture interface `ens37` comes up `DOWN`
after a reboot, so Zeek crashes on start with `pcap_activate: device is not up`, while
Suricata on another interface keeps the host looking healthy. v4 runs the kill chain twice,
before and after hardening, and a dead NDR sensor during either run makes the coverage matrix
worthless. So a **persistent `ens37` configuration is step zero of v4**, ahead of any
hardening, and the matrix build must verify all five sources are live at the start of each run
rather than assuming it. **Done and verified across a reboot on 30 Oct** — a netplan file for
the interface plus a systemd unit for Zeek autostart, both reboot-tested, written up in
[`infrastructure/logging-config.md`](infrastructure/logging-config.md). (The promiscuous part
turned out not to need configuring: netplan 0.106 rejects the key, and Zeek sets promiscuous
itself.) The `Purple - Telemetry Gap` search does not cover this gap — it is gated to Windows
hosts — so a cross-sensor liveness check that spans the Linux NDR hosts is added to v4's
logging work.

**The password-spray residual gap is sharper than "stays under the threshold."** The row above
is about the *attack* staying under the lockout threshold, which remains true. But the 30 Oct
re-run measured the *detection* side: this estate produces only four accounts that emit a
`4771` on a spray (`jsmith` is an unknown principal and emits none; `Guest` is now disabled and
emits none), and the rule needs five. So in v4 the spray case file's coverage cell is known in
advance: the attack is viable and the detection does **not** fire, not because hardening broke
it but because the lab is one account short of the threshold. That is recorded here so the
before/after matrix reports it as a measured estate limitation rather than a hardening effect.

## Revision, 2 Nov 2026 — three readable layers and the build sequence

A scope revision, written after the 31 October ingest work closed the CIM gap and the
pre-hardening baseline was captured. It changes how v4 is organised and adds two artefacts; it
does not revise any prediction above, which stay as written on 24 October.

The reason for the change: the plan above is a single flat scope, but the work it produces is
read by three different roles, and a reader could not tell which part was addressed to them.
v4 is therefore organised into three layers, each with its own artefacts.

### Build sequence

The artefacts have a dependency order, because two of them describe the same attack run and one
of them measures a change to it:

1. **The pre-hardening baseline is captured.** All five sources were verified live —
   `WinEventLog`, `XmlWinEventLog` (Sysmon), `zeek`, `suricata`, `wazuh`, each under 15 minutes
   stale — with `Network_Traffic` populated and 17 searches loaded / 12 scheduled. Snapshotted
   as `v4-pre-hardening` across all seven VMs. This is the clean "before" state, and it answers
   the Addendum's requirement that all five sources be verified at the start of a run rather
   than assumed.
2. **The two logging gaps are closed, before the benign window and not after it.** Both are
   listed under [Logging gaps](#logging-gaps-to-close-before-the-benign-window-step-2) below.
   The `wazuh-vm` one is the reason this is its own step rather than housekeeping: that host is
   the one sensor the cross-feed liveness rule cannot see, so if it goes dark at hour 20 of a
   48-hour window, nothing says so and the window has to be run again. This is the same
   argument the Addendum makes for `ens37` being step zero, applied to the next measurement.
   Snapshot afterwards as `v4-post-logging`.
3. **A benign baseline is measured — 24 to 48 hours with no attack.** The false-positive rate
   per rule, against normal activity. It comes before hardening because three of the five
   unscheduled searches are blocked on this measurement and nothing else. See
   [Benign baseline](#benign-baseline--the-measurement-that-comes-first).
   **Results are written into `benign-baseline.md` as they are measured, not at the end.** The
   repo lives outside the VMs and survives any rollback; the Splunk index does not. Snapshot
   afterwards as `v4-post-benign`, and that — not `v4-pre-hardening` — is the rollback target
   for the hardening work, because rolling back past the benign window would erase the
   measurement and cost another 48 hours. `v4-pre-hardening` stays as the deeper fallback.
4. **The full kill chain is run against the un-hardened estate. This is the "before" column.**
   The first draft of this sequence left it out, assuming the 30 October v3 re-run could serve
   as "before" — it cannot. That run predates the 31 October CIM fix, so `Purple - C2 Beacon`
   could not fire then (`Network_Traffic` held zero events) and can now; comparing it against a
   post-hardening run would credit hardening with a change the ingest fix made, the attribution
   error this page exists to avoid. So the before-run happens **here**: after the logging
   changes, to use the same pipeline as the "after" run, and after the benign window, so no
   implant beacons while false positives are counted.
   **Two consequences.** The Windows hosts now carry attack artefacts — the persistence task
   among them — and a scheduled task left in place would make `CASE-05` measure a pre-existing
   task rather than whether ASR blocks persistence. So the three Windows hosts are reverted to
   `v4-post-benign` before hardening begins. **Rollback scope is three hosts, never seven:**
   reverting Splunk or the sensors would erase the benign measurement and this run's own
   evidence. From the moment a measurement exists, the SIEM and the sensors are not rolled back.

   > **Measured, 9 Nov 2026 — reverting a guest while keeping the indexer has three side effects,
   > and one of them was already in the before-run column.** The revert was performed and the
   > estate measured immediately afterwards:
   >
   > | Host | Timezone | UTC offset vs DC after boot |
   > | ---- | -------- | --------------------------- |
   > | SPIDERMAN | `Central Europe Standard Time` | **−0.006 s** — fine |
   > | THEPUNISHER | `Central Europe Standard Time` | **+497,404 s = 5.76 days** |
   >
   > THEPUNISHER came up on the snapshot's clock and stayed there. Kerberos tolerates five
   > minutes, so for about an hour that host **could not authenticate to the domain at all**.
   > `w32tm /config /syncfromflags:domhier /update` then `/resync /force` brought it to +1.3 s.
   >
   > **The three side effects, in order of how long they stayed hidden.**
   >
   > **1. Kerberos skew errors.** A guest booting on a stale clock emits `KRB_AP_ERR_SKEW`
   > (`0x25`) until `w32time` converges. This is not hypothetical: the before-run recorded four
   > such errors from SPIDERMAN at 09:29 on 6 November, and the week's alert history shows
   > `Purple - Spray Success` **delivered an alert** on them at 09:40 — the false positive in
   > [`#6`](coverage-matrix.md) and [CASE-01](investigations/CASE-01-password-spray-undercount.md).
   > Its cause was recorded as "clock skew" without knowing where the skew came from. **It came
   > from this procedure.**
   >
   > **2. Backdated event injection.** The reverted guest's forwarder resumes with its old
   > `fishbucket` state and the host's stale clock, so it sends events that index today and claim
   > to be from the snapshot's date. Split by `_indextime`:
   >
   > | Indexed | `_time` claimed | Events |
   > | ------- | --------------- | ------ |
   > | 3 Nov | 3 Nov 19:00–23:00 | 40,534 — the original, legitimate |
   > | 6 Nov | 3 Nov 20:38–23:00 | 14 — the previous boot did this too |
   > | **9 Nov** | **3 Nov 20:42–20:48** | **1,986 — today's revert** |
   >
   > The 1,986 sit inside a range already indexed on 3 November, so they are duplicates, and any
   > count over a window containing 3 Nov 20:42–20:48 is inflated by them.
   >
   > **No cell in this repo is affected**, and that is luck rather than design: the benign window
   > closed at 18:40 on 3 November, two hours earlier, and every before-run measurement is on
   > 6 November. The next revert could land anywhere.
   >
   > **3. The mechanism is already documented in this pack, for a different reason.**
   > `Purple - Wazuh Sensor Health` and its two siblings key on `_indextime` rather than `_time`
   > precisely because *"a forwarder restart backfills with original timestamps and erases a
   > `_time` gap retroactively."* Same mechanism. The health rules were written to survive it;
   > the revert procedure was not written to avoid causing it.
   >
   > **So the procedure gains a step, and it is not optional for the per-bundle reverts.** Before
   > reverting a Windows guest: stop its forwarder. After boot: resync the clock, verify the
   > offset against the DC, *then* start the forwarder. Done in that order there is no skew window
   > and no backdated batch. Done as it was today, every bundle rollback reproduces all three
   > effects — and the plan calls for a snapshot per bundle plus a rollback on any bundle that
   > corrupts the baseline, so this would have happened five more times.
   >
   > One finding travels with it. `#6`'s false positive is not an estate quirk to be tuned away,
   > it is **an artefact of this lab's own methodology**, and it will appear in every after-run
   > column produced by a revert until the procedure above is followed. That reframes the owed
   > fix: excluding `0x25` from the rule would hide a signal the lab itself generates, which is a
   > worse outcome than the false positive.
5. **The IR report and the hunts are written against that before-run.** They describe and
   interrogate the chain as it fires against the un-hardened baseline, so the "before" story is
   on record before anything changes. Neither waits on hardening.
6. **Hardening is applied afterwards, bundle by bundle** — the controls that survive the
   criterion below, not the full CIS sweep, and not all at once. Each bundle is followed by a
   snapshot, a **targeted re-run of only the kill-chain phases that bundle plausibly affects**,
   and one column in `coverage-matrix.md`: what still fires, what the bundle blocked for the
   attacker, and what it broke for detection. A bundle that corrupts the baseline is rolled
   back to `v4-post-benign`. The honeypot account and
   [the rule that watches it](#the-honeypot-needs-a-rule-or-it-is-just-an-account) are created
   in this step, together.
7. **One full kill-chain re-run at the end**, with the hardening in place — the pair to the before-run at step 4. That is the clean
   "after" state, and it is the column the before/after comparison actually rests on.

8. **A second benign window, with internet.** The first was measured with no outbound egress
   from the guests, which is why `Purple - Large Outbound Transfer` ships with an uncalibrated
   placeholder and `Purple - C2 Beacon`'s allowlist rests on two OneDrive binaries. This window
   calibrates both against real egress — Windows Update, OneDrive, browser traffic — and moves
   them from "threshold lab-specific" to measured. **The root cause was found on 6 November
   and is not the NAT** — see the dated note below. Step 8 now begins with that fix rather than
   with a diagnosis.

Snapshot order: `v4-pre-hardening` (done) → `v4-post-logging` → `v4-post-benign` → one per bundle.

> **Measured, 6 Nov 2026 — why the guests cannot browse, and why two earlier descriptions of it
> were both wrong.** This page and the benign baseline recorded the condition as "no internet",
> and a check on 2 November recorded the opposite, "they have internet". Neither holds. The
> measurements:
>
> | From | Query | Result |
> | ---- | ----- | ------ |
> | Kali (Linux, same segment) | `dig @192.168.182.2` and `@8.8.8.8`, UDP | answers in 11 ms and 47 ms |
> | Windows ×3 | `Resolve-DnsName -Type A @192.168.182.2`, UDP | times out on all three |
> | Windows | `Resolve-DnsName @8.8.8.8 -TcpOnly` | returns A **and** AAAA |
> | Windows ×3 | `curl -6 https://www.google.com` | fails on all three; hung **133 s** on THEPUNISHER |
> | Windows ×3 | `curl -4 https://www.google.com` | `200` in 0.5 s (THEPUNISHER), `200` in 17 s (HYDRA-DC), fails (SPIDERMAN) |
>
> **Two faults overlap.** The VMware NAT advertises an IPv6 ULA prefix with no route out — every
> IPv6 flow in Zeek carries `resp_bytes = 0` — and Windows prefers IPv6 by default, so a browser
> resolves `AAAA`, tries it, and hangs for up to two minutes before anything else happens.
> Separately, UDP/53 from the Windows hosts is lossy rather than blocked: `nslookup` answered
> after four two-second timeouts, and the same query from Linux on the same segment answers in
> 11 ms. Outbound firewall rules were ruled out — there are none enabled on any of the three.
>
> **So the honest description is neither of the two that were recorded.** Transport to the
> internet works over IPv4; name resolution and browsing do not. That is why ICMP, a TCP connect
> and 137 MB of service traffic could all be true at once while Edge showed nothing, and it is
> why the condition looked intermittent — it is.
>
> **Conditions were not uniform across hosts during the before-run.** In one minute of testing,
> THEPUNISHER fetched a page over IPv4 in half a second, HYDRA-DC took seventeen, and SPIDERMAN
> could not at all. Any before-run cell that depends on external egress carries that unevenness.
>
> **Deliberately not repaired yet.** Fixing it mid-measurement would change the estate between
> the before and after columns, so it is left as a measured condition of the before-run and
> becomes the first action of step 8. The order there is IPv6 priority first, since the Windows
> DNS client queries `A` and `AAAA` together and some of the UDP timeouts are likely that same
> dead path; the UDP/53 loss is re-measured afterwards rather than assumed to be separate.
>
> One state change did happen on 6 Nov, after phases 1–4 and 11–12 were measured:
> `Clear-DnsServerCache -Force` was run on HYDRA-DC, so names that had been resolving from its
> cache now go through the failing forwarder path. The already-measured phases are unaffected;
> the remaining ones run in a slightly worse state than the earlier ones did.

**The two axes, and where they touch.** Steps 4–7 run the hardening axis: before → bundles →
after, measuring verdicts and coverage. Step 8 runs the internet axis, which calibrates
thresholds. They are mostly independent — hardening does not move a threshold — but they are
**not fully independent**, and the exception is worth naming rather than discovering. A
volume-based verdict sitting near its own threshold couples them: the firewall GPO's cell rests
on `Purple - Large Outbound Transfer` at a placeholder threshold that step 8 may move past the
transfer it is meant to catch. That cell is therefore recorded under the Phase A threshold and
annotated with the risk, which keeps step 8 free to run before or after the hardening work.

### Before-run detection measurement, 6 Nov 2026 — two cells closed, and a false-positive source the benign window could not see

The before-run at step 4 was executed on 6 November. Two cells were closed afterwards from the
blue side; what follows is the measurement, not the chain.

**The JA4 C2 rule fires on one endpoint and is silent on the other, and the threshold is why.**
The fingerprint hard-coded in `Purple - Sliver C2 Beacon by JA4 Fingerprint` matches the one this
run produced exactly — `t13i131000_f57a46bbacb6_e5728521abd4`, no drift from v3. Twelve TLS
handshakes carry it, every one of them to the Sliver host at `192.168.182.133` and nothing else:

| Host | Handshakes | Window | Mean interval | Jitter | Rule |
| ---- | ---------- | ------ | ------------- | ------ | ---- |
| SPIDERMAN (`.138`) | 11 | 12:04:15–12:09:15 | 30.0 s | 23.9 s | fires |
| THEPUNISHER (`.137`) | 1 | — | n/a | n/a | silent |

`where count > 5` separates them, and it is right to: one handshake has no interval, so there is
nothing to call beaconing. The distinction worth recording is that **the evidence covers both
endpoints while the alert covers one.** The v3 finding that a single JA4 links both hosts still
holds — it is visible in the fingerprint and invisible in the alert. Read off the alert alone,
half of it is lost. The fingerprint is the pivot; the rule is a threshold sitting on top of it,
and the two answer different questions.

**`ja4` is not a field in this pipeline.** This Zeek build ships `ja4d.log` (DHCP, 1,640 events)
and `ja4ssh.log` (SSH, 69) but no `ja4.log`; the TLS fingerprint is appended as a column to
`ssl.log`, and the forwarder delivers Zeek's TSV, so Splunk extracts no `ja4` field at all. The
shipped rule works because it matches the fingerprint as a bare string in `_raw` — that is why it
is written that way rather than as a field comparison. Any search that wants to *group* by
fingerprint needs a `rex` first, which is how the table above was produced. The move to JSON
through the Splunk Add-on for Zeek, already noted in `savedsearches.conf`, is what retires that.

**LSASS access: the rule caught the dump, and the beacon was not the caller.** `SharpKatz` ran
through Sliver's `execute-assembly`, which executes in a sacrificial process, so the beacon path
`C:\Temp\GlobalProtect_Update.exe` never appears as `SourceImage`. Searching for it returns
nothing, and a cell written from that search would have read as a miss when the rule had in fact
fired. What fired:

| Time | Host | SourceImage | GrantedAccess |
| ---- | ---- | ----------- | ------------- |
| 6 Nov 17:06:07 | THEPUNISHER | `notepad.exe` | `0x1f3fff` |

One event. The paired `0x1410` read 294 ms earlier is below the rule's mask list and correctly
does not fire. **`Purple - LSASS Access` = M, detects.**

**Running the rule over a week turned up a false positive the benign baseline could not have
seen.** Over seven days it returns four rows, not one:

| Time | Host | SourceImage | GrantedAccess | Verdict |
| ---- | ---- | ----------- | ------------- | ------- |
| 30 Oct 22:59:43 | HYDRA-DC | `C:\Windows\Sysmon64.exe` | `0x1FFFFF` | benign — Sysmon itself |
| 31 Oct 19:20:12 | HYDRA-DC | `C:\Windows\Sysmon64.exe` | `0x1FFFFF` | benign — Sysmon itself |
| 31 Oct 20:52:56 | SPIDERMAN | `powershell.exe` | `0x1f3fff` | pre-dates the before-run |
| 6 Nov 17:06:07 | THEPUNISHER | `notepad.exe` | `0x1f3fff` | true positive |

`Sysmon64.exe` is not in the exclusion list, and it reads LSASS on the DC with the widest mask
there is. Both occurrences follow a Sysmon service start on HYDRA-DC by about a minute:

| HYDRA-DC Sysmon `Started` (EID 4) | LSASS read follows | Delay |
| --------------------------------- | ------------------ | ----- |
| 30 Oct 22:58:42 | yes, 22:59:43 | +61 s |
| 31 Oct 19:18:56 | yes, 19:20:12 | +76 s |
| 6 Nov 09:50:46 | no | — |

Seven starts were logged in the window; the four on SPIDERMAN and THEPUNISHER produced nothing,
so this is DC-only. **The mechanism is not pinned down.** Two of three DC starts produced a read
and the third did not, and the shipped
[Sysmon config](../config/sysmonconfig.xml) cannot be the reason — its `ProcessAccess` is an
`include` on `TargetImage` alone, with no `SourceImage` filter, so the new config logs
`Sysmon64.exe` exactly as the old one did. Correlated with a DC Sysmon start, not caused by one
as far as this measurement can say.

**What this does to the benign baseline's claim.** [The baseline](benign-baseline.md) recorded
this rule as clean across 78,495 `EventCode=10` reads, and that is still true *of its window* —
2 Nov 18:40 to 3 Nov 18:40 — which is exactly the problem. That window contains no Sysmon
restart, and every occurrence of this false positive tracks one. A 24-hour sample cannot see a
reader that only appears around an administrative event it does not
contain. The measurement was honest and the number is right; the sentence
it supports is "none in twenty-four hours", not "zero false positives", and those are different
claims. The before/after comparison depends on the difference, because **the hardening bundles
will restart Sysmon and reboot the DC repeatedly** — so this row can reappear in the after-run
column, where reading it as credential theft would be a false attribution of exactly the kind
this page exists to prevent.

The fix is held rather than applied: adding `Sysmon64.exe` to the exclusion list now would change
the rule between the before and after columns. It goes in with the step 8 recalibration,
alongside the `Large Outbound` threshold, and the after-run is read with this row known.

The 31 Oct `powershell.exe` event is **not** a before-run artefact — it falls six days earlier,
on the same evening as the rollout and canary work, and **it is unexplained.** `0x1f3fff` from
PowerShell is not something to wave through, and nothing measured here says which it was: a test
trigger from that evening's verification, or a real read nobody chased. It is listed rather than
dropped so that anyone re-running this rule over a week-long window neither credits it to the
chain nor assumes it was accounted for. Resolving it needs the `CallTrace` and the parent process
from the raw event, which is a hunt for `hunts/` rather than a cell in this matrix.

**A second-order finding: most of the exclusion list does no work.** Cross-reading the nine
`SourceImage!=` exclusions against the masks those processes were observed using since the
31 October cutover, only three can ever reach the rule's mask list at all:

| Exclusion | Masks observed | Reaches the mask list? |
| --------- | -------------- | ---------------------- |
| `wininit.exe` | `0x1000000`, `0x1fffff` | yes — load-bearing |
| `csrss.exe` | `0x1fffff` | yes — load-bearing |
| `wazuh-agent.exe` | `0x1000`, `0x1410`, `0x1fffff` | yes — load-bearing |
| `svchost.exe` | `0x1000`, `0x3000`, `0x100000`, `0x101000` | no |
| `taskmgr.exe` | `0x1000`, `0x1400`, `0x1410` | no |
| `WmiPrvSE.exe` | `0x1000`, `0x1400`, `0x1410` | no |
| `MsMpEng.exe` | `0x1000`, `0x1010`, `0x1400`, `0x1410`, `0x1418`, `0x101000`, `0x3600` | no |
| `vmtoolsd.exe` | `0x1000`, `0x1400`, `0x1410` | no |
| `MRT.exe` | never observed | untested |

The list was tuned against a draft that did not filter on `GrantedAccess`; once the mask filter
went in, five entries stopped mattering and one was never exercised, while the one process that
demonstrably needs excluding is absent. **This is an inference from one week of observed
behaviour, not a proof.** `svchost.exe` is entitled to open LSASS with a wider mask than it
happened to use here, so the redundant entries are cheap insurance and are not being deleted —
the actionable half of this finding is the missing entry, not the surplus ones.

**Phases 3 and 9b were not executed, and are N/E in both columns rather than silent.** The
decision rule stands: a phase runs in the before-run only if a shipped rule measures it *and* the
after-run will run it too. Dropping them from one column alone would make the comparison
asymmetric, so they are dropped from both. `Purple - SAM Hive Dump` and the LOLBin branch carry
no verdict in v4 — unmeasured, with the reason named, which is not the same as untested.

### Revised, 7 Nov 2026 — what the before column changed about three of the five bundles

The predictions in [the controls table](#which-hardening-controls-stay-and-the-rule-that-decides-it)
were written on 24 October against rules nobody had measured. The before-run measured them, and
three bundles now have a prediction that is wrong, incomplete, or testable in advance. Recorded
here **before** the bundles run, because discovering it mid-run would leave the comparison unable
to say whether a cell moved for the reason claimed.

**Bundle 4, Account and Kerberos — the AES prediction tests a rule that cannot see the
condition.** The table says `Purple - RC4 Anomaly (post AES enforcement)` *"goes schedulable and
returns only the legacy `SQLService` tickets"*.
[CASE-03](investigations/CASE-03-rc4-wrong-message-type.md) measured why that cannot happen: the
rule reads `EventCode=4769`, and this estate's RC4 arrives in `4768` — two tickets on the attack
path, one of them eleven milliseconds before the alert that did fire. **Enforcing AES changes
nothing this rule can observe**, before or after, so a `✗ silent → ✗ silent` row would read as a
detection failure and prove nothing.

Two consequences for this bundle:

1. The rule has to carry `4768` before its post-enforcement test means anything. That fix is
   owed and held; **it must land before this bundle, not after**, or the bundle's own column is
   uninterpretable.
2. The bundle gains a prediction it did not have, and a better one: **AES enforcement should
   break Pass-the-Ticket outright.** `Rubeus asktgt` presenting an RC4 key to a KDC that enforces
   AES has nothing to negotiate. So phase 6 has two questions in the after-run rather than zero —
   does a rule catch the attempt, and does the attempt still work. A phase with no coverage at all
   becomes the bundle's clearest measurement.

**Bundle 2, Credential protection — the `RunAsPPL` risk is now measurable in advance.** The table
already names it: the attack fails on the protected host, and *"the risk is that it also goes
silent, because the `GrantedAccess` a PPL-denied open returns may not be in the rule's measured
mask list."* That was the right worry and it was unquantified.

The mask list is now known exactly — `0x1438`, `0x143a`, `0x1f0fff`, `0x1f1fff`, `0x1f2fff`,
`0x1f3fff`, `0x1fffff` — and so is the full distribution of masks this estate's benign processes
produce, from [the `#10` cell](coverage-matrix.md). So the test does not have to wait for the
bundle's re-run: **apply `RunAsPPL` on the one endpoint, attempt the LSASS open, and read the
`GrantedAccess` directly.** If it is outside the list, the silence is predicted rather than
discovered, and the cell can be marked as *attack blocked, detection blind* instead of as a
regression.

**Bundle 3, Network protocols — "the rule goes silent" is wrong.** The table predicts the firewall
GPO's default-inbound Block kills the IPv6 SMB copy, so
`Purple - Large Outbound Transfer` *"goes silent"*.
[CASE-06](investigations/CASE-06-exfil-uncalibrated-threshold.md) measured that the rule also
fires on 12.5 MB of ordinary Microsoft HTTPS, which the GPO does not touch — it blocks inbound,
and this is outbound to a Microsoft address.

So the honest prediction is **the rule stops returning the exfiltration rows and keeps returning
the benign one.** The cell reads `fires → fires`, with different contents, and a reader comparing
only the verdicts would conclude the bundle did nothing. The cell has to record *what* fired, not
just whether something did — which is a change to how this one is written down, not to the bundle.

**Bundles 1 and 5 stand as written.** Audit policy improves event completeness and moves no
verdict, and no ASR rule targets scheduled-task creation, so the persistence cell is unchanged
unless the prevalence rule blocks the payload. PowerShell script-block logging arrives as a second
source on the `\Updater` cradle, corroborating `#9` rather than replacing it, exactly as predicted.

**One ordering consequence, which is the practical output of this section.** The general rule in
this build sequence is that no rule changes between the before and after columns. Bundle 4 is the
exception and it has to be stated as one: `#13` needs `4768` before AES enforcement is applied, or
that bundle measures nothing. Every other owed fix still waits for step 8.

### Why the per-bundle runs are targeted, and what that costs

Targeted runs per bundle plus one full run at the end produce the same final comparison as five
full runs, and still attribute which bundle moved which cell. Two costs, recorded here rather
than discovered later:

**Un-run cells are unmeasured, not unchanged.** A phase not re-run after a bundle has a cell
that is not evidence the bundle left it alone — it is simply not measured. Two marks:

| Mark | Meaning |
| ---- | ------- |
| **M** | Measured — the phase was re-run after this bundle and the result recorded |
| **→** | Not re-measured; the value is carried forward from the previous column |

Every cell in the final full-run column is measured; a phase no bundle touches reads
`→ → → → →  M`. Without this distinction the matrix would claim more than was measured, which
for a before/after artefact is the one failure that voids it.

**Targeted runs miss cross-bundle regressions.** The most interesting result in work like this
is a bundle breaking a detection it has no obvious relationship to — SMB signing or NTLMv2-only
changing what Zeek can parse, or an ASR rule suppressing a process-creation event a rule keys
on. A targeted run does not look there, so it will not see it. The final full run does catch it,
but without attribution: the regression shows up against the baseline and has to be bisected
back to its bundle by re-running candidates. That is an accepted cost of the cheaper scheme, not
an oversight.

The coverage matrix is the only artefact that spans before and after, and it is built
incrementally rather than written at the end.

### Which hardening controls stay, and the rule that decides it

The five bundles above were scoped by what a CIS-aligned baseline contains — the right way to
describe a baseline, the wrong way to decide what this lab spends time on, because the
residual-gap register is built so that every kill-chain phase stays viable. The effect here
lands on **telemetry**, not on whether the attack succeeds, so a control earns its place only
if it changes what a detection sees.

**The criterion: a control stays if a rule can be named whose before/after cell it moves.**

Naming the rule is not enough on its own — the page's own standard is that predictions go on
record before the measurement, so each retained control also carries the direction it is
predicted to move. Writing that column is what exposed the lockout row below.

| Control | Rule whose cell it moves | Predicted outcome | Stays |
| ------- | ------------------------ | ----------------- | ----- |
| Advanced audit policy | all of them — it generates the events the rules key on | no rule changes verdict; event completeness improves and SACL telemetry becomes available with no rule yet keyed on it | yes |
| AES-only Kerberos | `Purple - RC4 Anomaly (post AES enforcement)` and Sigma rule 2 | RC4 Anomaly goes schedulable and returns only the legacy `SQLService` tickets; rule 2's verdict is unchanged, its zero-FP property becomes enforced | yes |
| Account lockout / FGPP † | `Purple - Verify Account Lockout (post FGPP)` | **does not fire** under the spray the register specifies — see below | yes † |
| `RunAsPPL` split (one endpoint, not both) | the LSASS access rules — `CASE-04` | attack fails on the protected host; the **risk is that it also goes silent**, because the `GrantedAccess` a PPL-denied open returns may not be in the rule's measured mask list | yes |
| PowerShell script-block / module logging | the PowerShell execution rules | existing rules unchanged — they key on `4688` and Sysmon; `4104` arrives as a second corroborating source | yes |
| Defender ASR rules | the persistence cell | **unchanged unless the prevalence rule blocks the payload** — no ASR rule targets scheduled-task creation | yes |
| `ms-DS-MachineAccountQuota=0` | none — kept only because it is one setting | — | no cell |
| Firewall GPO (`MARVEL-Firewall-Baseline`) | `Purple - Large Outbound Transfer` | the IPv6 SMB copy succeeds today and the rule returns it at the placeholder threshold; the GPO's default-inbound Block covers every address family, so the copy fails and the rule goes silent — **but see the threshold risk below** | yes |
| LLMNR / NBT-NS / mDNS / WPAD disabled | none — no Responder step in this chain, no rule for it | — | dropped |
| LDAP signing and channel binding | none | — | dropped |
| SMB signing required, SMBv1 removed | none | — | dropped |
| IPsec domain isolation (Connection Security Rules) | none — prevention only | — | dropped |
| LAPS | none — local-admin reuse is not a path this chain takes | — | dropped |
| gMSA for service accounts | none — the legacy SPN account is a documented exception anyway | — | dropped |

† **The lockout row is not a v4 change at all**, which is a different thing from moving no
cell. The `Strong-Users` fine-grained policy has been in force since 4 June 2026; the row and its
prediction are left as written because the correction below is what the prediction column exists
to produce. See [the dated note](#deliberate-residual-gaps).

One "no cell" entry remains and is labelled rather than quietly counted: `MachineAccountQuota=0`,
kept because it is one setting and leaving a known privilege-escalation path open to save thirty
seconds would be silly.

**The firewall GPO moved out of "no cell" on 5 Nov 2026**, on evidence the benign window produced
by accident. Its reason used to read "the lateral path is deliberately unchanged" — the IPv6
finding disproves that. A 100 MB copy from THEPUNISHER to `\\SPIDERMAN\BenignShare` resolved
over IPv6 and went through, while the same copy by IPv4 address was refused: the v3 rules are
scoped to single IPv4 addresses. Zeek logged it, and `Purple - Large Outbound Transfer` now
matches IPv6 sources while its `resp_h` exclusion is IPv4-only, so SPIDERMAN's IPv6 address is not
excluded and the rule returns the row. The v4 GPO's default-inbound Block is not scoped to an
address or a family, so it closes the path the per-address rules missed. Inbound enforcement and
egress observation sit on the same flow, so there is no direction mismatch: block the connection
and the bytes never accumulate.

**The risk this cell carries, stated beside it.** The threshold is still the uncalibrated 10 MB
placeholder, and two effects push the same way:

- **Phase B may calibrate it above this transfer.** Real Windows Update or OneDrive traffic can
  put hundreds of megabytes into a ten-minute bucket. If the measured threshold lands above
  53.5 MB, volume detection misses this exfil whatever the GPO does, and the cell flips for a
  reason that has nothing to do with hardening.
- **Zeek under-reads these bursts by about a third.** The same copy carried 26.9 MB of
  `missed_bytes` against 53.5 MB counted — 80.4 MB observed of a 100 MB file. A threshold
  calibrated from Zeek counts and applied to Zeek counts is internally consistent, but its
  effective real-world trigger point is roughly **1.9× its nominal value**: 10 MB nominal needs
  about 19 MB of actual traffic.

The cell is recorded under the Phase A placeholder threshold and carries both caveats. The rule
is also still `enableSched = 0`; that does not empty the cell, because every measurement in this
lab is made by re-running the search over the window rather than by reading alert history — the
benign baseline was measured exactly that way. So the with-internet window is **not** a
prerequisite for this cell and the ordering stays free.

**Attribution is settled before the run, not during it.** The workstations' IPv6 source addresses
rotate — THEPUNISHER sent from `…:5cc0` and thirteen minutes later from `…:91d0`, both temporary
addresses — so the transfer cannot be tied to a host by address the way the IPv4 rules do. The
before-run and after-run both attribute by the `fd15:4ba5:5a2b:1008::/64` prefix plus correlation
with the host's `4624`/`5140` on the Windows side, and the same method is used in both columns.

**The lockout row needs its own correction, and it is the reason the prediction column exists.**
An earlier version of this table justified keeping lockout by naming
`Purple - Verify Account Lockout (post FGPP)` as the rule whose cell it moves. That checked only
that the rule exists, not that it would fire. The search is `EventCode=4740` — *account was
locked out* — and the residual-gap register above commits to a spray that "stays under the
threshold." Under that spray no account locks, no `4740` is written, and the cell reads
unchanged both before and after. Naming a rule is not the same as moving its cell.

The fix turns it into a measurement rather than dropping it: the **after-run adds a deliberate
spray burst that crosses the threshold**, on one account, alongside the under-threshold spray
the register specifies. Then the register's claim is measured instead of asserted — at N−1
attempts the spray is invisible and at N the account locks and `4740` fires — and the matrix
carries the boundary rather than a blank. The under-threshold case stays exactly as predicted:
viable and undetected.

> **Measured, 2 Nov 2026 — the lockout is already in force, so it is not a hardening change.**
> A fine-grained password policy, `Strong-Users`, has existed since 4 June 2026 (v2 era) and
> applies to `Domain Users`: minimum length 14, lockout after 5 failures in 30 minutes for 30
> minutes, maximum password age 42 days. So the over-threshold burst would lock the account and
> write `4740` in the **before**-run too. The lockout cell does not move between the columns,
> `Purple - Verify Account Lockout (post FGPP)` is mis-described as "absent pre-hardening", and
> the register's "lockout enforced" row is the current state rather than a planned one. The
> burst stays in both runs, as a measured boundary, not as a hardening effect.
>
> The 42-day maximum age was checked against every account the chain depends on: `SQLService`,
> `pparker` and `fcastle` all have `PasswordNeverExpires`, so no attack step can fail on an
> expired password mid-v4.

The dropped controls are all prevention whose effect no shipped rule measures. They are correct
hardening in a real estate; here they would cost the most, carry the most risk, and change
nothing that can be shown. This cuts the hardening work from roughly 10–14 hours to about 6
without giving up a cell.

**AES-only does not make Sigma rule 2 an anomaly detector — it already is one.** Over 30 days
this domain issued 1,649 service tickets, every one of them `0x12` (AES-256), and zero RC4, so
the rule fires on nothing benign today. What AES-only changes is narrower:

- **Prevention:** an explicit RC4 downgrade currently succeeds — the v3 Pass-the-Ticket step
  obtained a `4768` TGT at `0x17`. Under AES-only it is refused everywhere except the legacy
  account.
- **Detection:** rule 2's zero-false-positive property moves from accidental to enforced. Today
  nothing happens to use RC4; afterwards policy forbids it. A baseline can drift, a policy
  cannot.
- **And one rule becomes schedulable at all:** `Purple - RC4 Anomaly (post AES enforcement)`
  counts every `0x17` regardless of SPN ownership, which is not a usable alert while RC4 is
  permitted. Its own description is "after AES enforcement every `0x17` is an anomaly —
  threshold inverts."

### Benign baseline — the measurement that comes first

Every detection in this repo has been tested against an attack. **None has been measured
against normal activity**, which is the first question anyone running a SOC asks, because alert
fatigue is what kills detection programmes.

So before the hardening work: let the lab run **24–48 hours with no attack at all** — then run
all scheduled searches over that window and count how many times each fired. The output is a
false-positive rate per rule, which is a table this kind of portfolio almost never has.

**The benign activity has to be generated, not waited for.** Seven VMs left powered on and idle
produce near-silence, and a window of silence measures nothing — it just returns zero for every
rule and invites exactly the wrong conclusion.

And the activity list cannot be generic, because under the convention below a rule whose
false-positive source was never touched is reported as unmeasured however long the window ran.
So the list is derived per rule, from what that rule actually keys on:

| Rule being calibrated | Its false-positive source | What has to run during the window |
| --------------------- | ------------------------- | --------------------------------- |
| `Purple - C2 Beacon from User-Writable Path` | processes sending traffic from `Temp` / `AppData` / `ProgramData` / `Users\Public` | OneDrive sync, browser auto-updaters (Chrome and Edge both live in `AppData`), any updater left enabled |
| `Purple - Kerberoasting User-SPN Ticket (etype-agnostic)` | legitimate service tickets for SPNs held by user accounts | **repeated, periodic authentication to `SQLService` from a user account** — see below |
| `Purple - Large Outbound Transfer` | legitimate bulk **egress** — the search sums `orig_bytes`, what an internal host sends | uploads to the share or to cloud storage, and the initial sync of a sizeable folder. **Not a download:** that is almost all `resp_bytes` and never touches this rule's source |

The first and third happen by themselves once the machines are genuinely in use. **The middle
one does not**, and it is the trap: a `4769` for a user-held SPN will not occur spontaneously in
a quiet lab, so if nobody touches that service the rule reads zero after 48 hours and is
reported as unmeasured. That is the rule the zero/unmeasured distinction was introduced for.
Worse, its blocker is specifically "an allowlist of routinely requested SPNs" — an allowlist
that cannot be built from a window in which no SPN was routinely requested. The baseline would
run successfully and leave the rule exactly as unschedulable as before.

Three things about that middle row are easy to get wrong:

- **The requestor has to be a user principal.** The rule excludes machine requestors twice
  over, `Account_Name!="*$"` and `Account_Name!="*$@*"`, because on `4769` the requestor arrives
  as `principal@REALM`. Authenticating from a machine or service context produces events the
  rule filters out, which is indistinguishable from having generated nothing at all.
- **A natural rate cannot be measured for an SPN with no real consumer.** `SQLService` is the
  human-managed legacy account from the residual-gap register; whatever frequency the window
  shows is the frequency that was deliberately generated, not the domain's own. So the allowlist
  for it is built on **identity** — which principals legitimately request which SPNs, and what
  the event looks like when they do — and not on a rate threshold. `benign-baseline.md` records
  that those tickets were generated rather than observed, because citing a self-chosen number as
  an environment's normal rate is the error this section exists to prevent.
What runs during the window is recorded in `benign-baseline.md` next to the counts, because the
counts only mean something in terms of what was exercised. (The honeypot SPN, created later at
step 6, is the one documented exception to the zero/unmeasured convention — see
[the honeypot rule](#the-honeypot-needs-a-rule-or-it-is-just-an-account).)

**Window length, reconciled.** The 24 October text specifies "a full week" for the
outbound-transfer percentiles; this revision specifies 24 to 48 hours, and the cost is stated
rather than hidden. 48 hours gives roughly 288 ten-minute windows per host, so a p99 sits two or
three samples from the maximum — a near-maximum, not a tail estimate. The threshold is therefore
set from the **95th** percentile with the sample count beside it, shipping in the
"threshold lab-specific" state. A week would give a defensible p99 and is not worth five more
days ahead of the first artefact.

The app ships 18 searches with 13 scheduled, and **none of the five unscheduled ones is blocked
on a missing idea** — each is blocked on a measurement or a setting. A sixth is missing entirely:

> **Resolved, 3 Nov 2026.** The benign window closed and two of these were unblocked by it, so
> the live app now runs **18 searches with 15 scheduled**. `C2 Beacon` and the etype-agnostic
> `Kerberoasting` rule are scheduled with the allowlists the window measured. Three remain
> unscheduled: `Large Outbound Transfer`, `Verify Account Lockout (post FGPP)` and
> `RC4 Anomaly (post AES enforcement)`.
>
> **One row below is wrong and is left as written.** `Verify Account Lockout` is listed as
> blocked on "the lockout policy not being applied yet". It was already applied — the
> `Strong-Users` fine-grained policy has been in force since 4 June 2026, which the window
> found. That rule is schedulable now and its cell does not move between the before and after
> columns at all. See the dated note under [Deliberate residual gaps](#deliberate-residual-gaps).
>
> Results and allowlists: [`benign-baseline.md`](benign-baseline.md).

| Unscheduled rule | Blocked on | Unblocked by |
| ---------------- | ---------- | ------------ |
| `Purple - C2 Beacon from User-Writable Path` | an allowlist of legitimate `AppData` egress | benign baseline |
| `Purple - Kerberoasting User-SPN Ticket (etype-agnostic)` | an allowlist of routinely requested SPNs | benign baseline |
| `Purple - Large Outbound Transfer` | a measured byte threshold, not the placeholder 10 MB | benign baseline |
| `Purple - Verify Account Lockout (post FGPP)` | the lockout policy not being applied yet | hardening (lockout) |
| `Purple - RC4 Anomaly (post AES enforcement)` | RC4 still being permitted | hardening (AES-only) |
| `Purple - Honeypot SPN Ticket Request` | the rule does not exist yet, and neither does the account | hardening (honeypot) — see below |

The benign baseline calibrates the first three; the two cheap Kerberos/account settings unblock
the next two; the last is written with the honeypot it watches. Taken together the target for v4
is explicit and measurable: **19 searches shipped, 19 scheduled**, with none left in the
ship-but-never-fire state that v3 produced two examples of. Each rule ends in one of three
states, not two:

| End state | Meaning |
| --------- | ------- |
| Scheduled, threshold measured | the benign window exercised this rule's false-positive source and the number holds |
| Scheduled, threshold lab-specific | calibrated here, but the window could not represent a real estate — carries a note saying so, and saying what to re-measure |
| Deleted | the rule is wrong, not merely uncalibrated |

The middle state exists on purpose. Deleting a conceptually sound detection because a seven-VM
lab could not calibrate it would be a loss dressed up as discipline.

#### The honeypot needs a rule, or it is just an account

The hardening baseline above adds "a honeypot service account with an SPN that is never
legitimately used: any Kerberos request for it is malicious by definition." **No such rule
exists** — `detections/` has nothing keyed on a honeypot or decoy SPN, in any of the three
formats. An account created without the rule is a decoy nobody watches, which is worse than not
setting the trap: it reads as coverage and provides none. So it is scoped now as the nineteenth
search, `4769` where `Service_Name` is the honeypot SPN, and three things make it unlike every
other rule in the pack:

- **No threshold** — one hit is the alert; the legitimate rate is zero by construction.
- **No exclusions.** The Kerberoasting rule filters machine requestors because there a machine
  asking for a service ticket is ordinary. Here a computer account requesting the honeypot SPN
  is as suspect as a user, so the rule excludes nothing.
- **An unexercised zero is its measurement** — silence is the expected result, which is why the
  zero/unmeasured convention does not apply to it.

It belongs to step 6, since it cannot exist before the account does. The two are created
together and neither ships without the other.

#### What this measurement cannot claim

A false-positive rate measured here is **not** one measured in production, for a specific
reason rather than as a disclaimer: three Windows hosts and a handful of accounts generate a
fraction of a real estate's benign noise. `Purple - C2 Beacon` is the clearest case — its false
positives come from legitimate `AppData` egress (OneDrive, Teams, browsers), so with few users
and almost no SaaS traffic an allowlist derived from this window is **incomplete by
construction**. The same holds for `Purple - Large Outbound Transfer`, whose threshold reflects
this segment and nothing else.

So **a zero means one of two different things** and they must not be collapsed: the rule had the
opportunity to fire and did not, or nothing exercised its false-positive source at all. The
second is not a clean rule but an unmeasured one — the distinction the matrix draws with `M` and
`→`. The baseline table therefore records, per rule, whether the window exercised what that rule
keys on, and a rule whose source was never exercised does not graduate to "threshold measured"
on the strength of a zero.

This repo has paid for that distinction once. `Purple - Spray Success` shipped with two claims
that were "reasoned about rather than executed," and running the query on 29 October showed both
were wrong — the rule had been passing on a coin flip, and a quiet day measured it at 1 true
positive and 4 false where the reasoning predicted none. An unexercised zero is the same failure
pointed the other way: a number that looks measured, from a process that never tested what it is
cited for. Stating the limit beside the table rather than after it is the difference between a
measurement and a claim.

No new attack techniques are added in v4. The chain already covers spray, Kerberoasting, LSASS
access, lateral movement, persistence, C2 and exfil; another technique would add volume, not
argument. One item is noted as optional and last: `T1003.006` (DCSync) sits at score 50 in the
[ATT&CK layer](../detections/attack_navigator_layer.json) because the SharpKatz attempt failed
at the DRS bind with RPC 1825, and the `4662` detection for it is already written in
[v2's playbook](../v2/03_detection_playbook.md). Making that attempt succeed would convert a
scored-50 cell to a measured one, but it is RPC troubleshooting rather than new detection work,
so it ranks below everything above.

### Logging gaps to close before the benign window (step 2)

Both are defects this repo found and recorded itself, and leaving them recorded-but-open is
worse than not having found them:

- **~~`wazuh-vm` is not covered by the cross-sensor liveness rule.~~ Closed, 2 Nov 2026 — and the
  remedy written here was wrong.** This gap gated the benign window: a 48-hour measurement is
  only worth the wait if a sensor going dark inside it is noticed while it happens, and
  `wazuh-vm` was the one host where it would not be. The fix prescribed above was "a second
  heartbeat feed brings it under the rule." **It does not.** A 60-second timer feed cross-checked
  against an event-driven one makes legitimate quiet look like an outage, and the measurement is
  concrete: with `wazuh-manager` active and healthy, `alerts.json` was observed going **431
  seconds** without a write, against readings of 0–8 seconds minutes earlier. At the shipped
  20-minute threshold a longer quiet stretch would eventually fire that rule with nothing wrong.
  The feed was the right idea and the cross-check the wrong instrument. So the heartbeat got its
  own search, `Purple - Wazuh Sensor Health (single-feed host)`, **verified by trigger across all
  three states** — empty on a healthy stack, `manager=inactive` at `hb_age_min=0.7` with the
  manager stopped (which is the proof it separates a dead manager from a dead host), clear again
  on restart. Its `alerts_age_sec` branch is deliberately **not** a firing condition: one sample
  is not a threshold, so the benign window measures the natural quiet distribution first.
- **~~The `security-vm` forwarder ingests Zeek's bookkeeping files.~~ Closed, 2 Nov 2026.**
  Measured before touching it: 141 distinct sources in 24 hours, about **70 of them not logs**
  — under 1% of events but half the source cardinality. And `*.log` alone was **not** the right
  filter: `.rotated.*` carry no extension so a whitelist drops them, but `stdout.log` and
  `stderr.log` do end in `.log` and are process output, so the stanza needs a blacklist too.
  `stderr.log` is routed to its own `zeek:stderr` sourcetype rather than discarded — it is where
  the `pcap_activate` message from the six-day Zeek outage sat unread. **Verified by probe with
  a positive control:** of three files written at once, `probe_control.log` arrived and the two
  junk-pattern files did not; without that control two absences would equally have meant the
  forwarder had stopped scanning. Details in
  [`infrastructure/logging-config.md`](infrastructure/logging-config.md).

Both are configuration changes inside the VMs, so they are made **before** `v4-post-logging`.
Made after it, a rollback would silently undo them.

### Layer 1 — triage (`investigations/`)

The case-file format above stands, with three elements made mandatory in every file:

| Element | What goes in it |
| ------- | --------------- |
| TP/FP decision | True positive or false positive, with the evidence that decided it |
| Severity | The severity assigned, and why it was raised or lowered from the alert default |
| Escalation | What L1 hands to L2: the open questions, the artefacts collected, the scope still unknown |

The Escalation section is the one that matters. The format above ends at the verdict and the
remediation, which is where most written triage stops; the handoff is the part of the L1 role
hardest to demonstrate on paper.

**Three case files, not six.** The 24 October tree lists `CASE-01` to `CASE-06` — six new
narratives about a chain [v3](../v3/) already documents in seven. The Escalation format is a
different demonstration from those files, not a duplicate, but three demonstrate it in full.
Named here so the scope is not left to interpretation:

| File | Why this one |
| ---- | ------------ |
| `CASE-02-kerberoasting.md` | AES-only Kerberos plus the legacy-account exception — the clearest policy-driven change in the set |
| `CASE-04-lsass-false-positive.md` | `RunAsPPL` on one endpoint and not the other is a measurable split (Credential Guard was scoped first and [is not available on these hosts](#deliberate-residual-gaps)), and the LSASS rule's benign reads are already measured (`WmiPrvSE.exe`, `wazuh-agent.exe`), so the TP/FP decision has real evidence behind it rather than a staged one |
| `CASE-05-persistence.md` | persistence is one of only two phases with no row in the residual-gap register. The uncertainty is narrower than an earlier draft of this table claimed: no ASR rule targets scheduled-task creation, so the cell is predicted unchanged unless the prevalence rule blocks the payload the task launches — which is the thing the case file measures |

Dropped: password spray (the Addendum establishes its detection outcome in advance, so there is
nothing to find), lateral movement (deliberately unchanged — WinRM stays open), and C2
beaconing, whose interesting work is the benign-baseline calibration below rather than a triage
narrative.

### Layer 2 — hunting and incident response

The layer the plan above does not cover at all. Two new artefacts.

**`v4/hunts/` — two to three hunt files.** Hypothesis-driven, not alert-driven: each starts from
a claim about attacker behaviour that can be proven or disproven, and states the hypothesis, the
query and why that source, the finding including a negative one, and the recommendation — a
rule, a hardening change, or "no action, hypothesis disproven."

**The selection rule is to hunt the gaps, not the wins.** A hunt that re-describes an alert that
already fired is triage in reverse; Kerberoasting and the JA4 fingerprint both fired in v3 and
are already case files. The two gaps this page has measured are the real material:

- **Spray detection by a signal other than the `4771` count.** The Addendum establishes that the
  shipped rule cannot fire here — the estate is one account short of the threshold — so that
  question is closed and is not the hunt. The open question is whether the spray is detectable
  at all by a different signal: source-address correlation across multiple accounts within a
  window, or `4625` failure patterns, neither of which depends on the account count. If a signal
  exists, it is a rule; if none does, the negative result is what makes the matrix cell honest.
- **C2 beaconing from an allowlisted path.** `Purple - C2 Beacon` ships unscheduled because
  legitimate software beacons from `AppData` too. The hypothesis is that a beacon there is
  separable from OneDrive, Teams and browser traffic by behaviour rather than by location —
  JA4 fingerprint rarity, connection-interval regularity, bytes-out to bytes-in ratio. The
  finding is the allowlist the rule needs before it can be scheduled.

A hunt that disproves its hypothesis, or proves a gap is real, is a complete hunt file: a
negative result naming a concrete gap beats a positive one repeating a rule already known to
work.

**`v4/incident-report.md` — one IR timeline for the before-run.** One narrative, not a set of
alerts: an executive summary for someone who will not read the rest; a timeline correlated
across all five sources; blast radius, separating what was compromised from what was reached but
not compromised and what was never touched; which single source would have been insufficient
alone; containment, in the order done and what that order cost; and the gaps found, including
the two hunted above. This is incident scoping, not triage, and it must not restate the case
files — a case file answers "is this real," the IR report answers "how far did it go."

### Layer 3 — detection engineering

Unchanged in content. `detections/` and the Sigma pack stay as they are, plus the nineteenth
search below. `coverage-matrix.md` is produced by steps 4, 6 and 7, not before them, and carries
the `M` / `→` marks so a reader can tell a measured cell from a carried-forward one. No CI
pipeline — the matrix carries the argument on its own.

### Current structure — changes to the 24 October tree

Rather than restate it: `README.md` and `infrastructure/logging-config.md` now **exist**;
`investigations/` holds **three** files (`CASE-02`, `CASE-04`, `CASE-05`) instead of six; and
three paths are **added** — `hunts/` (L2, 2–3 files), `incident-report.md` (L2, one correlated
timeline) and `benign-baseline.md` (the FP rate per rule, what the window exercised, and what it
cannot claim). Everything else in that tree stands as written.

Three case files, two to three hunt files, one IR report, one benign baseline. Three clean
layers beat three half-finished ones; once these exist, all 19 searches have reached one of the
three end states above, and the matrix is filled through the hardening run, v4 is closed.

> **Built, 7 Nov 2026 — eight case files rather than three, and the numbering is fresh.** The
> prediction above is left as written. What step 5 actually produced:
>
> | Planned | Built |
> | ------- | ----- |
> | `investigations/`, 3 files, reusing the v3 numbers `CASE-02`/`04`/`05` | **8 files, numbered `CASE-01`–`CASE-08` from scratch** |
> | `hunts/`, 2–3 files | 2 files |
> | `incident-report.md` | as planned |
>
> **Why eight.** The plan sized `investigations/` by the three v3 case files whose techniques the
> chain repeats. The before-run produced eight cells with a finding worth a file, and five of
> them are about defects the v3 cases could not have anticipated because the rules did not exist
> yet — a rule pointed at the wrong Kerberos message, an alert that cannot name the account it
> fired on, two C2 rules that each cover one endpoint, a scheduled rule in no inventory, and
> three consecutive chain steps with no alert between them. Writing three would have meant
> dropping findings to match a count.
>
> **Why fresh numbering.** Reusing `CASE-02`/`04`/`05` would tie a v4 file to the v3 file for the
> same technique, and none of the eight is a continuation of its v3 counterpart —
> [`CASE-01`](investigations/CASE-01-password-spray-undercount.md) is about telemetry that cannot
> count, where v3's spray case was about a threshold. A reader following `CASE-05` across versions
> would find two unrelated arguments. The v3 set stays [where it is](../v3/investigations/) and is
> linked from the cases that build on it.
>
> The end-state claim above still holds: every shipped search now has a measured cell, a case
> file, or a stated reason it has neither.
