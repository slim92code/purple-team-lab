# Lab v4 — Hardened Baseline and Alert Triage Case Files

> ## Status: predictions written 24 Oct 2026, build in progress
>
> The plan below was written before the work started and its predictions are left unchanged, so
> they stay auditable. **Nothing in the plan is a result.** What has been measured since is in
> dated sections, each carrying the date it was measured — those are results. The distinction
> between the two is the point of this page. Last updated 2 Nov 2026.
>
> | | |
> | --- | --- |
> | Written 24 Oct | scope, hardening baseline, firewall GPO design, logging change, residual-gap risk register |
> | Measured since | sensor persistence (30 Oct), CIM sourcetype fix rolled out and verified (31 Oct), pre-hardening baseline verified across all five feeds and snapshotted on all seven VMs |
> | Not yet done | applying the hardening bundles, re-running the kill chain, the coverage matrix, the case files, the hunts, the IR report |
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
does not revise any prediction above, which stay as written on 24 October. It replaces a
short-lived separate `v4/PLAN.md`, which duplicated this page and is removed — one page, one
source of truth.

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
4. **The IR report and the hunts are written against that pre-hardening run.** They describe
   and interrogate the chain as it fires against the un-hardened baseline, so the "before"
   story is on record before anything changes. Neither waits on hardening.
5. **Hardening is applied afterwards, bundle by bundle** — the controls that survive the
   criterion below, not the full CIS sweep, and not all at once. Each bundle is followed by a
   snapshot, a **targeted re-run of only the kill-chain phases that bundle plausibly affects**,
   and one column in `coverage-matrix.md`: what still fires, what the bundle blocked for the
   attacker, and what it broke for detection. A bundle that corrupts the baseline is rolled
   back to `v4-post-benign`. The honeypot account and
   [the rule that watches it](#the-honeypot-needs-a-rule-or-it-is-just-an-account) are created
   in this step, together.
6. **One full kill-chain re-run at the end**, with the hardening in place. That is the clean
   "after" state, and it is the column the before/after comparison actually rests on.

Snapshots, in the order they are taken: `v4-pre-hardening` (done) → `v4-post-logging` →
`v4-post-benign` → one per hardening bundle.

### Why the per-bundle runs are targeted, and what that costs

A full kill chain after every bundle would mean five full runs. The cheaper scheme — targeted
runs per bundle, one full run at the end — produces the same final comparison and still
attributes which bundle moved which cell, so the extra four full runs buy very little. But it
costs two things, and both are recorded here rather than discovered later:

**Un-run cells are unmeasured, not unchanged.** This is the part that matters. If a phase was
not re-run after a bundle, its cell in that column is not evidence that the bundle left it
alone — it is simply not measured. The matrix therefore uses two marks:

| Mark | Meaning |
| ---- | ------- |
| **M** | Measured — the phase was re-run after this bundle and the result recorded |
| **→** | Not re-measured; the value is carried forward from the previous column |

Every cell in the final full-run column is measured. A phase that no bundle plausibly touches
reads `→ → → → →  M`, which says on its face that its only post-hardening measurement is the
final run. Without this distinction the matrix would claim more than was measured, which for a
before/after artefact is the one failure that voids it.

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

The five bundles above were scoped on 24 October by what a CIS-aligned baseline contains. That
is the right way to describe a baseline and the wrong way to decide what this lab should spend
time on, because the residual-gap register is deliberately built so that every kill-chain phase
stays viable. The effect of hardening here lands on **telemetry**, not on whether the attack
succeeds — so a control earns its place only if it changes what a detection sees.

**The criterion: a control stays if a rule can be named whose before/after cell it moves.**

| Control | Rule whose cell it moves | Stays |
| ------- | ------------------------ | ----- |
| Advanced audit policy | all of them — it generates the events the rules key on | yes |
| AES-only Kerberos | `Purple - RC4 Anomaly (post AES enforcement)` and Sigma rule 2 | yes |
| Account lockout / FGPP | `Purple - Verify Account Lockout (post FGPP)` | yes |
| `RunAsPPL` + Credential Guard split | the LSASS access rules — `CASE-04` | yes |
| PowerShell script-block / module logging | the PowerShell execution rules | yes |
| Defender ASR rules | the persistence cell, one of two with no residual-gap row | yes |
| `ms-DS-MachineAccountQuota=0` | none — kept only because it is one setting | no cell |
| Firewall GPO (`MARVEL-Firewall-Baseline`) | none — the lateral path is deliberately unchanged | no cell |
| LLMNR / NBT-NS / mDNS / WPAD disabled | none — no Responder step in this chain, no rule for it | dropped |
| LDAP signing and channel binding | none | dropped |
| SMB signing required, SMBv1 removed | none | dropped |
| IPsec domain isolation (Connection Security Rules) | none — prevention only | dropped |
| LAPS | none — local-admin reuse is not a path this chain takes | dropped |
| gMSA for service accounts | none — the legacy SPN account is a documented exception anyway | dropped |

Two entries are kept despite moving no cell, and both are labelled as such rather than quietly
counted: `MachineAccountQuota=0` because it is a single setting and leaving a known privilege-
escalation path open to save thirty seconds would be silly, and the firewall GPO because the
[Firewall baseline](#firewall-baseline-gpo) section above records the v3 per-host rules as an
inconsistency, and dropping the GPO would leave that defect standing. Neither produces a column
in the matrix.

**Why the dropped controls were dropped, stated plainly:** they are prevention whose effect no
shipped rule measures. LLMNR poisoning, LDAP relay and SMB relay are real attacks and hardening
against them is correct in a real estate; this lab has no step that exercises them and no rule
that would show the difference, so applying them here would produce an unmeasurable change at
the highest cost and risk in the plan. IPsec domain isolation is the clearest case: the section
above already concedes it is "a real project, not one switch," and it is prevention with no
telemetry consequence. LAPS needs a schema extension and gMSA needs a KDS root key, for cells
the register already commits to leaving unchanged.

This cuts the hardening work from roughly 10–14 hours to about 6, and nothing that moves a
matrix cell is given up.

**One claim corrected while writing this.** An earlier draft of this section said AES-only
Kerberos turns the RC4 rule "from a present-but-unremarkable signal into an anomaly by
definition." That overstates it for Sigma rule 2, which is already a clean anomaly detector:
over 30 days this domain issued 1,649 service tickets, every one of them `0x12` (AES-256), and
zero RC4 — so the rule already fires on nothing benign. What AES-only actually changes is
narrower and worth stating exactly:

- **Prevention:** an explicit RC4 downgrade currently succeeds — the v3 Pass-the-Ticket step
  obtained a `4768` TGT at `0x17`. Under AES-only it is refused everywhere except the legacy
  account.
- **Detection:** rule 2's zero-false-positive property moves from accidental to enforced. Today
  nothing happens to use RC4; afterwards policy forbids it. A baseline can drift, a policy
  cannot.
- **And one rule becomes schedulable at all:** `Purple - RC4 Anomaly (post AES enforcement)`
  counts every `0x17` regardless of SPN ownership, which is not a usable alert while RC4 is
  permitted. Its own description is "after AES enforcement every `0x17` is an anomaly —
  threshold inverts." That rule is the one the original phrasing was true of.

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
| `Purple - Large Outbound Transfer` | legitimate bulk egress | file uploads, a large download, the initial sync of a sizeable folder |

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
- **Noted ahead, for step 5 and not for this window:** the honeypot SPN will be the one
  documented exception to the zero/unmeasured convention. The honeypot account does not exist
  during the benign window — it is created with the hardening baseline — so nothing about it
  constrains this measurement. But once the rule over it is written, an unexercised zero **is**
  its measurement rather than a gap, because its whole premise is that no legitimate traffic
  exists. The convention must not be applied mechanically there. See
  [the honeypot rule](#the-honeypot-needs-a-rule-or-it-is-just-an-account) below.

What runs during the window is recorded in `benign-baseline.md` next to the counts, because the
counts only mean something in terms of what was exercised.

This is not a side quest; it is the input three shipped rules are already waiting on. The app
ships 17 searches with 12 scheduled, and **none of the five unscheduled ones is blocked on a
missing idea** — each is blocked on a measurement or on a setting. A sixth is missing entirely
and is added below:

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
is explicit and measurable: **18 searches shipped, 18 scheduled**, with none left in the
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
exists** — `detections/` has nothing keyed on a honeypot or decoy SPN, in any of the three rule
formats. Creating the account without writing the rule produces a decoy nobody is watching,
which is worse than not setting the trap: it reads as coverage and provides none.

So it is scoped now rather than discovered after the hardening run, and it is the eighteenth
search:

```
[Purple - Honeypot SPN Ticket Request]
  4769 where Service_Name = <the honeypot SPN>
```

Three things make it unlike every other rule in the pack, and all three are the point of it:

- **No threshold.** One hit is the alert. There is no rate to calibrate because the legitimate
  rate is zero by construction.
- **No exclusions.** The Kerberoasting rule above filters machine requestors, because there a
  machine asking for a service ticket is ordinary. Here it is not: a computer account requesting
  the honeypot SPN is as suspect as a user doing it, so the rule excludes nothing.
- **An unexercised zero is its measurement.** Silence over the benign window is exactly the
  expected result, which is why the zero/unmeasured convention does not apply to it.

It cannot be written or scheduled until the honeypot account exists, so it belongs to step 5 and
not to the benign window. The account and the rule are created together, in that order, and
neither ships without the other.

#### What this measurement cannot claim

A false-positive rate measured here is **not** a false-positive rate in production, and the
reason is specific rather than a general disclaimer: this lab has three Windows hosts and a
handful of accounts, so the benign noise that drives most of these rules is a fraction of what
a real estate generates. `Purple - C2 Beacon from User-Writable Path` is the clearest case —
its false positives come from legitimate `AppData` egress (OneDrive, Teams, browsers), and with
few users and almost no SaaS traffic an allowlist derived from this window is **incomplete by
construction**. The same applies to `Purple - Large Outbound Transfer`, whose byte threshold
reflects this segment's traffic and nothing else.

So **a zero in the table means one of two different things**, and they must not be collapsed:
either the rule had the opportunity to fire on benign activity and did not, or nothing in the
window exercised its false-positive source at all. The second is not a clean rule — it is an
unmeasured one, the same distinction the coverage matrix draws with `M` and `→`. The baseline
table therefore records, per rule, whether the window actually exercised what the rule keys on;
a rule whose source was never exercised is reported as unmeasured and does not graduate to
"threshold measured" on the strength of a zero.

This repo has already paid for that distinction once. `Purple - Spray Success` shipped with two
claims in its description that were "reasoned about rather than executed," and when the query
was finally run over real data on 29 October both were wrong — the rule had been passing on a
coin flip, and a quiet day measured it at 1 true positive and 4 false where the reasoning had
predicted none. A zero that nothing exercised is the same failure in the other direction: a
number that looks measured, produced by a process that never tested the thing it is being
cited for. The Addendum's spray entry is the milder sibling, "a measured estate limitation
rather than a hardening effect" — there the number is real and only its attribution is at
stake.

Stating the limit next to the table rather than after it is the difference between a
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
worse than not having found them. They are scheduled before the benign window rather than
alongside the hardening work, for the reason given in step 2:

- **`wazuh-vm` is not covered by the cross-sensor liveness rule.** `Purple - Sensor Feed Stale`
  needs two independent feeds per host to cross-check, and that host sends only one
  (`wazuh` alerts.json), which is event-driven and can be legitimately quiet. A second heartbeat
  feed there — a scripted input or a Perfmon equivalent — brings it under the rule.
  **This one gates the benign window.** A 24-to-48-hour measurement is only worth the wait if a
  sensor going dark inside it is noticed while it happens; `wazuh-vm` is the one host where it
  would not be. Closing this first is the same reasoning the Addendum applies to `ens37`, which
  it makes step zero of v4 precisely because a dead sensor during a measured run makes the
  measurement worthless.
- **The `security-vm` forwarder ingests Zeek's bookkeeping files.** It monitors all of
  `/opt/zeek/logs/current/` and takes `.pid`, `.env_vars`, `.rotated.*` and
  `.archive-log.running.*.tmp` in as if they were logs; the stanza should match `*.log` only.
  Lower stakes than the first — no shipped rule keys on those files, so it does not distort any
  false-positive count — but it is done in the same pass to keep the window's index clean.

Both are configuration changes inside the VMs, so they are made **before** `v4-post-logging` is
taken. Made after it, a rollback would silently undo them.

### Layer 1 — triage (`investigations/`)

The case-file format above stands, with three elements made mandatory in every file:

| Element | What goes in it |
| ------- | --------------- |
| TP/FP decision | True positive or false positive, with the evidence that decided it |
| Severity | The severity assigned, and why it was raised or lowered from the alert default |
| Escalation | What L1 hands to L2: the open questions, the artefacts collected, the scope still unknown |

The Escalation section is the one that matters. The format above ends at the verdict and the
remediation recommendation, which is where most written triage stops; what it does not show is
the handoff, and the handoff is the part of the L1 role that is hardest to demonstrate on paper.

**Three case files, not six.** The 24 October tree above lists `CASE-01` to `CASE-06`, which
would be six new narratives about a kill chain [v3](../v3/) already documents in seven. The
Escalation format is a different demonstration from the v3 case files, not a duplicate of them,
but it is demonstrated in full by three. The three are chosen for having the richest
before/after, and they are named here so the scope is not left to interpretation:

| File | Why this one |
| ---- | ------------ |
| `CASE-02-kerberoasting.md` | AES-only Kerberos plus the legacy-account exception — the clearest policy-driven change in the set |
| `CASE-04-lsass-false-positive.md` | Credential Guard on one endpoint and not the other is a measurable split — blocked on one host, viable on the other — and the LSASS rule's benign reads are already measured (`WmiPrvSE.exe`, `wazuh-agent.exe`), so the TP/FP decision has real evidence behind it rather than a staged one |
| `CASE-05-persistence.md` | ASR rules, and persistence is one of only two phases with no row in the residual-gap register, so the cell is genuinely uncertain |

Dropped: password spray (the Addendum establishes its detection outcome in advance, so there is
nothing to find), lateral movement (deliberately unchanged — WinRM stays open), and C2
beaconing, whose interesting work is the benign-baseline calibration below rather than a triage
narrative.

### Layer 2 — hunting and incident response

The layer the plan above does not cover at all. Two new artefacts.

**`v4/hunts/` — two to three hunt files.** Hypothesis-driven, not alert-driven: the hunt starts
from a claim about attacker behaviour that can be proven or disproven, not from an alert that
already fired. Each file states the hypothesis, the query and why that data source, the finding
including a negative one, and the recommendation — a detection rule, a hardening change, or "no
action, hypothesis disproven."

**The selection rule is to hunt the gaps, not the wins.** A hunt that re-describes an alert
which already fired is triage in reverse. Kerberoasting and the JA4 C2 fingerprint both fired
in v3 and are already written up as case files, so re-running them as hunts would prove nothing.
The two gaps this page has already measured are the real hunt material:

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

A hunt that disproves its hypothesis, or that proves a gap is real, is a complete hunt file. A
negative result that names a concrete detection gap is worth more than a positive result that
repeats a rule already known to work.

**`v4/incident-report.md` — one IR timeline for the pre-hardening run.** One narrative, not a
set of alerts: an executive summary written for someone who will not read the rest; a timeline
correlated across all five sources into a single sequence; blast radius, separating what was
compromised from what was reached but not compromised and what was never touched; which single
source would have been insufficient alone; containment, in the order it was done and what that
order cost; and the detection gaps found, including the two hunted above.

This is incident scoping, not alert triage, and it must not restate the case files. A case file
answers "is this real." The IR report answers "how far did it go."

### Layer 3 — detection engineering

Unchanged in content. `detections/` and the Sigma pack stay as they are; `coverage-matrix.md` is
produced by steps 5 and 6 above, not before them, since the before/after columns cannot exist
until the bundles have been applied and the chain re-run. It carries the `M` / `→` marks so a
reader can tell a measured cell from a carried-forward one. No CI pipeline — the matrix carries
the argument on its own.

### Current structure

Replaces the 24 October tree above. Two files exist; the rest is still the target.

```
v4/
├── README.md                      <- this page
├── infrastructure/
│   ├── topology.md
│   ├── hardening-baseline.md      <- before / after / why, per control
│   └── logging-config.md          <- exists (sensor persistence, cross-sensor liveness)
├── investigations/                <- L1: the triage deliverable, 3 files not 6
│   ├── CASE-02-kerberoasting.md
│   ├── CASE-04-lsass-false-positive.md
│   └── CASE-05-persistence.md
├── hunts/                         <- L2: hypothesis-driven, 2-3 files
├── incident-report.md             <- L2: one correlated IR timeline
├── benign-baseline.md             <- FP rate per rule, what the window exercised, what it cannot claim
├── coverage-matrix.md             <- L3: before / after hardening, per phase
└── risk-register.md               <- the residual gaps above, with rationale
```

Three case files, two to three hunt files, one IR report, one benign baseline. Three clean
layers beat three half-finished ones; once these exist, all 18 searches have reached one of the
three end states above, and the matrix is filled through the hardening run,
v4 is closed.
