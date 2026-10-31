# Lab v4 — Hardened Baseline and Alert Triage Case Files

> ## Status: design document, not yet built
>
> This page is the plan for v4, written before the work starts. It is not a results page and
> nothing here is a finding. Last updated 24 Oct 2026.
>
> | | |
> | --- | --- |
> | Written | scope, hardening baseline, firewall GPO design, logging change, residual-gap risk register |
> | Not yet done | applying the baseline, re-running the kill chain, the coverage matrix, the case files |
> | Completed labs | [v2](../v2/) and [v3](../v3/) |
>
> It is published first on purpose. v4's deliverable is a before/after detection-coverage
> matrix, and a before/after written afterwards proves nothing, so the predictions have to be
> on record first. The residual gaps below work the same way: committing to them in advance
> is what makes them a risk register instead of a list written around whatever got through.
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

The canary was reverted from its per-file `inputs.conf` backup so the lab stays on one
consistent format; the proper rollout changes all three hosts, widens the `source` filters,
and re-tests each search, as a single focused pass.

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
