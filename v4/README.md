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
baseline first, then re-runs the same chain — so each phase either gets blocked by a
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

Plus a honeypot service account with an SPN that is never legitimately used — any Kerberos
request for it is malicious by definition.

Each control is recorded with what it was before, what it is now, and which detection it
enables or which attack phase it blocks.

## Firewall baseline (GPO)

v3 blocked the attacker and east-west SMB with six per-host rules added by hand — accurate
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
