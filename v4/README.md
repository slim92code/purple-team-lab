# Lab v4 — Hardened Baseline and Alert Triage Case Files

> **Status: in progress.** This folder is the plan; content lands as each stage completes.
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
| Network protocols | LLMNR / NBT-NS / mDNS / WPAD disabled, SMB signing required, SMBv1 removed, LDAP signing and channel binding, east-west SMB/WMI/WinRM blocked between endpoints |
| Account and Kerberos | Account lockout, 14-character minimum with complexity and history, AES-only Kerberos, `ms-DS-MachineAccountQuota=0`, LAPS, gMSA for service accounts (one legacy account excepted — see residual gaps) |
| Execution controls | PowerShell script-block / module / transcription logging, Defender ASR rules, tamper protection, Print Spooler disabled on the DC |

Plus a honeypot service account with an SPN that is never legitimately used — any Kerberos
request for it is malicious by definition.

Each control is recorded with what it was before, what it is now, and which detection it
enables or which attack phase it blocks.

## Deliberate residual gaps

Real environments are hardened unevenly. These gaps are chosen, documented as a risk
register, and are what the kill chain works through:

| Gap | Why it is realistic | Attack phase it leaves viable |
| --- | ------------------- | ----------------------------- |
| One legacy service account stays human-managed with an SPN | Applications that cannot use gMSA are the most common real exception | Kerberoasting |
| Lockout enforced, but spray stays under the threshold | One password per account per window is what real spray does | Password spray |
| WinRM reachable from one administrative host | Every environment keeps an admin path | Lateral movement |
| Credential Guard on one endpoint, not both | Uneven rollout is the norm | LSASS access |
| PowerShell logging on, application allowlisting off | Extremely common combination | PowerShell execution |

## Planned contents

```
v4/
├── README.md
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
