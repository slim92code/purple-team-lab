# v4 alert-triage case files

One file per cell worth investigating, written against the
[before-run column](../coverage-matrix.md) — the un-hardened estate, measured 6 November 2026.
Each follows the same shape: what the alert showed or failed to show, the questions asked, the
queries run verbatim, the findings, a verdict, and what is owed.

These are the deliverable v4 exists to produce. The matrix is the evidence; these are the
reasoning over it.

| Case | Phase | Verdict |
| ---- | ----- | ------- |
| [CASE-01 — a password spray that fired two alerts, neither from the spray rule](CASE-01-password-spray-undercount.md) | 2a | True positive. The rule written for it did not fire; two other things did. |
| [CASE-02 — account enumeration: four layers, one holds the evidence, none alerts](CASE-02-kerberos-enumeration.md) | 1 | True positive, undetected. Structural, not a threshold. |
| [CASE-03 — the RC4 rule reads the wrong Kerberos message, and its own description says so](CASE-03-rc4-wrong-message-type.md) | 4a, 6 | Two RC4 tickets issued to an attacker, neither detected. Scope defect, not tuning. |
| [CASE-04 — the lockout alert fires correctly and cannot say which account](CASE-04-lockout-alert-with-no-account.md) | 2c | True positive, unusable output. Two causes, one not the rule's fault. |

## Still to write

Cells with findings already measured and no case file yet:

| Cell | The finding |
| ---- | ----------- |
| `#2` / `#14` C2 | Two rules, each covering one endpoint, neither covering both. The evidence is wider than either alert. |
| `#15` Large Outbound | Fires on both exfiltrations and on 12.5 MB of ordinary Microsoft HTTPS, on a threshold that was never calibrated. |
| Phase 6 — Pass-the-Ticket | Executed, successful, and nothing in any layer alerts. |
| Phase 7 — WinRM lateral | The Zeek rule fires on 6 of 7 connections; the second burst is 6.59 MB of collection that no rule reads. |

## A convention worth stating once

Three of these cases turn on the same distinction, so it is set out here rather than repeated:
**an empty query result is a claim about the query until a control proves it is a claim about the
world.** Every "nothing fired" below is accompanied by a count of the event the rule reads,
because an inert rule and a quiet estate produce the same empty table and mean opposite things.

The column these are written against produced four near-miss queries across two independent
passes, one of which returned a partial result that looked like an answer. That history is
recorded in [the matrix's method section](../coverage-matrix.md), and it is why every case file
here carries its SPL.
