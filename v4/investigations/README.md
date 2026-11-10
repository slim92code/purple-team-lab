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
| [CASE-03 — the RC4 rule reads the wrong Kerberos message, and its own description says so](CASE-03-rc4-wrong-message-type.md) | 4a, 6 | Two RC4 tickets issued to an attacker, neither detected. Scope defect, not tuning. **Fix deployed and verified 10 Nov 2026.** |
| [CASE-04 — the lockout alert fires correctly and cannot say which account](CASE-04-lockout-alert-with-no-account.md) | 2c | True positive, unusable output. Two causes, one not the rule's fault. |
| [CASE-05 — two C2 rules, one endpoint each, and neither covers both](CASE-05-c2-two-rules-one-host-each.md) | 5a, 5b | True positive on two hosts. Both rules correct, neither complete. |
| [CASE-06 — exfiltration detected twice, and a Windows download that looks the same](CASE-06-exfil-uncalibrated-threshold.md) | 11, 12 | Two true positives, one false positive. No rule defect; the open item is a number. |
| [CASE-07 — the loudest rule on the instance is in nobody's inventory, and notifies nobody](CASE-07-the-loudest-rule-is-not-in-the-repo.md) | — | 28 firings from a rule in no file here. Three ways of counting coverage, three wrong answers. |
| [CASE-08 — the alerts give the ends of the chain and not the links](CASE-08-the-middle-of-the-chain-is-unalerted.md) | 6, 7 | Three true positives, no alerts. The estate detects acquisition and egress, not movement. |
| [CASE-09 — a catch-up alert for a three-day-old attack suppressed a live one](CASE-09-a-stale-alert-suppressed-a-live-one.md) | 2a | Two false alerts, one missed real one. No rule defect — a scheduler behaviour colliding with a throttle. |

Every cell in the before-run column with a finding now has a case file. What remains of step 5 is
the hunts and the incident report.

## A convention worth stating once

Three of these cases turn on the same distinction, so it is set out here rather than repeated:
**an empty query result is a claim about the query until a control proves it is a claim about the
world.** Every "nothing fired" below is accompanied by a count of the event the rule reads,
because an inert rule and a quiet estate produce the same empty table and mean opposite things.

The column these are written against produced four near-miss queries across two independent
passes, one of which returned a partial result that looked like an answer. That history is
recorded in [the matrix's method section](../coverage-matrix.md), and it is why every case file
here carries its SPL.
