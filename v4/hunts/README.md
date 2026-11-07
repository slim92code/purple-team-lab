# v4 hunts

Hypothesis-driven, not alert-driven. Each file starts from a claim about attacker behaviour that
can be proven or disproven, and states the hypothesis, the query and why that source, the finding
including a negative one, and the recommendation — a rule, a hardening change, or "no action,
hypothesis disproven".

**The selection rule is to hunt the gaps, not the wins.** A hunt that re-describes an alert which
already fired is triage in reverse. The material here is what the
[before-run column](../coverage-matrix.md) measured as missing.

| Hunt | Hypothesis | Outcome |
| ---- | ---------- | ------- |
| [HUNT-01 — is the spray detectable by any signal that does not depend on the account count?](HUNT-01-spray-without-the-4771-count.md) | A signal exists that does not require counting accounts in the Windows failure log | **Proven twice, disproven once.** Zeek counts 8 principals where the shipped rule sees 3; `4625` returns zero, so the industry-default spray signal is blind here |
| [HUNT-02 — can the beacon be separated by behaviour instead of a path allowlist?](HUNT-02-beacon-by-behaviour-not-path.md) | A beacon is separable from legitimate software by behaviour rather than by location | **One proven, one inverted.** Connections per destination gives 12.0 against OneDrive's 1.6–2.4; interval regularity ranks OneDrive *above* the implant |

## Why a negative result counts

Both hunts here produced a disproof more useful than their proof.

HUNT-01's is a zero: no `4625` events at all, so the spray detection most SIEM content ships
would have seen nothing from this attack. HUNT-02's is worse than a zero — interval regularity,
the first signal most beacon-detection content reaches for, ranks a Microsoft sync client as more
regular than a live C2 implant. A team that built it would get a false positive on OneDrive and a
false sense of coverage on the beacon, and it would survive review because the method is textbook.

Neither of those is a confirmation of a rule already known to work, which is the point of
hunting the gaps.
