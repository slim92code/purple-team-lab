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

## Planned

| Hunt | Hypothesis |
| ---- | ---------- |
| HUNT-02 — C2 beaconing from an allowlisted path | A beacon in `AppData` is separable from OneDrive, Teams and browser traffic by **behaviour** — interval regularity, bytes-out to bytes-in ratio, fingerprint rarity — rather than by location. The finding is the allowlist `Purple - C2 Beacon` needs before it can be scheduled |

## Why a negative result counts

A hunt that disproves its hypothesis, or proves a gap is real, is a complete hunt. HUNT-01's most
useful single number is a zero: no `4625` events at all, which means the spray detection most
SIEM content ships would have seen nothing from this attack. That is worth more than another
confirmation of a rule already known to work.
