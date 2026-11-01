# Purple Team Lab v4 - Build Plan

This lab is readable at three levels: L1 triage (`investigations/`), L2 hunting and incident response (`hunts/`, `incident-report.md`), and detection engineering (`coverage-matrix.md`, `detections/`).

The goal of v4 is to make all three layers explicit and self-contained, so a reader can enter at whichever level matches their role.

---

## Sequence (read this first)

The artifacts below have a dependency order, because two of them describe the same attack run and one of them measures a change to it:

1. **Pre-hardening baseline is already captured.** The full stack (5 feeds: WinEventLog, Sysmon/XmlWinEventLog, Zeek, Suricata, Wazuh) was verified live and snapshotted as `v4-pre-hardening`. CIM is green (Network_Traffic populated), 17 searches loaded / 12 scheduled. This is the clean "before" state.
2. **IR report and hunts are written against the pre-hardening run.** They describe and interrogate the attack chain as it fired against the un-hardened baseline. They do not wait on hardening.
3. **Hardening comes after.** Applied bundle-by-bundle, each bundle followed by a kill-chain re-run, snapshot, and a row in the coverage matrix. The coverage matrix is the only artifact that spans before and after.

So the build order is: L1 sharpening + L2 (IR + hunts) against the pre-hardening run, then hardening, then the before/after coverage matrix.

---

## Layer 1 - Triage (investigations/)

Format already exists: alert -> questions -> queries -> verdict. v4 sharpens it by adding three mandatory elements to every case file.

**`v4/investigations/CASE-0X.md`**

Each case must explicitly state:

| Element | What goes in it |
|---|---|
| TP/FP decision | True positive or false positive, with the evidence that decided it |
| Severity | Assigned severity, and a line on why it was raised or lowered from the alert default |
| Escalation | What L1 hands to L2: the open questions, the artifacts collected, the scope still unknown |

The Escalation section is the one that matters most. It shows understanding of handoff, which is the part of the L1 role that candidates usually cannot demonstrate on paper.

**Scope:** keep the existing case count. Do not add new cases in v4.

---

## Layer 2 - Hunting and Incident Response

This is the layer that is currently missing. Two new artifacts.

### `v4/hunts/` - 2 to 3 threat hunt files

Proactive, not alert-driven. This is the distinction that defines the layer: the hunt starts from a hypothesis about attacker behavior, not from a fired alert.

**Format per hunt file:**

1. **Hypothesis** - the behavioral assumption being tested, stated as a claim that can be proven or disproven
2. **Hunt query** - the actual Splunk/Sigma query, with a note on which data source and why that source was chosen
3. **Finding** - what came back, including a negative result if the hypothesis did not hold
4. **Recommendation** - detection rule, hardening change, or "no action, hypothesis disproven"

**Hunt selection rule: hunt the gaps, not the wins.**

A hunt that re-describes an alert that already fired is triage in reverse, not a hunt. The existing detections already fired on Kerberoasting (CASE-02) and on the Sliver C2 JA4 fingerprint (CASE-07); re-running those as "hunts" would violate the proactive definition above. The strongest hunt material is where the detection did **not** fire, and this lab already has two documented blind spots:

- **Password spray residual gap** (v4 README addendum). Hypothesis: failed-then-successful auth from a single source across many accounts leaves a pattern that the per-account lockout logic does not surface. Hunt across authentication events for the spray signature the detection missed. Expected: partial / negative, which is the honest and useful result.
- **C2 over an allowed path.** Hypothesis: a beacon that lives under an allowlisted directory (the AppData path the C2 Beacon CIM search still cannot scope) evades the process-location logic. Hunt on beacon *behavior* instead of location: JA4/JA3 fingerprint rarity, connection-interval regularity, bytes-out to bytes-in ratio. This is why the C2 Beacon CIM search still ships unscheduled - the hunt documents the gap the scheduled rule cannot yet close.
- **Optional third:** any other point in the v4 attack chain where the kill chain succeeded but nothing fired.

A hunt that disproves its hypothesis, or that proves a gap is real, is a valid hunt file. Write it up as such - a negative result that names a concrete detection gap is worth more than a positive result that repeats a rule that already works.

### `v4/incident-report.md` - one IR timeline for the full v4 run

Not seven separate alerts. One narrative covering the entire pre-hardening run (the run captured by the `v4-pre-hardening` baseline).

**Sections:**

| Section | Content |
|---|---|
| Executive summary | What happened, in five sentences, written for someone who will not read the rest |
| Timeline | What happened when, across all five data sources, correlated into a single sequence |
| Blast radius | What was compromised: accounts, hosts, data. What was reached but not compromised. What was never touched |
| Correlation | How the five sources combined to tell the story, and which single source would have been insufficient alone |
| Containment | What was done, in what order, and what the order cost |
| Lessons learned | Detection gaps found (including the two hunted above), response delays, what changes for v5 |

This is the incident scoping artifact, not alert triage. The difference a reader should see: a triage document answers "is this real," an IR report answers "how far did it go." It must not duplicate the v3 `investigations/` case files - those are per-alert; this is one correlated story across all five sources.

---

## Layer 3 - Detection Engineering

Already the strongest layer in content, but v4 adds the one artifact it is missing: a before/after measurement of hardening.

- `coverage-matrix.md` - the kill chain mapped to MITRE ATT&CK, with a column for the pre-hardening run and a column per hardening bundle. This is the only artifact that spans before and after, and it is built incrementally: one row updated after each bundle's kill-chain re-run.
- `detections/` - detection-as-code, Sigma rules. No structural change.

No CI/CD pipeline for this purpose. The coverage matrix carries the argument on its own.

**This layer is produced by the hardening phase, not before it.** The matrix cannot exist until the hardening bundles have been applied and the kill chain re-run against each. See Sequence, step 3.

---

## Hardening phase (produces the coverage matrix)

Applied after the pre-hardening IR report and hunts are written, so the "before" story is already documented from the clean baseline.

- Roll out **bundle by bundle**, not all at once: five GPO bundles.
- After each bundle: re-run the kill chain, snapshot, and record one column in `coverage-matrix.md` (what still fires, what the bundle broke for the attacker, what it broke for detection).
- Roll back to `v4-pre-hardening` if a bundle corrupts the baseline.

This is the work that turns "I built detections" into "I measured whether hardening moved the needle," which is the detection-engineering argument a reviewer actually wants.

---

## README

Put this line at the top of `v4/README.md`:

> This lab is readable at three levels: L1 triage (`investigations/`), L2 hunting and incident response (`hunts/`, `incident-report.md`), and detection engineering (`coverage-matrix.md`, `detections/`).

A reader then jumps to their own layer. An L1 recruiter sees triage immediately. The L2 and DE depth is there for whoever digs.

---

## Scope discipline

Two to three hunt files and one IR report. Not ten of each.

A lab with three clean layers beats a lab with three half-finished ones. Once the artifacts above exist and the coverage matrix is filled through the hardening run, v4 is closed.

---

## Relationship to BTL1

BTL1 modules cover phishing, SIEM, incident response, threat hunting, and digital forensics. The two new L2 artifacts exercise the hunting and IR modules directly, so the same work serves both the certification and the portfolio.
