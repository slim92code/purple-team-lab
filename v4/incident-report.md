# Incident report — MARVEL.LOCAL, 6 November 2026

**Scope:** the v4 before-run. A full intrusion chain executed against the un-hardened estate, to
establish the detection baseline the hardening run will be compared against.

This report answers **how far it went**. Whether each individual alert was real is answered in
[the case files](investigations/); which rule fired and why is in
[the coverage matrix](coverage-matrix.md). Neither is repeated here.

---

## Executive summary

An attacker with network access to the domain enumerated accounts, found a valid credential by
password spray, used it to extract and crack a service-account key, moved laterally between two
workstations, dumped credentials from memory, established persistence, and exfiltrated 85 MB over
two address families.

**The intrusion ran for six hours and thirty-four minutes.** It was detected thirty-seven minutes
in. Nothing responded, at any point, because none of the rules that fired were configured to
notify anyone.

| | |
| --- | --- |
| First attacker action | 11:03:15 — account enumeration |
| First true-positive alert | 11:40 — password spray correlation, **37 minutes later** |
| Last measured attacker action | 17:37:37 — 55 MB exfiltration |
| Total duration | **6 h 34 min** |
| Hosts compromised | **2 of 3** Windows endpoints |
| Credentials compromised | **2 confirmed** (`fcastle`, `SQLService`), plus unmeasured LSASS yield |
| Accounts protected by a control | **1** — `tstark`, locked out and never compromised |
| Steps that produced an alert | **6 of 9** |
| Steps that produced a **response** | **0 of 9** |

**The single most consequential finding is not a detection gap.** Six attacker actions generated
alerts, correctly, within minutes. Every one of them went into a list nobody was reading: the
shipped detection pack sets alert tracking and throttling and ships no notification action, and
the one rule on the instance that fires most often is in a private namespace with no action
configured at all. **Detection worked and response did not exist.** An estate that detects an
intrusion in thirty-seven minutes and lets it run for another six hours has a response problem,
not a detection problem.

**Second: the attack was detected at its ends and not in its middle.** The steps that acquired
things — a service ticket, a credential from memory, a scheduled task, an outbound transfer —
alerted. The steps that *used* what was acquired — the stolen ticket, the lateral session, the
internal data pull — did not. An analyst reading only the alert queue would see a Kerberoast on
one host and an exfiltration from another four hours later, with no visible connection between
them.

---

## Timeline, correlated across five sources

`S` Splunk/Windows · `Z` Zeek · `W` Wazuh · `U` Suricata · `Y` Sysmon. **Bold** = an alert fired.

| Time | Action | Seen by | Alert |
| ---- | ------ | ------- | ----- |
| 11:03:15 | Account enumeration, 58 names, 1 valid (`administrator`) | **Z** 57 unknown principals · U `krb5` only | — |
| 11:32:00–01 | Password spray, 8 principals, `fcastle:Password1` **succeeds** | Z 8 principals · S 3 countable failures + 1 success · W `60104` ×16 | **S 11:40** · **W `60205` L10** |
| 11:32:05–06 | Brute force against `tstark` → **account locked** | S `4740` ×2 · Z 5 `CLIENT_REVOKED` | **W `60115` L9** · S returns rows |
| 11:48:12.37–.38 | Kerberos negotiation advertises RC4 | **U** `weak_encryption` ×2 | U has no signature action |
| 11:48:12.382 | TGS request, `fcastle` → `SQLService` | **Z** | Sigma content, not deployed |
| 11:48:12.502 | TGT issued to `fcastle` at **RC4** | S `4768` `0x17` | — |
| 11:48:12.513 | Service ticket for `SQLService` at AES-256 | S `4769` `0x12` | **S 11:50** |
| *(offline)* | `SQLService` key cracked from the ticket | — | — |
| 12:04:15–12:09:15 | C2 beacon from SPIDERMAN, 11 TLS handshakes, 30 s ± 24 s | Z JA4 · Y `EventCode=3` ×12, one destination | **S 12:10 ×2** |
| **12:21:45.874** | **Pass-the-Ticket** — `SQLService` TGT from SPIDERMAN, RC4, successful | S `4768` · Z | **none** |
| **12:23:39–41** | **WinRM pivot**, SPIDERMAN → THEPUNISHER, 4 sessions | Z `conn.log` 5985 | **none** |
| **16:24:38–39** | **6.59 MB pulled back** to SPIDERMAN over WinRM | Z `conn.log` | **none** |
| 16:40–17:45 | Implant written to `C:\Temp` on THEPUNISHER | **W** `92203`, `92213` **L15** | W, highest severity of the run |
| 16:48 | C2 beacon from THEPUNISHER, 1 handshake | Y · Z (below threshold) | S `#2` has it |
| 17:06:06.9 / .207 | LSASS opened from `notepad.exe`, `0x1410` then `0x1f3fff` | Y | **S 17:10** · **W `100200` L12** |
| 17:19:10.442 | Scheduled task `\Updater` with a download cradle, as SYSTEM | S `4698` | **S 17:20** · **W `100210` L12** |
| 17:27:09 | **Exfiltration** 15 MB → C2 `:8080` over IPv4 | Z · U `flow`/`http`/**`fileinfo`** | S `#15` returns rows |
| 17:37:22 | Exfiltration 15 MB → C2 `:8081` over IPv6 | Z | S `#15` |
| 17:37:37 | Exfiltration **55 MB** → C2 `:8081` over IPv6 | Z | S `#15` |

**Three independent sensors agree on the roast to within 140 ms** — Suricata at `.373`/`.384`,
Zeek at `.382`, the DC's own log at `.502` and `.513`. Nothing in this timeline needed manual
correlation to establish; the sensors agree where they overlap.

---

## Blast radius

### Compromised

| Asset | How | Evidence |
| ----- | --- | -------- |
| **SPIDERMAN** | Initial implant; C2 from 12:04; staging point for the 6.59 MB pull | JA4 beacon, `EventCode=3` from `C:\Temp` |
| **THEPUNISHER** | Reached by WinRM at 12:23 using the stolen `SQLService` ticket; implant dropped; LSASS dumped; persistence installed; exfiltration source | Wazuh L15 drop, `0x1f3fff` LSASS open, `4698`, 85 MB outbound |
| **`fcastle`** | Password spray — `Password1` | `4768` success at 11:32:01 |
| **`SQLService`** | SPN roasted, ticket cracked offline, ticket replayed | `4769` at 11:48, `4768` from the wrong host at 12:21 |
| **LSASS contents, THEPUNISHER** | `SharpKatz` via `execute-assembly`, full access mask | `GrantedAccess 0x1f3fff` |

The LSASS yield is **not measured**. The dump succeeded and what it returned was never
enumerated, so every account with a session on THEPUNISHER at 17:06 must be treated as
potentially compromised. That is a real limit of this report, not a formality.

### Reached but not compromised

**HYDRA-DC**, the domain controller. Every Kerberos request in this chain went to it — the
enumeration, the spray, the roast, the Pass-the-Ticket — and it answered all of them correctly.
It was *used* throughout and never *compromised*: no code ran on it, no session was established,
and a DCSync attempt in an earlier run failed at RPC 1825.

That distinction matters for scoping. A timeline that lists the DC on eight rows invites the
reading that the DC fell. It did not. It behaved exactly as a KDC should, which is also why it is
the source of most of the evidence against the attacker.

### Protected by a control

**`tstark`** — brute-forced at 11:32:05 and **locked out after five failures**, by a fine-grained
password policy in force since June. Six wrong passwords were offered; the account stopped
answering. This is the only point in the chain where a preventive control stopped something, and
it worked.

### Never touched

The monitoring estate: the Zeek/Suricata sensor host, the Wazuh manager, the Splunk indexer. No
attempt was made against any of them, and all three continued producing the evidence in this
report throughout — with one exception already on record: the Wazuh manager's disk had filled
during an earlier window, which is why its rules have a shorter measured baseline than the rest.

---

## Which single source would have been insufficient

Every one of them. The interesting part is *how* each fails, because the failures do not overlap.

| Source alone | Would have seen | Would have missed |
| ------------ | --------------- | ----------------- |
| **Windows / Splunk** | roast, C2 path, LSASS, persistence, exfiltration volume | **the enumeration entirely** (no event is written), 5 of 8 spray principals, the lateral session, the internal pull |
| **Zeek** | enumeration, all 8 spray principals, roast, C2 fingerprint, lateral session, both exfiltrations, the internal pull | LSASS, persistence, the implant drop — no host visibility at all |
| **Wazuh** | spray, lockout **with the account name**, LSASS, persistence, the implant drop at severity 15 | the enumeration, the roast, exfiltration volume |
| **Suricata** | the RC4 negotiation, the exfiltrated **file itself** via `fileinfo` | everything else, and it raised no alert on anything — stock ruleset |
| **Sysmon** | C2 process and path on both hosts, LSASS access | all network volume, all Kerberos |

Two conclusions, and the second is the one worth carrying.

**The layers are complementary rather than redundant.** The enumeration exists only in Zeek. The
locked-out account name exists only in Wazuh. The exfiltrated file exists only in Suricata. The
process that opened LSASS exists only in Sysmon. Dropping any one layer removes a step from this
report.

**And the three unalerted steps were visible the whole time.** Pass-the-Ticket is in the Windows
log and in Zeek. The WinRM pivot is in Zeek. The internal 6.59 MB pull is in Zeek. **Not one of
them was missed for lack of telemetry.** They were missed because no rule reads what was already
collected — which makes this a detection-content gap, not a visibility gap, and a cheaper problem
than it looks.

---

## Containment

**None was performed, deliberately, and the estate is still compromised as this is written.**

The C2 sessions remain live. The persistence task remains installed. The implants remain on disk
on both endpoints. This is not an oversight: v4's deliverable is a before/after comparison, and
remediating the before-run would destroy the state the after-run is measured against.

**What that costs this report, stated rather than glossed:**

- There is no eradication or recovery phase to describe, so the usual IR arc stops at
  identification.
- **Dwell time cannot be reported.** The 6 h 34 min above is the span between the first and last
  *measured* actions, not between compromise and removal. Removal has not happened.
- The LSASS yield cannot be bounded by "credentials rotated at time T", because none were.
- Any reader wanting a containment timeline should treat its absence as the experiment's
  condition, not as the estate's response capability — which, separately, is zero.

**One state change did occur** and is recorded for completeness: `Clear-DnsServerCache -Force`
was run on HYDRA-DC after the Kerberos and exfiltration phases were measured. It affects name
resolution only and no measurement above depends on it.

**The planned action is reversion, not remediation.** The three Windows endpoints return to the
`v4-post-benign` snapshot before hardening begins — which removes the implants, the persistence
and the attack artefacts in one step, and is also the only way to prevent the leftover scheduled
task from making a hardening measurement look like a detection.

**Rollback scope is three hosts, never seven.** Reverting Splunk or the sensors would erase the
evidence this report is built from.

---

## Gaps

Each of these is measured and written up elsewhere; this is the scoping view, in order of what it
would cost an estate.

| Gap | Consequence here |
| --- | ---------------- |
| **No notification action anywhere** | Six correct alerts, zero responses, six hours of unopposed activity |
| **No Pass-the-Ticket rule in any layer** | The step that turned a cracked key into access to a second host is invisible to content, not to telemetry |
| **The lateral session's rule is not deployed** | Sigma content exists, its logic matches, nothing on this estate runs it |
| **Kerberos enumeration has no rule on the only layer that sees it** | 58 principals on the wire, nothing acts on them. [HUNT-01](hunts/HUNT-01-spray-without-the-4771-count.md) establishes that one rule would also close the spray gap |
| **Internal data staging is not measured at all** | 6.59 MB moved host-to-host an hour before the exfiltration, by design outside the volume rule's scope |
| **One scheduled rule is in no inventory** | It fired 28 times in seven days, more than every documented rule combined, and notified nobody |

Two hunts were run against these rather than against the alerts that worked, and both produced a
**disproof** more useful than their proof:
[the industry-default spray signal returns zero events on this estate](hunts/HUNT-01-spray-without-the-4771-count.md),
and
[the industry-default beacon signal ranks a Microsoft sync client as more regular than a live C2 implant](hunts/HUNT-02-beacon-by-behaviour-not-path.md).

**Nothing above has been fixed.** Every change is held until after the hardening run, because
altering a rule between the before and after columns destroys the comparison those columns exist
to produce. The list of what is owed, and why each item waits, is in
[the matrix](coverage-matrix.md#still-owed-to-this-matrix).

---

## What an outside reader should take from this

An estate with five telemetry sources, eighteen shipped detections and a documented methodology
detected this intrusion in thirty-seven minutes and did nothing about it for six hours.

The reason is not sophistication on the attacker's part. Two of the nine steps used nothing but
ordinary Kerberos and ordinary remote management, and the rest were caught. The reason is that
**detection and response are separate problems and only one of them had been built**, and that a
coverage review which counts rules — eighteen shipped, fifteen scheduled — measures the one that
had been.
