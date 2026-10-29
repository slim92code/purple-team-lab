# Alert triage — case files

What an analyst did when each alert fired. Seven cases covering the v3 kill chain, written
in one format: the alert, the questions asked, the queries run, what was found, the verdict,
and the tuning and hardening that follows.

They chain. Each one hands off to the next in the order the attack actually ran.

| Case | Phase | MITRE | Verdict |
| ---- | ----- | ----- | ------- |
| [CASE-01](CASE-01-password-spray.md) | Password spray | T1110.003 | True positive, one account compromised |
| [CASE-02](CASE-02-kerberoasting.md) | Kerberoasting | T1558.003 | True positive, Domain Admin credential cracked |
| [CASE-03](CASE-03-pass-the-ticket.md) | Pass-the-Ticket | T1550.003 | True positive, stolen ticket in use |
| [CASE-04](CASE-04-lateral-movement-winrm.md) | Lateral movement | T1021.006 | True positive, workstation-to-workstation pivot |
| [CASE-05](CASE-05-lsass-access.md) | LSASS access | T1003.001 | True positive on one host, undetectable on the other at the time (both causes since closed — see the case) |
| [CASE-06](CASE-06-persistence-scheduled-task.md) | Persistence | T1053.005 | True positive delivered at level 4 |
| [CASE-07](CASE-07-c2-beaconing.md) | C2 beaconing | T1071.001 | True positive, two endpoints linked by one fingerprint |

## What the set is for

Detections are half the job. The other half is what happens when one fires, and that is the
part a SOC role is actually measured on.

Three of these cases are about detections that did not work, which is why they are here
rather than summarised away:

- **CASE-02.** The canonical Kerberoasting rule keys on RC4. This domain issues AES, 1,649
  tickets to zero over 30 days, so the rule has never had an input.
- **CASE-05.** A deployed EDR, a built-in rule at level 12, and a custom rule written for
  this exact technique. None of the three would have told an analyst that credentials were
  being read out of memory, for four different reasons.
- **CASE-06.** Everything worked. The event arrived, parsed and alerted, at the same
  severity as a OneDrive updater, which put it below where anyone looks.

Each of those was found by measuring rather than by reading the rule, and each fix is
verified by triggering the condition rather than by the absence of alerts.
