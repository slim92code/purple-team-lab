# CASE-03 — Pass-the-Ticket with the cracked service account

| | |
| --- | --- |
| Alert | `4768` TGT request, reviewed during the CASE-02 hunt |
| Fired | 20 Oct 2026, 12:38 |
| Severity | High |
| MITRE | [T1550.003 — Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/) |
| Verdict | True positive. Domain Admin credential in use from a workstation. |
| Handed from | [CASE-02](CASE-02-kerberoasting.md) |

## 1. What the alert showed

A Kerberos TGT (`4768`) requested **for** `SQLService`, sourced from `192.168.182.138`
(SPIDERMAN), with encryption type `0x17` (RC4).

![TGT for SQLService](../screenshots/04_pass_the_ticket_4768.png)

Two details make this worth opening. The request is for a service account, and it comes
from a workstation rather than from the host that runs the service.

## 2. Questions

1. Does `SQLService` normally authenticate from SPIDERMAN?
2. Why is this `4768` and not `4769`, and why RC4 when the domain issues AES?
3. Is this the roast repeating, or the cracked credential being used?
4. What did the ticket get used for after it was issued?

## 3. Queries

```spl
index=main host=HYDRA-DC EventCode=4768
| search Account_Name=SQLService
| table _time, Account_Name, Client_Address, Ticket_Encryption_Type, Ticket_Options
```

Baseline, where this account normally authenticates from:

```spl
index=main EventCode=4768 OR EventCode=4624 Account_Name=SQLService earliest=-30d
| stats count values(Client_Address) as sources by Account_Name
```

Correlate with what ran on SPIDERMAN at that moment:

```spl
index=main host=SPIDERMAN source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  earliest="10/20/2026:12:35:00" latest="10/20/2026:12:42:00"
| table _time, Image, ParentImage, CommandLine
```

## 4. Findings

| | |
| --- | --- |
| Event | `4768`, TGT issued |
| Principal | `SQLService` |
| Source | `192.168.182.138` (SPIDERMAN), a workstation |
| Encryption type | `0x17` (RC4) |
| Time | 12:38, roughly 66 minutes after the roast |
| Tooling | Rubeus `asktgt /user:SQLService`, run in memory via Sliver `execute-assembly` |

**`4768` rather than `4769` is the tell.** A roast requests a *service* ticket, which is
`4769`. This is a request for a *ticket-granting* ticket in the service account's name,
which means the attacker already holds its credential and is authenticating as it. The
sequence of event IDs separates the theft from the use.

**RC4 here is the tool, not the domain.** The domain issues AES for service tickets, as
CASE-02 established with 1,649 `0x12` tickets and zero RC4. Rubeus requested RC4 by default.
On a domain that otherwise never produces `0x17`, a single RC4 TGT is anomalous on its own,
which makes it a usable signal even though the equivalent `4769` rule is dead here.

**The source is wrong for the account.** `SQLService` is a service identity. A TGT request
for it from a user workstation is not something the service itself does.

![Rubeus ticket imported](../attack/07_ptt_ticket_imported.png)

## 5. Verdict

True positive. The credential cracked in CASE-02 was used to request and inject a TGT for
`SQLService` on SPIDERMAN. The attacker is now operating as a Domain Admin without having
touched the account's password interactively.

## 6. What the account did next

Four minutes later, at 12:42, the injected ticket was used for a Kerberos-authenticated
WinRM session from SPIDERMAN to THEPUNISHER. Handed off as
[CASE-04](CASE-04-lateral-movement-winrm.md).

## 7. Recommendations

Containment:

1. Reset `SQLService` again after containment, since any ticket issued before the reset
   stays valid for its lifetime.
2. Revoke existing Kerberos tickets rather than relying on the password change alone.
3. Isolate SPIDERMAN. The implant that ran Rubeus in memory is still present at this point
   in the timeline.

Detection tuning:

4. Alert on `4768` where the principal is a service account and the source is not the host
   that runs the service. Build the account-to-host mapping once and alert on exceptions.
5. Where AES is the norm, alert on any `0x17` ticket regardless of event ID. There were
   zero legitimate RC4 service tickets here across 30 days, so the false-positive cost is
   close to nothing. Note this domain is not AES-*only*: this `4768` is proof RC4 is still
   issued on request, which is exactly why the alert is worth having and why
   recommendation 8 below is the durable fix.
6. Correlate `4769` for an SPN with a later `4768` for the same principal from a different
   source. That pair is the roast and the reuse, and it is stronger than either alone.

Hardening:

7. Add `SQLService` to Protected Users once it is a gMSA, which blocks RC4 and NTLM for it
   and shortens ticket lifetime.
8. Set `msDS-SupportedEncryptionTypes` to AES-only per account so a downgrade request fails
   rather than succeeding quietly.
9. Credential Guard on the endpoints raises the cost of in-memory ticket injection.
