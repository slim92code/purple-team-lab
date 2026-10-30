# CASE-01 — Password spray against MARVEL.LOCAL

| | |
| --- | --- |
| Alert | `V3 - Password Spray EC4771` (Splunk) on 20 Oct; shipped as `Purple - Password Spray (multi-user from one source)`, which was not deployed until 30 Oct |
| Fired | 20 Oct 2026, 11:31 (the ad-hoc search) |
| Severity | High |
| MITRE | [T1110.003 — Password Spraying](https://attack.mitre.org/techniques/T1110/003/) |
| Verdict | True positive. One account compromised, used 98 seconds later. |
| Handed to | [CASE-02](CASE-02-kerberoasting.md) |

## 1. What the alert showed

A burst of Kerberos pre-authentication failures (`4771`) against the domain controller:
five accounts, one source address `192.168.182.133`, inside a minute.

One source against many accounts is the spray pattern. A brute force is the inverse, one
account and many attempts.

![Spray, endpoint view](../screenshots/02_spray_windows_4771.png)

## 2. Questions

1. How many accounts, from how many sources, in what window? Spray, brute force, or a
   broken service account?
2. Does `192.168.182.133` belong in this domain?
3. Did anything succeed? `4771` only logs failures, so the alert cannot answer this.
4. Did lockout trigger, and if not, why not?
5. If something succeeded, what did that account do next?

## 3. Queries

Confirm the pattern and the source, Windows `4771`:

```spl
index=main EventCode=4771
| stats dc(Account_Name) as distinct_users values(Account_Name) as users by Client_Address
| where distinct_users > 3
```

One source, `192.168.182.133`, five accounts: `Administrator`, `Guest`, `SQLService`,
`fcastle`, `tstark`.

Zeek `kerberos.log` records both outcomes, so it answers question 3:

```spl
index=main source="*kerberos.log*" NOT _raw="#*" earliest="10/20/2026:11:31:00" latest="10/20/2026:11:31:20"
| rex field=_raw "^(?P<ts>\S+)\t\S+\t(?P<orig_h>\S+)\t\S+\t(?P<resp_h>\S+)\t\S+\t(?P<req_type>\S+)\t(?P<client>[^\t]+)\t(?P<service>[^\t]+)\t(?P<success>\S+)\t(?P<error_msg>\S+)"
| where req_type="AS" AND orig_h="192.168.182.133"
| dedup client
| table _time, orig_h, resp_h, client, success, error_msg
| sort _time
```

![Spray, network view](../screenshots/01_spray_zeek_kerberos.png)

Lockout policy, on the DC:

```
net accounts
```

Lockout threshold 5, duration 5 min, observation window 5 min. Minimum password length 7.

## 4. Findings

Seven accounts tried from `192.168.182.133` in 0.6 seconds, 11:31:09.718 to 11:31:10.319:

| Outcome | Accounts |
| ------- | -------- |
| Rejected at pre-authentication | `Administrator`, `SQLService`, `tstark`, `fcastle` |
| Unsupported encryption type | `Guest` |
| Unknown principal (does not exist) | `jsmith` |
| Succeeded | `pparker` |

Windows logged five of the six failures. The `jsmith` attempt produced no `4771` at all,
because Kerberos does not log one for an account that does not exist. The network layer saw
an attempt the endpoint log never recorded, so a spray detection built only on `4771`
undercounts the attacker's account list.

`192.168.182.133` holds no machine account and does not appear in normal authentication
traffic.

Lockout was configured and did not fire. The threshold is 5 failures per account; the spray
sent one attempt per account. That is what spraying is built to do.

## 5. Verdict

True positive. A spray from a non-domain host recovered valid credentials for `pparker`, a
standard domain user. The lockout policy was not bypassed or broken, it was designed around.

One limitation, surfaced when the shipped rule was re-run on 30 Oct and recorded in its own
description: `Purple - Password Spray` counts distinct accounts that emit a `4771` and needs
five, but this estate yields only four (`jsmith` is an unknown principal and emits none;
`Guest` emits `0xE` only while enabled). On 20 Oct `Guest` supplied the fifth, so the
detection was a clean true positive. With `Guest` since disabled, a repeat spray produced
four and the rule stayed silent — it is validated in principle but not reliably exercisable in
this lab. The threshold stays at five; detections are not tuned down to a lab's account count.

## 6. What the account did next

```spl
index=main host=HYDRA-DC EventCode=4769
| search Service_Name=SQLService
| table _time, Account_Name, Service_Name, Ticket_Encryption_Type, Client_Address
```

At 11:32:48, 98 seconds after the spray succeeded, `pparker` requested a service ticket for
the `SQLService` SPN from the same address. That is Kerberoasting, handed off as
[CASE-02](CASE-02-kerberoasting.md).

`SQLService` is a Domain Admin with an SPN, so the roast leads to domain compromise. The
spray alert is the first link of that chain, not a low-severity hygiene finding.

## 7. Recommendations

Containment:

1. Reset `pparker`, revoke existing Kerberos tickets, review all authentications from that
   account since 11:31.
2. Treat `192.168.182.133` as hostile. Block it and hunt for other traffic from it.
3. The spray reached a DA-owned SPN within two minutes, so treat `SQLService` as
   potentially compromised and prioritise CASE-02.

Detection tuning:

4. The rule keys on `4771` and a distinct-account threshold. Add the Zeek `kerberos.log`
   view so successes and unknown-principal attempts are visible. As written, the alert
   cannot tell the analyst whether anything worked.
5. Alert on the pattern rather than the volume. N distinct accounts from one source in a
   short window already fires at five, but the `jsmith` miss shows the real account list is
   larger than the alert reports.

Hardening:

6. Minimum password length is 7. Raise it. The recovered password was crackable from a
   standard wordlist.
7. Lockout at 5 does not stop a one-attempt-per-account spray. Add a detection for the
   low-and-slow pattern and consider a longer observation window.
8. `SQLService` is a human-managed Domain Admin with an SPN. Move it to a gMSA and remove
   the SPN from any account holding Tier 0 rights.
