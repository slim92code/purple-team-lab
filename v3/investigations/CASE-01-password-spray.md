# CASE-01 — Password spray against MARVEL.LOCAL

| | |
| --- | --- |
| **Alert** | `V3 - Password Spray EC4771` (Splunk, scheduled) |
| **Fired** | 20 Oct 2026, 11:31 |
| **Severity** | High |
| **MITRE** | [T1110.003 — Password Spraying](https://attack.mitre.org/techniques/T1110/003/) |
| **Verdict** | **True positive — one account compromised, used within 98 seconds** |

---

## 1. What the alert showed

A burst of Kerberos pre-authentication failures (`4771`) against the domain controller:
five distinct accounts, all from a single source address `192.168.182.133`, inside one
minute. One source hitting many accounts is the spray signature — the inverse of a
brute-force, where one account takes many attempts.

![Spray, endpoint view](../screenshots/02_spray_windows_4771.png)

## 2. Questions I asked

1. How many accounts, from how many sources, in what window? (Spray vs. brute force vs. a
   broken service account.)
2. Is `192.168.182.133` a host that belongs in this domain?
3. **Did any attempt succeed?** `4771` only logs failures, so the alert cannot answer this
   on its own.
4. Did account lockout trigger — and if not, why not?
5. If something succeeded, what did that account do next?

## 3. Queries I ran

**Confirm the pattern and the source** — Windows `4771`:

```spl
index=main EventCode=4771
| stats dc(Account_Name) as distinct_users values(Account_Name) as users by Client_Address
| where distinct_users > 3
```

→ One source, `192.168.182.133`, five accounts: `Administrator`, `Guest`, `SQLService`,
`fcastle`, `tstark`.

**Find the successes the endpoint log cannot show** — Zeek `kerberos.log` records both
outcomes, so it answers question 3:

```spl
index=main source="*kerberos.log*" NOT _raw="#*" earliest="10/20/2026:11:31:00" latest="10/20/2026:11:31:20"
| rex field=_raw "^(?P<ts>\S+)\t\S+\t(?P<orig_h>\S+)\t\S+\t(?P<resp_h>\S+)\t\S+\t(?P<req_type>\S+)\t(?P<client>[^\t]+)\t(?P<service>[^\t]+)\t(?P<success>\S+)\t(?P<error_msg>\S+)"
| where req_type="AS" AND orig_h="192.168.182.133"
| dedup client
| table _time, orig_h, resp_h, client, success, error_msg
| sort _time
```

![Spray, network view](../screenshots/01_spray_zeek_kerberos.png)

**Check the lockout policy** — on the DC:

```
net accounts
```

→ Lockout threshold 5, duration 5 min, observation window 5 min. Minimum password length 7.

## 4. What I found

Seven accounts were tried from `192.168.182.133` in **0.6 seconds** (11:31:09.718 →
11:31:10.319):

| Outcome | Accounts |
| ------- | -------- |
| Rejected at pre-authentication (wrong password) | `Administrator`, `SQLService`, `tstark`, `fcastle` |
| Unsupported encryption type | `Guest` |
| Unknown principal (account does not exist) | `jsmith` |
| **Succeeded** | **`pparker`** |

Three things worth recording:

- **The alert under-counted.** Windows logged five of the six failures. An unknown-principal
  attempt (`jsmith`) produces no `4771` at all, so the network layer saw one attempt the
  endpoint log never recorded. A spray detection built only on `4771` undercounts the
  attacker's account list.
- **The source is not a domain host.** `192.168.182.133` holds no machine account and
  appears nowhere in normal authentication traffic.
- **Lockout was configured and still did not fire.** The threshold is 5 failures per
  account; the spray sent **one** attempt per account. This is the defining property of
  spraying — it is built to stay under exactly this control.

## 5. Verdict

**True positive.** A password spray from a non-domain host recovered valid credentials for
`pparker` (a standard domain user). The lockout policy was not bypassed or broken — it was
designed around.

## 6. What the account did next

A successful spray is not the end of the alert; it is the start of a hunt. I pivoted on the
compromised account:

```spl
index=main host=HYDRA-DC EventCode=4769
| search Service_Name=SQLService
| table _time, Account_Name, Service_Name, Ticket_Encryption_Type, Client_Address
```

**11:32:48 — 98 seconds after the spray succeeded** — `pparker` requested a service ticket
for the `SQLService` SPN from the same address: Kerberoasting — handed off as CASE-02.

`SQLService` is a **Domain Admin** with an SPN, so that roast leads straight to domain
compromise. The spray alert is therefore not a low-severity hygiene finding — it is the
first link of a chain that ends at Tier 0.

## 7. Recommendations

**Immediate (containment)**

1. Reset `pparker`, revoke existing Kerberos tickets, and review all authentications from
   that account since 11:31.
2. Treat `192.168.182.133` as hostile — block and hunt for other traffic from it.
3. Because the spray reached a DA-owned SPN within two minutes, treat `SQLService` as
   potentially compromised and prioritise CASE-02.

**Detection tuning**

4. The current rule keys on `4771` and a distinct-account threshold. Add the Zeek
   `kerberos.log` view so successes and unknown-principal attempts are visible; as written,
   the alert cannot tell the analyst whether anything worked.
5. Alert on the pattern rather than the volume: *N distinct accounts from one source inside
   a short window* already fires at five, but the `jsmith` miss shows the account list is
   larger than the alert reports.

**Hardening**

6. Minimum password length is 7 — raise it. The recovered password was crackable from a
   standard wordlist.
7. Lockout at 5 does not stop a one-attempt-per-account spray. Add a detection for the
   low-and-slow pattern instead of relying on lockout, and consider a longer observation
   window.
8. `SQLService` is a human-managed Domain Admin with an SPN. Move it to a gMSA and remove
   the SPN from any account that holds Tier 0 rights.
