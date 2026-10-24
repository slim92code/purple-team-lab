# Lab v3 — Network Detection and Host EDR Layers

> The full technical report is in Serbian:
> [`Purple_Team_izvestaj_v3_SR.pdf`](Purple_Team_izvestaj_v3_SR.pdf).
> This page is the English summary.
> Repo entry point: [root README](../README.md).

> **Note on the report.** The PDF records the lab as it stood during the run (20 Oct 2026).
> One of its statements no longer matches: it reports that THEPUNISHER's Wazuh agent has no
> Sysmon `localfile` block, but that block is present today and forwarding began at
> **12:08 on 20 Oct**, part-way through the run. The statement still holds for SPIDERMAN and
> HYDRA-DC. This page carries the state verified against all three agents' `ossec.conf`,
> their live Sysmon configuration, and every archived alert file; see
> [Known gaps](#known-gaps-carried-into-v4).

v3 adds two detection layers on top of the [v2](../v2/) Sysmon + Splunk baseline: network
detection (Zeek + Suricata) and host EDR (Wazuh). Five telemetry sources now feed one SIEM —
Windows Security log, Sysmon, Wazuh, Zeek, and Suricata, all into Splunk. The same Active
Directory kill chain was re-run and each phase evaluated against every source.

## Infrastructure

![Topology and detection flow](topology.svg)

| Host | Address | Role |
| ---- | ------- | ---- |
| HYDRA-DC | `.135` | Windows Server 2022 — AD DS, `MARVEL.LOCAL` |
| SPIDERMAN | `.138` | Windows 10 endpoint |
| THEPUNISHER | `.137` | Windows 10 endpoint |
| Splunk | `.131` | Splunk 10.2 SIEM |
| Wazuh | `.150` | Wazuh 4.12 manager — 3 Windows agents, Sysmon from 1 of them ([why](#known-gaps-carried-into-v4)) |
| security-vm | `.151` | Zeek + Suricata |
| Kali | `.133` | Attacker |

## Hardening baseline (as-built)

Not a default install. The Windows estate carries a host-firewall segmentation mesh and SMB
hardening applied before the run, so the kill chain had to work through it.

**Host-firewall segmentation** — inbound block rules, one set per host:

| Host | Blocks inbound |
| ---- | -------------- |
| HYDRA-DC | Kali → SMB, Kali → WMI |
| THEPUNISHER | SPIDERMAN → SMB, Kali → WMI |
| SPIDERMAN | THEPUNISHER → SMB, Kali → WMI |

The attacker is denied WMI on every host and SMB to the DC; the two endpoints cannot reach
each other over SMB. On top of that: SMBv1 removed on all three hosts (signing required on
the DC), account lockout at 5 attempts, and RemoteRegistry plus a set of discovery/legacy
services disabled on the endpoints.

**Where it held, where it leaked.** The mesh forced the attack off SMB and WMI — but WinRM
(5985) was left open, and that is the path the lateral movement took (detection screenshot
05). Prevention narrowed the attack surface without closing it, and the detection layer
caught what came through. That is the lab's thesis in a single move: hardening ≠ detection.

**Residual gaps — deliberate, and the v4 before-state:**

| Gap | Consequence | In v4 |
| --- | ----------- | ----- |
| WinRM open east-west | the lateral-movement path | kept by design — v4 tightens SMB/WMI around it, the pivot stays open and monitored |
| SMB signing only on the DC | endpoints accept unsigned SMB | v4 |
| Kali → SMB blocked only on the DC | endpoints reachable over SMB from the attacker | v4 |
| No LSA Protection (`RunAsPPL`) | LSASS dump succeeds — by design here, it is what screenshot 07 detects | v4 |
| WDigest / LLMNR not hardened | credential-exposure and name-poisoning surface | v4 |

## Kill chain and detection coverage

| Phase | Technique | Detected by |
| ----- | --------- | ----------- |
| Password spray | T1110.003 | Windows `4771`, Zeek `kerberos.log` |
| Kerberoasting | T1558.003 | Windows `4769`, Suricata `krb5`, Suricata `weak_encryption` |
| Pass-the-Ticket | T1550.003 | Windows `4768` TGT for `SQLService` (RC4), Zeek `kerberos.log` |
| Lateral movement (WinRM) | T1021.006 | Zeek `conn.log` port 5985, Suricata `REQUEST_AUTH_UNRECOGNIZED` |
| LSASS access | T1003.001 | Sysmon EID 10 (THEPUNISHER only — SPIDERMAN is a deliberate blind spot, screenshot 12) |
| Scheduled task persistence | T1053.005 | Windows `4698`, Wazuh rule `60228` (screenshot 13) |
| C2 beaconing | T1071.001 | Zeek `ssl.log` — JA4 TLS fingerprinting |

## Findings

**Network layer caught a spray attempt the endpoint log missed.** Zeek `kerberos.log`
recorded seven accounts tried from a single non-domain source inside 0.6 seconds: one
succeeded (`pparker`), four were rejected at pre-authentication, and two failed otherwise —
one unsupported encryption type (`Guest`), one unknown principal (`jsmith`). Windows `4771`
logged only five of the six failures: an unknown-principal attempt produces no `4771`, so
the network layer saw one spray attempt that never reached the endpoint log.

**One JA4 fingerprint linked two compromised endpoints.** Both endpoints beaconed to the
attacker host over TLS sharing an identical Sliver JA4 client fingerprint
(`t13i131000_f57a46bbacb6_e5728521abd4`) — 69 sessions from SPIDERMAN, 27 from THEPUNISHER.
The fingerprint survives a binary rename, so the detection does not depend on a filename or
hash.

**Wazuh scheduled-task alerting does not separate malicious from benign.** The `\Updater`
persistence task created on THEPUNISHER fired rule `60228` at level 4 — the same rule and
the same severity as a benign `\OneDrive Standalone Update Task` on the same host
(screenshot 13). Task creation is alerted on; task *content* is not evaluated.

**The EDR's only credential-access alert is a 100% false positive.** Wazuh's built-in rule
`92900` fires at **level 12** for any process reading LSASS with read permissions. Across
every archived alert file the lab has, it fired 32 times and **all 32 were benign** —
`MsMpEng.exe` (Defender, 29), `svchost.exe` (2), `MRT.exe` (1). Not one was the attack: the
SharpKatz read of LSASS never reached Wazuh at all. A high-severity alert that is wrong
every single time is worse than no alert, because it trains the analyst to close it.

**Wazuh's built-in LSASS rule has its severity inverted.** Rule `92900` carries its own
filter — `grantedAccess` must be `0x1010` or `0x40`. So the one credential-access alert the
EDR ships fires at level 12 for Defender's routine read, and is **silent** on a full-access
handle (`0x1fffff`) or a `MiniDumpWriteDump` mask (`0x1438`). Confirmed by experiment: a
PowerShell `OpenProcess` against `lsass.exe` with `PROCESS_ALL_ACCESS` produced no alert at
all from the default ruleset. Wrong every time on the benign mask, silent on the aggressive
ones. This also invalidated a draft of the replacement rule that hung off `92900` as its
parent — a child requiring a full-access mask is mutually exclusive with a parent that only
matches `0x1010`. The shipped rule binds to the `sysmon_event_10` group instead.

**Tuning a rule needs the baseline, not the attack.** A first draft of the replacement rule
matched access masks `0x1010` and `0x1410` alongside the full-access ones. Measured against
935 real `ProcessAccess` reads of `lsass.exe` sampled from THEPUNISHER's own Sysmon log,
that draft would have alerted **90 times, 89 of them benign** — `WmiPrvSE.exe` alone
accounts for 79 at `0x1410`, and `wazuh-agent.exe`, the EDR agent itself, reads LSASS at
`0x1fffff`. Restricting to full and `MiniDumpWriteDump` masks and excluding the platform
sources measured in that sample brings it to **one** alert: a `powershell.exe` read at
`0x1f3fff`, which is the only one that warrants triage.

## Attack chain

The red-team side of the run — spray, Kerberoasting, C2, Pass-the-Ticket, with Defender
enabled throughout — is documented with screenshots in [`attack/`](attack/). Each attack
step maps to the detection screenshots below.

## Detection screenshots

All times are from the 20 Oct 2026 run. Zeek queries parse the raw TSV with `rex` to show
log structure; in production the Zeek TA extracts these fields (see v4).

### 01 — Password spray, network view (T1110.003)
[![Spray Zeek](screenshots/01_spray_zeek_kerberos.png)](screenshots/01_spray_zeek_kerberos.png)
> Zeek `kerberos.log`: seven accounts from `192.168.182.133` in 0.6 s — `pparker` succeeds,
> `jsmith` fails as unknown principal (no Windows `4771` for that one, so the network layer
> sees an attempt the endpoint log misses).

### 02 — Password spray, endpoint view (T1110.003)
[![Spray 4771](screenshots/02_spray_windows_4771.png)](screenshots/02_spray_windows_4771.png)
> Windows `4771` correlation: single source `192.168.182.133`, five distinct accounts failing
> pre-authentication.

### 03 — Kerberoasting, AES service ticket (T1558.003)
[![Kerberoasting 4769](screenshots/03_kerberoasting_4769.png)](screenshots/03_kerberoasting_4769.png)
> `4769` for `SQLService`, `Ticket_Encryption_Type=0x12` (AES-256) requested by `pparker`
> from `192.168.182.133`. v3 uses AES, not the RC4 (0x17) of v2.

### 04 — Pass-the-Ticket, TGT for the cracked account (T1550.003)
[![TGT 4768](screenshots/04_pass_the_ticket_4768.png)](screenshots/04_pass_the_ticket_4768.png)
> `4768` TGT requested **for** `SQLService` from `192.168.182.138` (SPIDERMAN) at 12:38, RC4
> (`0x17`). This is after the roast and the offline crack — Rubeus `asktgt /user:SQLService`
> using the recovered credential, i.e. Pass-the-Ticket, not the roast itself.

### 05 — Lateral movement over WinRM (T1021.006)
[![WinRM Zeek](screenshots/05_lateral_winrm_zeek.png)](screenshots/05_lateral_winrm_zeek.png)
> Zeek `conn.log`: three connections `192.168.182.138 → 192.168.182.137` on port `5985`
> (WinRM) — SPIDERMAN pivoting to THEPUNISHER.

### 06 — Suricata application-layer anomalies
[![Suricata anomaly](screenshots/06_suricata_anomaly.png)](screenshots/06_suricata_anomaly.png)
> `weak_encryption` on the Kerberos exchanges and `REQUEST_AUTH_UNRECOGNIZED` during the
> 12:42–12:43 WinRM pivot.

### 07 — LSASS access, the real credential theft (T1003.001)
[![LSASS EID10](screenshots/07_lsass_sysmon_ec10.png)](screenshots/07_lsass_sysmon_ec10.png)
> Sysmon EID 10 on THEPUNISHER: `notepad.exe` accessing `lsass.exe` with `GrantedAccess
> 0x1F3FFF` (CRITICAL). The query excludes `MsMpEng.exe`/Defender, so Defender's own routine
> LSASS access is filtered out and the injected `notepad.exe` is what surfaces.

### 08 — Persistence, scheduled task (T1053.005)
[![Persistence 4698](screenshots/08_persistence_updater_4698.png)](screenshots/08_persistence_updater_4698.png)
> `4698` on THEPUNISHER: task `\Updater`, `powershell.exe -WindowStyle Hidden -c IEX(...
> update.ps1)` — the download cradle visible in the command fields.

### 09 — C2 beaconing, JA4 fingerprint (T1071.001)
[![JA4](screenshots/09_c2_ja4_fingerprint.png)](screenshots/09_c2_ja4_fingerprint.png)
> Zeek `ssl.log` filtered on the Sliver JA4 `t13i131000_f57a46bbacb6_e5728521abd4`:
> 69 beacons from SPIDERMAN and 27 from THEPUNISHER to the C2 at `192.168.182.133`.

### 10 — Kerberoasting via Suricata krb5, by signature not IP (T1558.003)
[![Suricata krb5](screenshots/10_suricata_krb5_kerberoasting.png)](screenshots/10_suricata_krb5_kerberoasting.png)
> Suricata `krb5` filtered on the Kerberoasting signature — service tickets whose SPN is
> neither `krbtgt` nor a machine account (`$`), so the filter keys on the attack pattern
> rather than the attacker's address. Three anomalous service tickets surface the whole
> credential-abuse chain: `pparker → SQLService` (the roast), `SQLService → HTTP/THEPUNISHER`
> (the cracked account reused), and `Administrator → cifs/HYDRA-DC`.

### 11 — Detection content shipped as alerts
[![V3 Alerts](screenshots/11_v3_alerts_enabled.png)](screenshots/11_v3_alerts_enabled.png)
> Six v3 saved alerts, all enabled: spray, Kerberoasting, LSASS, persistence, JA4 C2, and
> large outbound transfer.

### 12 — The SPIDERMAN LSASS blind spot, proven
[![Blind spot](screenshots/12_spiderman_lsass_blindspot.png)](screenshots/12_spiderman_lsass_blindspot.png)
> SPIDERMAN forwarded 1,191 Sysmon process-create events (EID 1) but **zero** ProcessAccess
> events (EID 10), while THEPUNISHER logged 629 EID 10. SPIDERMAN's Sysmon is alive and
> forwarding — its ProcessAccess layer is simply dark, so an LSASS dump on that host would
> not be seen. Confirmed from the live config rather than inferred from the absence:
> `sysmon64 -c` on SPIDERMAN shows `ProcessAccess  onmatch: include` with **no rule lines
> under it**, so the include list matches nothing. This is the deliberate blind spot from
> the coverage table, shown as an absence and then verified at the source. Confirmed on the
> host as well: grouping 5,000 recent Sysmon events on SPIDERMAN by event ID returns eleven
> distinct IDs — 1 (2,529), 13, 11, 3, 22, 5, 12, 2, 8, 255 and 4 — and **no EID 10 in the
> list at all**. THEPUNISHER, by contrast,
> carries exactly one `ProcessAccess` rule (`TargetImage is C:\Windows\system32\lsass.exe`),
> which is why the two hosts differ. The difference is the Sysmon config, not the agent.

### 13 — Wazuh EDR: the scheduled-task rule gap (T1053.005)
[![Wazuh rule gap](screenshots/13_wazuh_rule_gap_60228.png)](screenshots/13_wazuh_rule_gap_60228.png)
> On THEPUNISHER, Wazuh's built-in rule `60228` fired at level 4 for both the malicious
> `\Updater` task and a benign `\OneDrive Standalone Update Task` — same rule, same severity.
> Wazuh alerts on task *creation* but does not score task *content*, so the hidden PowerShell
> IEX download cradle inside `\Updater` (visible in screenshot 08) is treated no differently
> from a routine update. A tuned rule keying on the command would separate the two.

## Alert triage — case files

Detections are only half the job; the other half is what an analyst does when one fires.
[`investigations/`](investigations/) holds the triage write-ups for this run — alert,
questions asked, queries run, verdict, and the tuning and hardening recommendations.

- [**CASE-01 — Password spray**](investigations/CASE-01-password-spray.md) — true positive:
  seven accounts tried in 0.6 s from a non-domain host, one succeeded, and the compromised
  account was used to Kerberoast a Domain Admin SPN 98 seconds later. Account lockout was
  configured and never fired — the spray was built to stay under it.

## Shipped as detection-as-code

The v3 findings are not just screenshots — they are committed as deployable rules in
[`detections/`](../detections):

- [`sigma/v3_ndr.yml`](../detections/sigma/v3_ndr.yml) — Kerberoasting keyed on the user-SPN
  pattern (etype-agnostic, catches the AES roast an RC4-only rule misses), WinRM east-west
  lateral movement, and the Sliver C2 JA4 fingerprint.
- [`wazuh/local_rules.xml`](../detections/wazuh/local_rules.xml) — five rules covering both
  Wazuh gaps. `100210`/`100211` read the scheduled task's own definition and re-score a
  PowerShell download cradle or a hidden-window launcher, so `\Updater` no longer looks
  like a benign OneDrive task. `100200` alerts on a dump-capable `GrantedAccess` mask
  against `lsass.exe`; `100201` and `100205` suppress the platform processes measured in the
  baseline above — `100205` deliberately hangs off `92900` itself, so it also removes the
  32-for-32 false positive the built-in rule produces.

### Rule verification — 24 Oct 2026

Each rule was deployed and fired by a targeted trigger rather than assumed to work. Times
UTC; the Windows hosts run UTC+2.

| Rule | Trigger | Result |
| ---- | ------- | ------ |
| — | `wazuh-analysisd -t` | **clean** — the previous version raised `(7610)` and discarded its rule |
| `100200` | `OpenProcess(lsass, PROCESS_ALL_ACCESS)` from PowerShell | **level 12**, 11:42:39 |
| `100201` | 20 platform `ProcessAccess` reads forced through the chain | **0 alerts** |
| `100205` | `MsMpEng.exe` reading LSASS at `0x1010` | **0 alerts** (was level 12, 32/32) |
| `100210` | task with `IEX` + `DownloadString` | **level 12**, 11:48:57 |
| `100211` | task with `-nop -w hidden -enc` | **level 10**, 11:49:04 |
| *negative* | task running `defrag.exe C: /O` | stays `60228` **level 4** |
| *negative* | task running `powershell.exe -ExecutionPolicy Bypass -File …` | stays `60228` **level 4** |

The second negative test is the one that counts: a scheduled task that legitimately runs
PowerShell with `-ExecutionPolicy Bypass` is the realistic false positive for these rules,
and neither fired on it.

`100201` could not be triggered directly, because no platform process in this lab opens
LSASS with a full-access mask. It was tested by temporarily widening `100200` to include
`0x1000` — the mask `svchost.exe` and `MsMpEng.exe` use constantly — so ordinary platform
reads had to pass through the suppression chain. Twenty such events produced zero alerts;
the mask was then reverted.

## Known gaps carried into v4

- The hardening baseline above is partial and inconsistent by design — a realistic
  starting point, not a finished one. v4 rebuilds it to a CIS-aligned standard (consistent
  SMB signing, LSA Protection, WDigest/LLMNR off, and a GPO firewall baseline with a
  domain-isolation gate — WinRM east-west stays open on purpose as the monitored pivot) and
  re-runs the chain for a before/after coverage matrix.
- Account lockout is enforced (5 failures), but the spray sent a single attempt per
  account and so never reached the threshold — the standard way password spraying evades
  lockout. The weaker control is the 7-character minimum password length; v4 raises it.
- `SQLService` is a human-managed **Domain Admin** with an SPN, so the Kerberoasting roast
  cracks straight to Domain Admin — not a low-privilege service account. Its password was
  also stored in the account's AD `Description` field (T1552.001), a second, independent
  exposure. v4 moves it to a gMSA and clears the description.
- **The Wazuh gaps are fixed at the rule layer, not at the telemetry layer.** The tuned
  rules in [`detections/`](../detections/wazuh/local_rules.xml) are deployed and verified
  (see the table above), so the `\Updater` pattern now scores level 12 instead of 4 and a
  full-access LSASS handle alerts at all. What is **not** fixed is the ingestion gap below:
  the LSASS rule still only has telemetry on one of three hosts. A correct rule over missing
  data is still no coverage, which is the distinction this lab exists to make. Screenshot 13
  records the original behaviour, before the rules were written.
- **Wazuh receives Sysmon from one of three Windows agents.** Across every archived alert
  file: HYDRA-DC 51,725 alerts with **0** from Sysmon, SPIDERMAN 22,782 with **0**,
  THEPUNISHER 18,591 with **376** (32 of them `ProcessAccess`). Only THEPUNISHER carries a
  `Microsoft-Windows-Sysmon/Operational` block in its `ossec.conf`.
  The DC case is the sharpest: Sysmon **is** installed and running there and its log holds
  **43,683 events** — the Wazuh agent simply never reads the channel. So the EDR is blind to
  all of it while the agent reports healthy and busy. Any Wazuh-side Sysmon detection,
  including the LSASS rule, can only ever fire on one of three hosts. Agent count is not
  telemetry coverage, and nothing in the agent list shows the difference.
  The `4698` task rules are unaffected — the Security channel is configured on all three.
- **A custom rule that could not fire — and the tool had been saying so.** A custom LSASS
  rule was deployed against `<if_group>sysmon_event10</if_group>`. The real group name is
  `sysmon_event_10` — one missing underscore. `grep` over `/var/ossec/ruleset/rules/` returns
  nothing for the misspelling, and no alert in any archive has ever carried it. The rule
  matched nothing and alerted zero times, ever. Its silence
  was first read as "no attack has been run since it was added" — which was *also* true, so
  two independent causes produced the same zero and the harmless one masked the real one.
  What settles it is that Wazuh had been reporting the fault all along:

  ```
  wazuh-analysisd: WARNING: (7610): Group 'sysmon_event10' was not found.
  Invalid 'if_group'. Rule '100200' will be ignored.
  ```

  One `wazuh-analysisd -t` would have shown that at any point. The lesson is not the typo —
  it is that a silent rule was counted as coverage without ever asking the engine whether it
  had loaded. A rule that cannot fire is worse than a missing one, because it reports as
  coverage. Rewritten against `<if_sid>92900</if_sid>`, a parent SID that demonstrably fires
  here and does not get renamed between ruleset versions. That replacement was itself wrong
  and was caught the same way — by testing it. `92900` only matches `0x1010` and `0x40`, so a
  child of it requiring a full-access mask could never fire either. The shipped rule binds to
  `<if_group>sysmon_event_10</if_group>`, and the fix is proven by a controlled before/after:
  the same trigger, from the same host, with the same mask, six minutes apart — 0 alerts
  under the old parent, level 12 under the new one, with Sysmon recording both events.
