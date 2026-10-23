# Lab v3 — Network Detection and Host EDR Layers

> The full technical report is in Serbian:
> [`Purple_Team_izvestaj_v3_SR.pdf`](Purple_Team_izvestaj_v3_SR.pdf).
> This page is the English summary.
> Repo entry point: [root README](../README.md).

v3 adds two detection layers on top of the [v2](../v2/) Sysmon + Splunk baseline, taking
the lab to five: Windows Security log, Sysmon, Splunk SIEM, Wazuh EDR, and Zeek + Suricata
network detection. The same Active Directory kill chain was re-run and each phase evaluated
against all five layers.

## Infrastructure

![Topology and detection flow]

| Host | Address | Role |
| ---- | ------- | ---- |
| HYDRA-DC | `.135` | Windows Server 2022 — AD DS, `MARVEL.LOCAL` |
| SPIDERMAN | `.138` | Windows 10 endpoint |
| THEPUNISHER | `.137` | Windows 10 endpoint |
| Splunk | `.131` | Splunk 10.2 SIEM |
| Wazuh | `.150` | Wazuh 4.12 manager — 3 Windows agents |
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

| Gap | Consequence | Closed in |
| --- | ----------- | --------- |
| WinRM open east-west | the lateral-movement path | v4 |
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
> forwarding — its ProcessAccess layer is simply dark (`include` with no rule), so an LSASS
> dump on that host would not be seen. This is the deliberate blind spot from the coverage
> table, shown as an absence rather than asserted.

### 13 — Wazuh EDR: the scheduled-task rule gap (T1053.005)
[![Wazuh rule gap](screenshots/13_wazuh_rule_gap_60228.png)](screenshots/13_wazuh_rule_gap_60228.png)
> On THEPUNISHER, Wazuh's built-in rule `60228` fired at level 4 for both the malicious
> `\Updater` task and a benign `\OneDrive Standalone Update Task` — same rule, same severity.
> Wazuh alerts on task *creation* but does not score task *content*, so the hidden PowerShell
> IEX download cradle inside `\Updater` (visible in screenshot 08) is treated no differently
> from a routine update. A tuned rule keying on the command would separate the two.

## Known gaps carried into v4

- The hardening baseline above is partial and inconsistent by design — a realistic
  starting point, not a finished one. v4 rebuilds it to a CIS-aligned standard (consistent
  SMB signing, LSA Protection, WDigest/LLMNR off, east-west WinRM filtering) and re-runs the
  chain for a before/after coverage matrix.
- Account lockout is enforced (5 failures), but the spray sent a single attempt per
  account and so never reached the threshold — the standard way password spraying evades
  lockout. The weaker control is the 7-character minimum password length; v4 raises it.
- `SQLService` is a human-managed account with an SPN, which is what made Kerberoasting
  possible.
- The Wazuh scheduled-task rule gap above is unfixed here.
