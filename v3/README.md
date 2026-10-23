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

| Host | Address | Role |
| ---- | ------- | ---- |
| HYDRA-DC | `.135` | Windows Server 2022 — AD DS, `MARVEL.LOCAL` |
| SPIDERMAN | `.138` | Windows 10 endpoint |
| THEPUNISHER | `.137` | Windows 10 endpoint |
| Splunk | `.131` | Splunk 10.2 SIEM |
| Wazuh | `.150` | Wazuh 4.12 manager — 3 agents |
| security-vm | `.151` | Zeek + Suricata |
| Kali | `.133` | Attacker |

## Kill chain and detection coverage

| Phase | Technique | Detected by |
| ----- | --------- | ----------- |
| Password spray | T1110.003 | Windows `4771`, Zeek `kerberos.log`, Suricata `krb5` |
| Kerberoasting | T1558.003 | Windows `4769`, Suricata `krb5`, Suricata `weak_encryption` |
| Pass-the-Ticket | T1550.003 | Windows `4624` type 3, Zeek `kerberos.log` |
| Lateral movement (WinRM) | T1021.006 | Zeek `conn.log` port 5985, Suricata `REQUEST_AUTH_UNRECOGNIZED` |
| LSASS access | T1003.001 | Sysmon EID 10 (THEPUNISHER only — SPIDERMAN is a deliberate blind spot) |
| Scheduled task persistence | T1053.005 | Windows `4698`, Wazuh rule `60228` |
| C2 beaconing | T1071.001 | Zeek `ssl.log` — JA4 TLS fingerprinting |

## Findings

**Network layer caught the spray with no endpoint telemetry.** Zeek `kerberos.log` recorded
seven distinct accounts attempted from a single non-domain source inside one second, six
failing pre-authentication and one succeeding. The successful account is visible in the
network data alone, before any host log is consulted.

**One JA4 fingerprint linked two compromised endpoints.** Both endpoints beaconed to the
attacker host over TLS — 43 sessions from SPIDERMAN, 22 from THEPUNISHER — sharing an
identical JA4 client fingerprint. The fingerprint survives a binary rename, so the
detection does not depend on a filename or hash.

**Wazuh scheduled-task alerting does not separate malicious from benign.** The `\Updater`
persistence task created on THEPUNISHER fired rule `60228` at level 4 — the same rule and
the same severity as a legitimate OneDrive update task created on the same host earlier
that day. Task creation is alerted on; task *content* is not evaluated.

**An LSASS alert that looks like credential theft is Windows Defender.** Wazuh rule `92900`
fired six times for `MsMpEng.exe` accessing `lsass.exe` with `GrantedAccess 0x101000` —
synchronize plus query-limited-information, the access an anti-malware engine uses to
inspect a process, not the access a credential dump requires. Triaged as a false positive;
the rule needs a source-image exclusion and an access-mask condition.

**Wazuh alerts did not reach Splunk.** Agent data was present in the Wazuh manager's own
archives for all three agents while the corresponding Splunk search returned nothing,
placing the gap in the Wazuh-to-Splunk forwarding path rather than in agent collection.

## Known gaps carried into v4

- The lab runs on a default-ish Windows baseline, so no attack had to work through
  hardening. v4 rebuilds on a CIS baseline and re-runs the chain for a before/after
  coverage matrix.
- No account lockout policy, which is why the spray ran uninterrupted.
- `SQLService` is a human-managed account with an SPN, which is what made Kerberoasting
  possible.
- Wazuh-to-Splunk forwarding and the two Wazuh rule gaps above are unfixed here.
