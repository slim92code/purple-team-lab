# Purple Team Home Lab — Active Directory Detection Engineering

> A self-built Active Directory lab where every attack is run, detected in Splunk, then
> stress-tested for what default tooling misses — and the gap is closed and re-proven.
> Built to demonstrate SOC L2 thinking: methodology, not tool execution.

**This README is the 2-minute scan.** The deep-dive videos and full playbooks are
optional evidence linked below.

---

## What this demonstrates

- **Detection engineering** — 9 detections shipped as [Sigma rules](detections/sigma/sigma_rules.yml) (vendor-agnostic) and a deployable [Splunk pack](detections/splunk/purple_lab), CIM/TA-normalized, version-controlled.
- **Adversary emulation** — 8 MITRE ATT&CK techniques across a full AD kill chain, Defender left **on** throughout.
- **The purple loop** — attack, detect, find the detection gap, fix it, then re-run to prove the fix works. Prevention shrinks the attack surface but never to zero, so detection covers what slips through.

## Lab

```
               Kali (attacker) 192.168.182.133
                        │
      ┌─────────────────┼──────────────────┐
      │                 │                  │
HYDRA-DC .135      THEPUNISHER .137     SPIDERMAN .138
Win Server 2022    Win 10 endpoint      Win 10 endpoint
AD DS / MARVEL.LOCAL    │                  │
      └────────── Sysmon + Splunk UF ──────┘
                        │
                Splunk SIEM 192.168.182.131
```

Five VMs, VMware NAT `192.168.182.0/24`. Sysmon + Splunk Universal Forwarder on every
Windows host; audit policy enforced via GPO.

## MITRE ATT&CK coverage

| Phase          | Technique         | Tooling                 | Detection               | Prevention                  |
| -------------- | ----------------- | ----------------------- | ----------------------- | --------------------------- |
| Recon          | T1046 / T1087.002 | nmap, kerbrute, Certipy | 4768 err 0x6 burst      | Segmentation                |
| Initial Access | T1110.003         | kerbrute spray          | 4771 multi-user/source  | FGPP + lockout              |
| Execution      | T1218.004         | InstallUtil + .NET      | LOLBin from user path   | AppLocker / WDAC            |
| Cred Access    | T1558.003         | GetUserSPNs             | 4769 RC4 (0x17)         | AES + strong pwd + gMSA     |
| Lateral / C2   | T1071.001         | Sliver mTLS             | behavioral beacon       | AppLocker + egress filter   |
| Cred Access    | T1003.002 / .006  | reg save, DCSync        | reg-save combo / 4662   | Defender + Credential Guard |
| Persistence    | T1053.005         | schtasks                | 4698 SYSTEM + user path | Restricted local admin      |
| C2 / Exfil     | T1071.001 / T1041 | Sliver beacon           | Sysmon EID3 + JA3 (NDR) | TLS inspection              |

Full coverage matrix and per-technique detection cards: [`03_detection_playbook.md`](03_detection_playbook.md).

## Headline finding — the C2 detection gap

A modern C2 (Sliver, mTLS/443) beaconed from a domain endpoint and default Sysmon did
not record the network connection — `NetworkConnect` is not logged for `C:\Temp` out of the box.

The naive fix is to add the implant's filename to a watchlist. That is an anti-pattern:
rename the binary and the detection dies. The fix shipped here is behavioral — flag any
process running from a user-writable path (`C:\Temp`, `AppData`, `ProgramData`) that
initiates egress, then confirm with beacon interval/jitter analysis. A renamed implant
still trips it. See [Sigma rule 7](detections/sigma/sigma_rules.yml) and the CIM `tstats`
version in the Splunk pack.

## Blue-team win (Defender on, not staged)

AMSI blocked the Mimikatz DCSync call in-memory (`ScriptContainedMaliciousContent`)
before execution. Genuine endpoint protection win.

**Honest finding — why DCSync never landed:**
SharpKatz (compiled .NET) evaded AMSI but failed at the DRS bind with RPC 1825 — a
Kerberos/transport auth error, not access-denied. fcastle is a Domain Admin and holds
replication rights via nested `BUILTIN\Administrators` membership. The block was
tooling/transport, not permissions. Documented accurately because the distinction matters:
confusing RPC auth failure with permission control is an AD 101 mistake.

## Screenshots

### 01 — Password Spray detected (T1110.003)

[![Password Spray](screenshots/01_password_spray.png)](screenshots/01_password_spray.png)
> Splunk 4771 correlation: single source (192.168.182.133 / Kali), 3 unique accounts in a 5-minute window. No lockout triggered — one bad attempt per account is the spray signature.

### 02 — Kerberoasting RC4 ticket (T1558.003)

[![Kerberoasting](screenshots/02_kerberoasting.png)](screenshots/02_kerberoasting.png)
> 4769 with Ticket_Encryption_Type=0x17 (RC4-HMAC) for `SQLService`. On a modern AES domain, RC4 service tickets for user-SPNs are anomalous by definition.

### 03 — Lateral Movement via secretsdump (T1003.002)

[![Lateral Movement](screenshots/03_lateral_movement.png)](screenshots/03_lateral_movement.png)
> 4624 Logon Type 3 (network logon) from Kali (.133) to THEPUNISHER (.137) — credential reuse pivot, SAM hashes extracted via RemoteRegistry.

### 04 — Defender + AMSI blocks Mimikatz (T1003.001)

[![Defender AMSI](screenshots/04_defender_amsi.png)](screenshots/04_defender_amsi.png)
> `Trojan:PowerShell/Powersploit.C` blocked at AMSI layer before execution. Alert level: Severe. Defender left on throughout the lab — genuine blue-team win, not a staged result.

### 05 — C2 Beacon from C:\Temp (T1071.001) — the showcase

[![C2 Beacon](screenshots/05_c2_beacon.png)](screenshots/05_c2_beacon.png)
> Sysmon EID3: `C:\Temp\GlobalProtect_Update.exe` → 192.168.182.133:443 (Sliver mTLS). Default Sysmon missed this — the SwiftOnSecurity baseline covers `C:\Users` and `C:\ProgramData` but not a bare `C:\Temp`. One line closes the gap. Detection keys on location, not filename — a renamed binary still trips it.

## Repo map

```
.
├── README.md                       <- you are here
├── 01_lab_setup.md                 <- AD lab build (DC, endpoints, Sysmon, Splunk)
├── 02_attack_playbook.md           <- 8 phases, commands, MITRE mapping
├── 03_detection_playbook.md        <- detection cards, SPL, IR runbook, hardening
├── lab_issues.md                   <- real build/debug log (GPO/auditpol, ACLs, forwarder)
├── commands.md                     <- command quick-reference
├── config/sysmonconfig.xml         <- Sysmon config incl. the C:\Temp NetworkConnect fix
├── screenshots/                    <- 5 detection screenshots
└── detections/
    ├── sigma/sigma_rules.yml       <- Detection-as-Code, vendor-agnostic
    └── splunk/purple_lab/          <- deployable Splunk app (+ cim-acceleration/)
```

## Scope / honest caveats (lab, not production)

- `C:\Temp` is a Defender exclusion so payload delivery is reproducible on camera; in
production it would not be, and the AppLocker fix in Segment 10 addresses exactly that path.
- DC SMB/RPC is firewall-filtered from Kali, so privileged attacks pivot through an
endpoint — which is the realistic path anyway.
- Single-domain, no NDR/EDR layer yet (Lab v2: pfSense+Suricata/Zeek for JA3, Wazuh, MISP).

---

*Self-taught. Certs: TCM Security SOC 201, Detection Engineering for Beginners, Practical Windows Forensics.*
