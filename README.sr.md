**[English](README.md)** · **Srpski**

# Purple Team Home Lab — Detection Engineering nad Active Directory

> Samostalno izgrađen Active Directory lab gde se svaki napad izvede, detektuje u Splunk-u,
> pa testira na ono što default alati **propuštaju** — i taj gap se zatvori i ponovo dokaže.
> Cilj je pokazati SOC L2 razmišljanje: metodologiju, ne puko izvršavanje alata.

**Ovaj README je skeniranje za ~2 minuta.** Detaljni video i puni playbook-ovi su opcioni
dokaz, linkovani ispod.

---

## Šta ovo demonstrira

- **Detection engineering** — 9 detekcija isporučenih kao [Sigma pravila](detections/sigma/sigma_rules.yml) (vendor-agnostic) i deployable [Splunk pack](detections/splunk/purple_lab/), CIM/TA-normalizovano, pod verzionisanjem.
- **Adversary emulation** — 8 MITRE ATT&CK tehnika kroz kompletan AD kill chain, Defender **uključen** sve vreme.
- **Purple petlja** — napad → detekcija → **pronalazak detection gap-a** → fix → **ponovni dokaz**. Deo koji većina labova preskoči.
- **Hardening ≠ detection** — prevencija smanjuje napadački surface; nikad ga ne svodi na nulu. Detekcija je safety net za ono što prođe.

## Lab

```
                 Kali (napadač) 192.168.182.133
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

Pet VM-ova, VMware NAT `192.168.182.0/24`. Sysmon + Splunk Universal Forwarder na svakom
Windows hostu; audit polisa nametnuta kroz GPO.

## MITRE ATT&CK pokrivenost

| Faza | Tehnika | Alat | Detekcija | Prevencija |
|---|---|---|---|---|
| Recon | T1046 / T1087.002 | nmap, kerbrute, Certipy | 4768 err 0x6 burst | Segmentacija |
| Initial Access | T1110.003 | kerbrute spray | 4771 multi-user/source | FGPP + lockout |
| Execution | T1218.004 | InstallUtil + .NET | LOLBin iz user putanje | AppLocker / WDAC |
| Cred Access | T1558.003 | GetUserSPNs | 4769 RC4 (0x17) | AES + jaka lozinka + gMSA |
| Lateral / C2 | T1071.001 | Sliver mTLS | **behavioral** beacon | AppLocker + egress filter |
| Cred Access | T1003.002 / .006 | reg save, DCSync | reg-save combo / 4662 | Defender + Credential Guard |
| Persistence | T1053.005 | schtasks | 4698 SYSTEM + user putanja | Restricted local admin |
| C2 / Exfil | T1071.001 / T1041 | Sliver beacon | Sysmon EID3 + JA3 (NDR) | TLS inspection |

Puna coverage matrica i detection cards po tehnici: [`03_detection_playbook.md`](03_detection_playbook.md).

[![ATT&CK Coverage](screenshots/09_attack_navigator.svg)](detections/attack_navigator_layer.json)

Interactive layer: open in [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) — `detections/attack_navigator_layer.json`

## Centralni nalaz — C2 detection gap (climax)

Moderan C2 (Sliver, mTLS/443) beaconao je sa domain endpoint-a, a **default Sysmon nije
zabeležio mrežnu konekciju** — `NetworkConnect` za njega nije logovan out-of-the-box.

Naivni „fix" bi bio dodati ime implanta na watchlist. To je anti-pattern: preimenuje se
binar i detekcija pada. Fix isporučen ovde je **behavioral** — flaguje *bilo koji* proces
iz user-writable putanje (`C:\Temp`, `AppData`, `ProgramData`) koji pravi egress, pa se
potvrdi beacon interval/jitter analizom. Preimenovani implant i dalje upada. Vidi
[Sigma pravilo 7](detections/sigma/sigma_rules.yml) i `tstats` verziju u Splunk pack-u.

## Blue-team pobede (Defender uključen, nije stejdžovano)

- **AMSI blokirao Mimikatz** — PowerShell invokacija zaustavljena pri skeniranju; alat nikad nije izvršen.
- **SharpKatz (AMSI-evading) prošao Defender** ali pao na DRS bind-u — RPC 1825 (Kerberos auth greška na transport sloju). `fcastle` JE Domain Admin i IMA DS-Replication-Get-Changes kroz `BUILTIN\Administrators` — permisije nikad nisu bile prepreka. Dva nezavisna sloja zaustavila su DCSync: AMSI na alatu, Kerberos transport na protokolu.

## Dashboard

![SOC L2 Detection Dashboard](screenshots/06_dashboard.png)
> Ceo attack chain vidljiv u jednom pogledu — 5 countera, MITRE ATT&CK bar chart i attack timeline kroz ceo period laba. Napravljen u Splunk Simple XML; izvor u [`detections/splunk/purple_lab/`](detections/splunk/purple_lab/).

## Video serija

Kompletan serijal (10 segmenata, ~75 min): [YouTube Playlist](https://www.youtube.com/playlist?list=PLL1zKaMLDyG24fX3g8Ck42y_e6nPrRU4-)

| Segment | Tema |
|---|---|
| Seg 1 | Lab Setup & Recon |
| Seg 2 | Password Spray (T1110.003) |
| Seg 3 | LOLBin Execution (T1218.004) |
| Seg 4 | Kerberoasting (T1558.003) |
| Seg 5 | Lateral Movement / Sliver C2 |
| Seg 6 | Credential Dumping + Defender/AMSI |
| Seg 7 | Persistence (T1053.005) |
| Seg 8 | C2 Evasion + Sysmon Gap Fix |
| Seg 9 | Splunk Dashboard Tour |
| Seg 10 | Production Hardening |

## Screenshot-ovi

### 01 — Password Spray detektovan (T1110.003)
![Password Spray](screenshots/01_password_spray.png)
> Splunk 4771 korelacija: jedan izvor (192.168.182.133 / Kali), 3 unique naloga u 5-minutnom prozoru. Lockout se nije okinio — jedna loza po nalogu je spray signature.

### 02 — Kerberoasting RC4 tiket (T1558.003)
![Kerberoasting](screenshots/02_kerberoasting.png)
> 4769 sa Ticket_Encryption_Type=**0x17** (RC4-HMAC) za `SQLService`. Na modernom AES domenu, RC4 service tiketi za user SPN-ove su anomalija po definiciji.

### 03 — Lateralno kretanje via secretsdump (T1003.002)
![Lateral Movement](screenshots/03_lateral_movement.png)
> 4624 Logon Type 3 (network logon) sa Kali (.133) na THEPUNISHER (.137) — pivot kroz credential reuse, SAM hashes izvučeni via RemoteRegistry.

### 04 — Defender + AMSI blokira Mimikatz (T1003.001)
![Defender AMSI](screenshots/04_defender_amsi.png)
> `Trojan:PowerShell/Powersploit.C` blokiran na AMSI sloju pre izvršavanja. Alert level: Severe. Defender je bio **uključen** tokom celog laba — ovo je prava blue-team pobeda.

### 05 — C2 Beacon iz C:\Temp (T1071.001) — climax
![C2 Beacon](screenshots/05_c2_beacon.png)
> Sysmon EID3: `C:\Temp\GlobalProtect_Update.exe` → 192.168.182.133:443 (Sliver mTLS). Default Sysmon je propustio ovo — SwiftOnSecurity baseline pokriva `C:\Users` i `C:\ProgramData` ali ne i goli `C:\Temp`. Jedna linija zatvara gap. Detekcija keyuje na **lokaciju**, ne na ime fajla.

## Mapa repo-a

```
.
├── README.md / README.sr.md                    <- ulazna tačka (skeniranje za 2 min)
├── 01_lab_setup.md / 01_lab_setup.sr.md       <- build AD laba (DC, endpointi, Sysmon, Splunk)
├── 02_attack_playbook.md / 02_attack_playbook.sr.md  <- 8 faza, komande, MITRE mapping
├── 03_detection_playbook.md / 03_detection_playbook.sr.md  <- detection cards, SPL, IR runbook, hardening
├── lab_issues.md / lab_issues.sr.md           <- realni build/debug log (GPO/auditpol, ACL, forwarder)
├── COMMAND_REFERENCE.md                       <- brza referenca komandi
├── config/sysmonconfig.xml                    <- Sysmon config sa C:\Temp NetworkConnect fix-om
├── screenshots/                               <- 12 detekcijskih screenshot-ova (spray, kerb, lateral, amsi, c2, dashboard, persistence, gap demo, hardening)
└── detections/
    ├── sigma/sigma_rules.yml                  <- Detection-as-Code, vendor-agnostic
    └── splunk/purple_lab/                     <- deployable Splunk app (+ cim-acceleration/)
```

## Napomena o formatu

Primarni deliverable je **ovaj repo** — skenira se za ~2 minuta. Video serija je opcioni
deep-dive za one koji žele da vide kako kill chain ide od početka do kraja; preporučeni
watch je ~1h highlight cut (Kerberoasting → Credential Dumping → C2 gap → Dashboard →
Hardening). Hiring manager ocenjuje repo, ne runtime.

## Opseg / iskrene napomene (lab, ne produkcija)

- `C:\Temp` je Defender exclusion da bi delivery payload-a bio reproducibilan na snimku; u
  produkciji ne bi bio, a AppLocker fix u Segmentu 10 pokriva baš tu putanju.
- DC SMB/RPC je firewall-filtriran sa Kali-ja, pa privilegovani napadi pivotuju kroz
  endpoint — što je ionako realan put.
- Single-domain, bez NDR/EDR sloja zasad (Lab v2: pfSense+Suricata/Zeek za JA3, Wazuh, MISP).

---

*Self-taught. Background: TCM Security (SOC 201, Practical Windows Forensics, Detection Engineering for Beginners, Linux 100/101; SOC 101 · PEH · PMAT u toku), TryHackMe (top 1%, 173 rooms).*
