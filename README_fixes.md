## Izmene za GitHub README.md

### 1. Blue-team wins sekcija — ZAMENI SA:

```markdown
## Blue-team wins (Defender on, not staged)

- **AMSI blocked Mimikatz in-memory** — `ScriptContainedMaliciousContent` caught before execution. Genuine endpoint protection win.

Honest finding — why DCSync never landed:
SharpKatz (compiled .NET) evaded AMSI but failed at the DRS bind with RPC 1825 — a Kerberos/transport auth error, not access-denied. fcastle is a Domain Admin and holds replication rights via nested BUILTIN\Administrators membership. The block was tooling/transport, not permissions. Documented accurately because the distinction matters: confusing RPC auth failure with permission control is an AD 101 mistake.
```

### 2. Footer — ZAMENI SA:

```markdown
*Self-taught. Certs: TCM Security SOC 201, Detection Engineering for Beginners, Practical Windows Forensics.*
```

### 3. Repo mapa — ukloni ako 04_video_narrative.md postoji na git-u:

```
├── 04_video_narrative.md  <- video narration script (optional deep-dive)
```
