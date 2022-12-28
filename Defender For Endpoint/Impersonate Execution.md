#Impersonate Execution
Detects execution of the Impersonate tool. Which can be used to manipulate tokens on a Windows computers remotely (PsExec/WmiExec) or interactively

## Query 
```
DeviceProcessEvents | where (((ProcessCommandLine contains @'impersonate.exe' and (ProcessCommandLine contains @' list ' or ProcessCommandLine contains @' exec ' or ProcessCommandLine contains @' adduser '))) or ((((InitiatingProcessSHA256 contains @'MD5=9520714AB576B0ED01D1513691377D01' or InitiatingProcessSHA256 contains @'SHA256=E81CC96E2118DC4FBFE5BAD1604E0AC7681960143E2101E1A024D52264BB0A8A' or InitiatingProcessSHA256 contains @'IMPHASH=0A358FFC1697B7A07D0E817AC740DF62')) or ((InitiatingProcessMD5 contains @'MD5=9520714AB576B0ED01D1513691377D01' or InitiatingProcessMD5 contains @'SHA256=E81CC96E2118DC4FBFE5BAD1604E0AC7681960143E2101E1A024D52264BB0A8A' or InitiatingProcessMD5 contains @'IMPHASH=0A358FFC1697B7A07D0E817AC740DF62')) or ((SHA256 contains @'MD5=9520714AB576B0ED01D1513691377D01' or SHA256 contains @'SHA256=E81CC96E2118DC4FBFE5BAD1604E0AC7681960143E2101E1A024D52264BB0A8A' or SHA256 contains @'IMPHASH=0A358FFC1697B7A07D0E817AC740DF62')) or ((SHA1 contains @'MD5=9520714AB576B0ED01D1513691377D01' or SHA1 contains @'SHA256=E81CC96E2118DC4FBFE5BAD1604E0AC7681960143E2101E1A024D52264BB0A8A' or SHA1 contains @'IMPHASH=0A358FFC1697B7A07D0E817AC740DF62')) or ((MD5 contains @'MD5=9520714AB576B0ED01D1513691377D01' or MD5 contains @'SHA256=E81CC96E2118DC4FBFE5BAD1604E0AC7681960143E2101E1A024D52264BB0A8A' or MD5 contains @'IMPHASH=0A358FFC1697B7A07D0E817AC740DF62')) or ((InitiatingProcessSHA1 contains @'MD5=9520714AB576B0ED01D1513691377D01' or InitiatingProcessSHA1 contains @'SHA256=E81CC96E2118DC4FBFE5BAD1604E0AC7681960143E2101E1A024D52264BB0A8A' or InitiatingProcessSHA1 contains @'IMPHASH=0A358FFC1697B7A07D0E817AC740DF62')) or (MD5 =~ @'9520714AB576B0ED01D1513691377D01') or (SHA256 =~ @'E81CC96E2118DC4FBFE5BAD1604E0AC7681960143E2101E1A024D52264BB0A8A') or (IMPHASH =~ @'0A358FFC1697B7A07D0E817AC740DF62'))))

```

## Category
This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access |  |  |
| Execution | v |  |
| Persistence |  |  | 
| Privilege escalation | v |  |
| Defense evasion | v |  | 
| Credential Access |  |  | 
| Discovery |  |  | 
| Lateral movement |  |  | 
| Collection |  |  | 
| Command and control |  |  | 
| Exfiltration |  |  | 
| Impact |  |  |
| Vulnerability |  |  |
| Exploit |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |
| Ransomware |  |  |


## Contributor info
**Contributor:** Sai Prashanth Pulisetti
**GitHub alias:** prashanthpulisetti
**Contact info:** @pulisettis
