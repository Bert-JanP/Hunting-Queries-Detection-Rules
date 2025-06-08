# ASR Executable Office Content 

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1137 | Office Application Startup | https://attack.mitre.org/techniques/T1137/ |

#### Description
The discroption of this ASR rule: This rule prevents Office apps, including Word, Excel, and PowerPoint, from creating potentially malicious executable content, by blocking malicious code from being written to disk.Malware that abuses Office as a vector might attempt to break out of Office and save malicious components to disk. These malicious components would survive a computer reboot and persist on the system. Therefore, this rule defends against a common persistence technique.

This query tries to detect persistence via executable office content. Malicious executable files can be loaded when a infected office file is opened. This ASR rule does not generate a alert by default. 

Note: The query for Sentinel is different then the one for MDE, this is because the FileProfile function is used, which is currently not supported by Sentinel. Therefore I suggest running this query in MDE for the best results. 

#### Risk
A malcious Office Application has run and resulted in a attacker that gained Persistence

#### References
- https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide#block-office-applications-from-creating-executable-content

## Defender XDR
```
// To prevent False Positives a FilePrevalanceThreshold is used.
let FilePrevalanceThreshold = 100;
DeviceEvents
// Filter on the specific ActionTypes
| where ActionType in~ ('AsrExecutableOfficeContentAudited', 'AsrExecutableOfficeContentBlocked')
// Enrich results with File information
| invoke FileProfile('SHA1', 10000)
| where GlobalPrevalence <= FilePrevalanceThreshold
| project Timestamp, DeviceName, DeviceId, InitiatingProcessAccountUpn, FileName, FolderPath, ActionType, Signer, GlobalFirstSeen, GlobalPrevalence, SHA1, InitiatingProcessCommandLine, InitiatingProcessFolderPath
```
## Sentinel
```
DeviceEvents
// Filter on the specific ActionTypes
| where ActionType in~ ('AsrExecutableOfficeContentAudited', 'AsrExecutableOfficeContentBlocked')
// Enrich results with File information
| invoke FileProfile('SHA1', 10000)
| project TimeGenerated, DeviceName, DeviceId, InitiatingProcessAccountUpn, FileName, FolderPath, ActionType, SHA1, InitiatingProcessCommandLine, InitiatingProcessFolderPath
```
