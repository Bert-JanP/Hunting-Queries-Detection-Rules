# Process Primary Token Elevated to SeDebugPrivilege

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1134 | Access Token Manipulation | https://attack.mitre.org/techniques/T1134/ |

#### Description
This query detects when a process's primary token is modified to include `SeDebugPrivilege` (privilege bit 20). `SeDebugPrivilege` grants a process the ability to open and manipulate any other process on the system, regardless of its security descriptor. This privilege is routinely abused by attackers for credential dumping (e.g., accessing LSASS), process injection, and lateral movement. The query uses a bitmask comparison to identify exactly when this privilege is added to a token and enriches the result with file prevalence data to reduce false positives.

#### Risk
Granting `SeDebugPrivilege` to a process is a strong indicator of privilege escalation or credential theft activity. Tools like Mimikatz require this privilege to dump credentials from LSASS memory.

## Defender XDR
```KQL
// Token elevated to SeDebugPriv
let SeDebugPriv = binary_shift_left(1, 20);
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == 'ProcessPrimaryTokenModified'
| extend CurrentTokenPrivEnabled = tolong(parse_json(AdditionalFields).CurrentTokenPrivEnabled), OriginalTokenPrivEnabled = tolong(parse_json(AdditionalFields).OriginalTokenPrivEnabled)
| extend PrivilegeDiff = binary_xor(OriginalTokenPrivEnabled, CurrentTokenPrivEnabled)
| where PrivilegeDiff == SeDebugPriv
| invoke FileProfile(InitiatingProcessSHA256)
| project-reorder Timestamp, ActionType, InitiatingProcessFileName, InitiatingProcessSHA256, InitiatingProcessFolderPath, GlobalPrevalence, GlobalFirstSeen, InitiatingProcessCommandLine
```

## Sentinel
```KQL
// Token elevated to SeDebugPriv
let SeDebugPriv = binary_shift_left(1, 20);
DeviceEvents
| where TimeGenerated > ago(7d)
| where ActionType == 'ProcessPrimaryTokenModified'
| extend CurrentTokenPrivEnabled = tolong(parse_json(AdditionalFields).CurrentTokenPrivEnabled), OriginalTokenPrivEnabled = tolong(parse_json(AdditionalFields).OriginalTokenPrivEnabled)
| extend PrivilegeDiff = binary_xor(OriginalTokenPrivEnabled, CurrentTokenPrivEnabled)
| where PrivilegeDiff == SeDebugPriv
| invoke FileProfile(InitiatingProcessSHA256)
| project-reorder TimeGenerated, ActionType, InitiatingProcessFileName, InitiatingProcessSHA256, InitiatingProcessFolderPath, GlobalPrevalence, GlobalFirstSeen, InitiatingProcessCommandLine
```