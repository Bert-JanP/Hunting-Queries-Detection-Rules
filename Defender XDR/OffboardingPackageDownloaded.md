# Defender For Endpoint Offboarding Package Downloaded

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1562.001 | Impair Defenses: Disable or Modify Tools | https://attack.mitre.org/techniques/T1562/001/ |

### Description
This query lists when a Defender For Endpoint offboarding package has been downloaded. Defender For Endpoint offboarding packages are considered tier0, because this allows you to remove security tooling from devices. (Local) Administrator permissions are needed to execute the proces and successfully ofboard devices.

### Risk
An actor has gotten access to an account that is able to download an Defender For Endpoint offboarding package and offboard devices, reducing visability.

### References
- https://learn.microsoft.com/en-us/defender-endpoint/offboard-machines
- https://kqlquery.com/posts/audit-defender-xdr/

## Defender XDR
```
CloudAppEvents
| where ActionType == "DownloadOffboardingPkg"
| extend UserId = tostring(parse_json(RawEventData).UserId), ClientIP = tostring(parse_json(RawEventData).ClientIP)
| project-rename InitiatedByAccountName = AccountDisplayName, InitiatedByAccounttId = AccountId
| project-reorder Timestamp, InitiatedByAccountName, UserId, ClientIP, ActionType
```
## Sentinel
```
CloudAppEvents
| where ActionType == "DownloadOffboardingPkg"
| extend UserId = tostring(parse_json(RawEventData).UserId), ClientIP = tostring(parse_json(RawEventData).ClientIP)
| project-rename InitiatedByAccountName = AccountDisplayName, InitiatedByAccounttId = AccountId
| project-reorder TimeGenerated, InitiatedByAccountName, UserId, ClientIP, ActionType
```
