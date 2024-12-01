# Detect when AnyDesk makes a remote connection

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1219 | Remote Access Software | https://attack.mitre.org/techniques/T1219/ |

#### Description
List devices from which AnyDesk makes a remote connection.

#### References
- https://redcanary.com/threat-detection-report/trends/rmm-tools/

## Defender XDR
```KQL
DeviceNetworkEvents
| where InitiatingProcessFileName == "AnyDesk.exe"
| where LocalIPType == "Private"
| where RemoteIPType == "Public"
| where RemoteUrl != "boot.net.anydesk.com" // Initial AnyDesk Connection when booted.
| project
     Timestamp,
     DeviceId,
     InitiatingProcessAccountName,
     ActionType,
     RemoteIP,
     RemotePort,
     RemoteUrl
```

## Sentinel
```
DeviceNetworkEvents
| where InitiatingProcessFileName == "AnyDesk.exe"
| where LocalIPType == "Private"
| where RemoteIPType == "Public"
| where RemoteUrl != "boot.net.anydesk.com" // Initial AnyDesk Connection when booted.
| project
     TimeGenerated,
     DeviceId,
     InitiatingProcessAccountName,
     ActionType,
     RemoteIP,
     RemotePort,
     RemoteUrl
```



