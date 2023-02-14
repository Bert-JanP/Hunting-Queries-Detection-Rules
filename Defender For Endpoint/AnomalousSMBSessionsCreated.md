# Anomalous amount of SMB sessions created (BloodHound)

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1018 | Remote System Discovery | https://attack.mitre.org/techniques/T1018|

#### Description
This detection rule is aimed to detect a host that performs SMB Discovery by alerting if a device creates more then 100 unique SMB sessions within 15 minutes. That is one of the characteristics of bloodhound. The SMB sessions can be used to identify remote systems.

#### Risk
A actor has gotten access to a system en performs a scan to identify possible lateral movement paths.

## Defender For Endpoint
```
DeviceNetworkEvents
| where Timestamp < ago(1h)
| where RemotePort == 445
| summarize
     TotalIpsAccessed = dcount(RemoteIP),
     RemoteIPs = make_set(RemoteIP),
     arg_max(Timestamp, *)
     by DeviceName, bin(Timestamp, 15m)
| where TotalIpsAccessed > 100 // Can be adjusted to reduce false positives
| project-reorder
     Timestamp,
     DeviceName,
     InitiatingProcessAccountDomain,
     InitiatingProcessAccountName,
     InitiatingProcessCommandLine,
     InitiatingProcessFolderPath
```
## Sentinel
```
DeviceNetworkEvents
| where TimeGenerated < ago(1h)
| where RemotePort == 445
| summarize
     TotalIpsAccessed = dcount(RemoteIP),
     RemoteIPs = make_set(RemoteIP),
     arg_max(TimeGenerated, *)
     by DeviceName, bin(TimeGenerated, 15m)
| where TotalIpsAccessed > 100 // Can be adjusted to reduce false positives
| project-reorder
     TimeGenerated,
     DeviceName,
     InitiatingProcessAccountDomain,
     InitiatingProcessAccountName,
     InitiatingProcessCommandLine,
     InitiatingProcessFolderPath
```



