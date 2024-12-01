# Inbound Authentication From Public IP

## Query Information

#### Description
This query can be used to identify devices that are publicly disclosed to the internet by monitoring for inbound authentication attempts.

#### Risk
Devices that are publicly disclosed to the internet are more pround to exploitation.

#### References
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625

## Sentinel
```KQL
let AllowedEntpoints = pack_array('devicename');
SecurityEvent
| where EventID in ('4625', '4624')
| where Computer !in(AllowedEntpoints)
| where not(ipv4_is_private(IpAddress))
| summarize arg_min(TimeGenerated, *) by Computer
| lookup kind=leftouter (DeviceInfo
    | summarize arg_max(TimeGenerated, *) by DeviceId
    | project DeviceName = toupper(DeviceName), DeviceType, PublicIP, ExposureLevel, MachineGroup) on $left.Computer == $right.DeviceName
```