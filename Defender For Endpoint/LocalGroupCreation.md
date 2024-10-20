# Local Group Created

## Query Information

#### Description
This query lists all the local groups that have been created, this is done by listing all SecurityGroupCreated events and filtering all group creations on Domain Controllers. The GroupDomainName can be used to identify on which device the group has been created.

#### Risk
Local groups can be created in order to evade AD Group requirements and control measures.

#### References
- https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/get-localgroup?view=powershell-5.1

## Defender XDR
```KQL
let AllDomainControllers =
    DeviceNetworkEvents
    | where LocalPort == 88
    | where LocalIPType == "FourToSixMapping"
    | summarize make_set(DeviceId);
DeviceEvents
| where ActionType == "SecurityGroupCreated"
| where not(DeviceId in (AllDomainControllers))
| extend Details = parse_json(AdditionalFields)
| extend
    GroupName = tostring(Details.GroupName),
    GroupDomainName = tostring(Details.GroupDomainName),
    GroupSid = tostring(Details.GroupSid)
| join kind=inner (DeviceInfo
    | where Timestamp > ago(30d)
    | summarize arg_max(Timestamp, *) by DeviceId
    | project DeviceId, OSPlatform, DeviceType)
    on DeviceId
| project Timestamp, DeviceId, DeviceName, GroupName, GroupDomainName, GroupSid, OSPlatform, DeviceType, ReportId
```
## Sentinel
```KQL
let AllDomainControllers =
    DeviceNetworkEvents
    | where LocalPort == 88
    | where LocalIPType == "FourToSixMapping"
    | summarize make_set(DeviceId);
DeviceEvents
| where ActionType == "SecurityGroupCreated"
| where not(DeviceId in (AllDomainControllers))
| extend Details = parse_json(AdditionalFields)
| extend
    GroupName = tostring(Details.GroupName),
    GroupDomainName = tostring(Details.GroupDomainName),
    GroupSid = tostring(Details.GroupSid)
| join kind=inner (DeviceInfo
    | where TimeGenerated > ago(30d)
    | summarize arg_max(TimeGenerated, *) by DeviceId
    | project DeviceId, OSPlatform, DeviceType)
    on DeviceId
| project TimeGenerated, DeviceId, DeviceName, GroupName, GroupDomainName, GroupSid, OSPlatform, DeviceType, ReportId
```
