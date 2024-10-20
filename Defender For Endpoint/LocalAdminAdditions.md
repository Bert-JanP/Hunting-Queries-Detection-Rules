# Local Administrator Additions

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1136.001 | Create Account: Local Account | https://attack.mitre.org/techniques/T1136/001/ |

#### Description
Adversaries may create a local accounts to maintain access to victim systems. This query lists all the locad admins that have been added in the seletect timeframe per device. 

#### Risk
Local Admin accounts have high priviliges on and can should be limited.

#### References
- https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts#administrator

## Defender XDR
```KQL
DeviceEvents
| where ActionType == "UserAccountAddedToLocalGroup"
| extend Details = parse_json(AdditionalFields)
| extend
    GroupName = tostring(Details.GroupName),
    GroupDomainName = tostring(Details.GroupDomainName),
    GroupSid = tostring(Details.GroupSid)
// Filter Local Administrators
| where GroupSid == "S-1-5-32-544"
| summarize LocalAdmins = make_set(AccountSid) by DeviceName
| extend TotalLocalAdmins = array_length(LocalAdmins)
| sort by TotalLocalAdmins
```
## Sentinel
```KQL
DeviceEvents
| where ActionType == "UserAccountAddedToLocalGroup"
| extend Details = parse_json(AdditionalFields)
| extend
    GroupName = tostring(Details.GroupName),
    GroupDomainName = tostring(Details.GroupDomainName),
    GroupSid = tostring(Details.GroupSid)
// Filter Local Administrators
| where GroupSid == "S-1-5-32-544"
| summarize LocalAdmins = make_set(AccountSid) by DeviceName
| extend TotalLocalAdmins = array_length(LocalAdmins)
| sort by TotalLocalAdmins
```
