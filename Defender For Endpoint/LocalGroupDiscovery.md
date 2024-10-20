# Local Group Discovery

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1069.001 | Permission Groups Discovery: Local Groups | https://attack.mitre.org/techniques/T1069/001/ |

#### Description
Adversaries often execute the *net localgroup "adminstrator"* command to get information about the local admins on a device, but there might also be other groups that could be intersting. This query can be used as custom detection rule to detect local group discovery events using net.exe or net1.exe. There is a whitelist for departments that are expected to perform this action, but if HR or Sales executes these commands you probably want to know.

#### Risk
A compromised account performs discovery activities in your environment.

#### References
- https://thedfirreport.com/2021/11/29/continuing-the-bazar-ransomware-story/
- https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF

## Defender XDR
```KQL
let WhitelistedDepartments = dynamic(["Service Desk", "It Admins"]);
let StartTime = 30d;
DeviceProcessEvents
| where Timestamp > startofday(ago(StartTime))
| where FileName in ("net.exe", "net1.exe")
| where ProcessCommandLine has "localgroup"
| extend GroupName = extract(@'"(.*?)"', 1, ProcessCommandLine)
| join kind=inner (IdentityInfo
    | where Timestamp > ago(30d)
    | summarize arg_max(Timestamp, *) by OnPremSid
    | project Department, OnPremSid)
    on $left.AccountSid == $right.OnPremSid
// Filter whitelisted departments
| where not(Department in (WhitelistedDepartments))
| project-reorder Timestamp, Department, ProcessCommandLine, GroupName
```
## Sentinel
```KQL
let WhitelistedDepartments = dynamic(["Service Desk", "It Admins"]);
let StartTime = 30d;
DeviceProcessEvents
| where TimeGenerated > startofday(ago(StartTime))
| where FileName in ("net.exe", "net1.exe")
| where ProcessCommandLine has "localgroup"
| extend GroupName = extract(@'"(.*?)"', 1, ProcessCommandLine)
| join kind=inner (IdentityInfo
    | where TimeGenerated > ago(30d)
    | summarize arg_max(TimeGenerated, *) by OnPremSid
    | project Department, OnPremSid)
    on $left.AccountSid == $right.OnPremSid
// Filter whitelisted departments
| where not(Department in (WhitelistedDepartments))
| project-reorder TimeGenerated, Department, ProcessCommandLine, GroupName
```
