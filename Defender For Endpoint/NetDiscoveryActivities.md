# List net(1).exe discovery activities

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1069 | Permission Groups Discovery | https://attack.mitre.org/techniques/T1069/ |
| T1087 | Account Discovery | https://attack.mitre.org/techniques/T1087/ |
| T1201 | Password Policy Discovery | https://attack.mitre.org/techniques/T1201/ |

#### Description
This query lists the net.exe or net1.exe activities that have been executed by each account. The parameters that are included are:
```PowerShell
net accounts
net group
net user
net localgroup
```
The query calculates the amount of executions for each parameter together with the total discovery events that have been executed. This overview can be leveraged to determine which users perform anomalous amounts of discovery events using net(1).exe. The full commands that are executed are also included in the results, for analysis of the commandline executions.

#### References
- https://learn.microsoft.com/en-us/windows/win32/winsock/net-exe-2
- https://www.trendmicro.com/en_us/research/19/f/shifting-tactics-breaking-down-ta505-groups-use-of-html-rats-and-other-techniques-in-latest-campaigns.html
- https://www.cybereason.com/blog/operation-cuckoobees-deep-dive-into-stealthy-winnti-techniques

## Defender XDR
```KQL
let StartTime = 30d;
DeviceProcessEvents
| where Timestamp > startofday(ago(StartTime))
| where FileName in ("net.exe", "net1.exe")
| extend NetActionType = case(ProcessCommandLine has "accounts", "ACCOUNTS", 
    ProcessCommandLine has "group", "GROUP", 
    ProcessCommandLine has "user", "USER", 
    ProcessCommandLine has "localgroup", "LOCALGROUP", 
    "Other")
| where NetActionType != "Other"
| where isnotempty(AccountUpn)
| summarize TotalEvents = count(), TotalAccountsEvents = countif(NetActionType == "ACCOUNTS"), TotalGroupEvents = countif(NetActionType == "GROUP"), TotalUserEvents = countif(NetActionType == "USER"), TotalLocalGroupEvents = countif(NetActionType == "LOCALGROUP"), ExecutedCommands = make_set(ProcessCommandLine) by AccountUpn
```
## Sentinel
```KQL
let StartTime = 30d;
DeviceProcessEvents
| where TimeGenerated > startofday(ago(StartTime))
| where FileName in ("net.exe", "net1.exe")
| extend NetActionType = case(ProcessCommandLine has "accounts", "ACCOUNTS", 
    ProcessCommandLine has "group", "GROUP", 
    ProcessCommandLine has "user", "USER", 
    ProcessCommandLine has "localgroup", "LOCALGROUP", 
    "Other")
| where NetActionType != "Other"
| where isnotempty(AccountUpn)
| summarize TotalEvents = count(), TotalAccountsEvents = countif(NetActionType == "ACCOUNTS"), TotalGroupEvents = countif(NetActionType == "GROUP"), TotalUserEvents = countif(NetActionType == "USER"), TotalLocalGroupEvents = countif(NetActionType == "LOCALGROUP"), ExecutedCommands = make_set(ProcessCommandLine) by AccountUpn
```
