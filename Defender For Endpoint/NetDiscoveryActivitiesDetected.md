# Detect net(1).exe Discovery Activities

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1069 | Permission Groups Discovery | https://attack.mitre.org/techniques/T1069/ |
| T1087 | Account Discovery | https://attack.mitre.org/techniques/T1087/ |
| T1201 | Password Policy Discovery | https://attack.mitre.org/techniques/T1201/ |

#### Description
This query can be used to detect suspicious net.exe or net1.exe activities that have been executed by a account. The parameters that are to detect this behaviour are:
```PowerShell
net accounts
net group
net user
net localgroup
```
The query calculates the amount of executions for each parameter together with the total discovery events that have been executed. This overview can be leveraged to determine which users perform anomalous amounts of discovery events using net(1).exe. The full commands that are executed are also included in the results, for analysis of the commandline executions. The detection rule can be tweaked depending on the needs of your environment. 
- *StartTime* - Determines from which point the search must be started.
- *BinFormat* = Determines by what timeframe the count should be applied, the default is a total count per day.
- *Threshold* = Determines when to alert, when using the default this is at least 10 events in a period of 1 day. 

If you have accounts that should be excluded you can create a variable with a global whitelist, for example service desk employees might trigger a lot of incidents.

#### Risk
An adversary has gained access to an account and tries to disover the network to perform lateral movement.

#### References
- https://learn.microsoft.com/en-us/windows/win32/winsock/net-exe-2
- https://www.trendmicro.com/en_us/research/19/f/shifting-tactics-breaking-down-ta505-groups-use-of-html-rats-and-other-techniques-in-latest-campaigns.html
- https://www.cybereason.com/blog/operation-cuckoobees-deep-dive-into-stealthy-winnti-techniques

## Defender XDR
```KQL
let StartTime = 2d;
let BinFormat = 1d;
let Threshold = 10;
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
| summarize TotalEvents = count(), TotalAccountsEvents = countif(NetActionType == "ACCOUNTS"), TotalGroupEvents = countif(NetActionType == "GROUP"), TotalUserEvents = countif(NetActionType == "USER"), TotalLocalGroupEvents = countif(NetActionType == "LOCALGROUP"), ExecutedCommands = make_set(ProcessCommandLine), LastEvent = arg_max(Timestamp, *), FirstEvent = arg_min(Timestamp, *) by AccountUpn, bin(Timestamp, BinFormat)
| where TotalEvents >= Threshold
| project-reorder FirstEvent, LastEvent, TotalEvents, TotalAccountsEvents, TotalGroupEvents, TotalLocalGroupEvents, TotalUserEvents, ExecutedCommands
```
## Sentinel
```KQL
let StartTime = 2d;
let BinFormat = 1d;
let Threshold = 10;
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
| summarize TotalEvents = count(), TotalAccountsEvents = countif(NetActionType == "ACCOUNTS"), TotalGroupEvents = countif(NetActionType == "GROUP"), TotalUserEvents = countif(NetActionType == "USER"), TotalLocalGroupEvents = countif(NetActionType == "LOCALGROUP"), ExecutedCommands = make_set(ProcessCommandLine), LastEvent = arg_max(TimeGenerated, *), FirstEvent = arg_min(TimeGenerated, *) by AccountUpn, bin(TimeGenerated, BinFormat)
| where TotalEvents >= Threshold
| project-reorder FirstEvent, LastEvent, TotalEvents, TotalAccountsEvents, TotalGroupEvents, TotalLocalGroupEvents, TotalUserEvents, ExecutedCommands
```
