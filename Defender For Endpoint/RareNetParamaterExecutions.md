# List Rare Net(1).exe Parameter Executions

## Query Information

#### Description
This query lists rare net.exe or net1.exe parameters that are executed. The following parameters can be used:
```PowerShell
The syntax of this command is:

NET
    [ ACCOUNTS | COMPUTER | CONFIG | CONTINUE | FILE | GROUP | HELP |
      HELPMSG | LOCALGROUP | PAUSE | SESSION | SHARE | START |
      STATISTICS | STOP | TIME | USE | USER | VIEW ]
```

The goal of the query is to determine which parameters are 'rare' in the context of your environment. This is done based on the userinput via the *RareThresholdNetActionType* variable. The default threshold is 10, whcih means that maximum 10 commands with that specific parameter should have been executed in the time between teh *StartTime* and the query execution time. The last part of the query lists all the rare parameters and the commandlines that have been executed.

#### Risk
Adversaries might use parameters that are not often used in your environment.

#### References
- https://learn.microsoft.com/en-us/windows/win32/winsock/net-exe-2

## Defender XDR
```KQL
let StartTime = 30d;
let RareThresholdNetActionType = 10; // Determine how rare a command must be to be included in the results
let RareNetParameters = DeviceProcessEvents
    | where Timestamp > startofday(ago(StartTime))
    | where FileName in ("net.exe", "net1.exe")
    | extend NetActionType = case(ProcessCommandLine has "accounts", "ACCOUNTS", 
        ProcessCommandLine has "computer", "COMPUTER", 
        ProcessCommandLine has "config", "CONFIG", 
        ProcessCommandLine has "continue", "CONTINUE", 
        ProcessCommandLine has "file", "FILE", 
        ProcessCommandLine has "group", "GROUP", 
        ProcessCommandLine has "help", "HELP", 
        ProcessCommandLine has "helpmsg", "HELPMSG", 
        ProcessCommandLine has "localgroup", "LOCALGROUP", 
        ProcessCommandLine has "pause", "PAUSE", 
        ProcessCommandLine has "session", "SESSION", 
        ProcessCommandLine has "share", "SHARE", 
        ProcessCommandLine has "start", "START", 
        ProcessCommandLine has "statistics", "STATISTICS", 
        ProcessCommandLine has "stop", "STOP", 
        ProcessCommandLine has "time", "TIME", 
        ProcessCommandLine has "use", "USE", 
        ProcessCommandLine has "user", "USER", 
        ProcessCommandLine has "view", "VIEW", "Else")
    | summarize TotalCommands = count() by NetActionType
    | where TotalCommands <= RareThresholdNetActionType
    | distinct NetActionType;
DeviceProcessEvents
| where Timestamp > startofday(ago(StartTime))
| where FileName in ("net.exe", "net1.exe")
| extend NetActionType = case(ProcessCommandLine has "accounts", "ACCOUNTS", 
        ProcessCommandLine has "computer", "COMPUTER", 
        ProcessCommandLine has "config", "CONFIG", 
        ProcessCommandLine has "continue", "CONTINUE", 
        ProcessCommandLine has "file", "FILE", 
        ProcessCommandLine has "group", "GROUP", 
        ProcessCommandLine has "help", "HELP", 
        ProcessCommandLine has "helpmsg", "HELPMSG", 
        ProcessCommandLine has "localgroup", "LOCALGROUP", 
        ProcessCommandLine has "pause", "PAUSE", 
        ProcessCommandLine has "session", "SESSION", 
        ProcessCommandLine has "share", "SHARE", 
        ProcessCommandLine has "start", "START", 
        ProcessCommandLine has "statistics", "STATISTICS", 
        ProcessCommandLine has "stop", "STOP", 
        ProcessCommandLine has "time", "TIME", 
        ProcessCommandLine has "use", "USE", 
        ProcessCommandLine has "user", "USER", 
        ProcessCommandLine has "view", "VIEW", "Else")
| where NetActionType in (RareNetParameters)
| project-reorder Timestamp, AccountUpn, ProcessCommandLine
```
## Sentinel
```KQL
let StartTime = 30d;
let RareThresholdNetActionType = 10; // Determine how rare a command must be to be included in the results
let RareNetParameters = DeviceProcessEvents
    | where TimeGenerated > startofday(ago(StartTime))
    | where FileName in ("net.exe", "net1.exe")
    | extend NetActionType = case(ProcessCommandLine has "accounts", "ACCOUNTS", 
        ProcessCommandLine has "computer", "COMPUTER", 
        ProcessCommandLine has "config", "CONFIG", 
        ProcessCommandLine has "continue", "CONTINUE", 
        ProcessCommandLine has "file", "FILE", 
        ProcessCommandLine has "group", "GROUP", 
        ProcessCommandLine has "help", "HELP", 
        ProcessCommandLine has "helpmsg", "HELPMSG", 
        ProcessCommandLine has "localgroup", "LOCALGROUP", 
        ProcessCommandLine has "pause", "PAUSE", 
        ProcessCommandLine has "session", "SESSION", 
        ProcessCommandLine has "share", "SHARE", 
        ProcessCommandLine has "start", "START", 
        ProcessCommandLine has "statistics", "STATISTICS", 
        ProcessCommandLine has "stop", "STOP", 
        ProcessCommandLine has "time", "TIME", 
        ProcessCommandLine has "use", "USE", 
        ProcessCommandLine has "user", "USER", 
        ProcessCommandLine has "view", "VIEW", "Else")
    | summarize TotalCommands = count() by NetActionType
    | where TotalCommands <= RareThresholdNetActionType
    | distinct NetActionType;
DeviceProcessEvents
| where TimeGenerated > startofday(ago(StartTime))
| where FileName in ("net.exe", "net1.exe")
| extend NetActionType = case(ProcessCommandLine has "accounts", "ACCOUNTS", 
        ProcessCommandLine has "computer", "COMPUTER", 
        ProcessCommandLine has "config", "CONFIG", 
        ProcessCommandLine has "continue", "CONTINUE", 
        ProcessCommandLine has "file", "FILE", 
        ProcessCommandLine has "group", "GROUP", 
        ProcessCommandLine has "help", "HELP", 
        ProcessCommandLine has "helpmsg", "HELPMSG", 
        ProcessCommandLine has "localgroup", "LOCALGROUP", 
        ProcessCommandLine has "pause", "PAUSE", 
        ProcessCommandLine has "session", "SESSION", 
        ProcessCommandLine has "share", "SHARE", 
        ProcessCommandLine has "start", "START", 
        ProcessCommandLine has "statistics", "STATISTICS", 
        ProcessCommandLine has "stop", "STOP", 
        ProcessCommandLine has "time", "TIME", 
        ProcessCommandLine has "use", "USE", 
        ProcessCommandLine has "user", "USER", 
        ProcessCommandLine has "view", "VIEW", "Else")
| where NetActionType in (RareNetParameters)
| project-reorder TimeGenerated, AccountUpn, ProcessCommandLine
```
