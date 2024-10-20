# Nltest Discovery Activities

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1482 | Domain Trust Discovery | https://attack.mitre.org/techniques/T1482/ |

#### Description
The windows utility Nltest is known to be used by adversaries to enumerate domain trusts. This detection is based on the *DeviceProcessEvents* table and triggers if more than 3 nltest queries are executed by a user on the same computer within 30 minutes. You can alter the variables yourself to tailor it to your environment.

In case you want to detect this behaviour with Windows Security Events, see: [Security Events - Nltest Discovery](../SecurityEvents/NltestDiscovery.md)

#### Risk
Adverseries perform discovery activities on your network.

#### References
- https://attack.mitre.org/software/S0359/
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731935(v=ws.11)

## Defender XDR
```KQL
let BinSize = 30m;
let Threshold = 3;
DeviceProcessEvents
| where ActionType == "ProcessCreated"
| where tolower(ProcessCommandLine) has "nltest.exe"
| extend ParsedCommandLine = tolower(parse_command_line(ProcessCommandLine, "windows")[1])
| where ParsedCommandLine has_any (NLTestParameters)
| summarize TotalQueries = count(), TotalUniqueQueries = dcount(ProcessCommandLine), Commands = make_set(ProcessCommandLine, 100), arg_max(Timestamp, *) by DeviceName, AccountUpn, bin(Timestamp, BinSize)
| where TotalQueries >= Threshold
```

## Sentinel
```KQL
let BinSize = 30m;
let Threshold = 3;
DeviceProcessEvents
| where ActionType == "ProcessCreated"
| where tolower(ProcessCommandLine) has "nltest.exe"
| extend ParsedCommandLine = tolower(parse_command_line(ProcessCommandLine, "windows")[1])
| where ParsedCommandLine has_any (NLTestParameters)
| summarize TotalQueries = count(), TotalUniqueQueries = dcount(ProcessCommandLine), Commands = make_set(ProcessCommandLine, 100), arg_max(TimeGenerated, *) by DeviceName, AccountUpn, bin(TimeGenerated, BinSize)
| where TotalQueries >= Threshold
```
