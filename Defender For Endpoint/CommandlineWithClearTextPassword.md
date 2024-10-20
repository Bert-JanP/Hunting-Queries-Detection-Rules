# Commandlines with cleartext passwords

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1552 | Unsecured Credentials | https://attack.mitre.org/techniques/T1552/ |

#### Description
Adversaries may search compromised systems to find and obtain insecurely stored credentials. It is best practice to not have unsecured credentials in use, therefore this query can help you to list accounts that use passwords on the commandline. Commandlines are often logged for various reasons, thus also accessible for adversaries. This query can guide you to which user use cleartext passwords on the commandline by providing the TotalExecutions, UniqueCommands, Commandlines, UniqueUsers and Usernames for each device. 

To limit false positives a filter can be used to only filter if both a username and a cleartext password is found.

#### Risk
Cleartext passwords can be logged and used by attackers to gain access to accounts.

## Defender XDR
```KQL
DeviceProcessEvents
| where ProcessCommandLine has_all ("-password", "*")
| extend UserName = tostring(extract(@'user(?:name)?[=\s](\w+)', 1, ProcessCommandLine))
// Optionally only include results with UserName for less False Positives
//| where isnotempty(UserName)
| summarize TotalExecutions = count(), UniqueCommands = dcount(ProcessCommandLine), CommandLines = make_set(ProcessCommandLine, 1000), UniqueUsers = dcount(UserName), UserNames = make_set(UserName) by DeviceName
| sort by UniqueUsers, UniqueCommands, TotalExecutions
```
## Sentinel
```KQL
DeviceProcessEvents
| where ProcessCommandLine has_all ("-password", "*")
| extend UserName = tostring(extract(@'user(?:name)?[=\s](\w+)', 1, ProcessCommandLine))
// Optionally only include results with UserName for less False Positives
//| where isnotempty(UserName)
| summarize TotalExecutions = count(), UniqueCommands = dcount(ProcessCommandLine), CommandLines = make_set(ProcessCommandLine, 1000), UniqueUsers = dcount(UserName), UserNames = make_set(UserName) by DeviceName
| sort by UniqueUsers, UniqueCommands, TotalExecutions
```
