# Encoded Powershell Commands That Have Potentially Performed Recon Activities
----
### Defender For Endpoint

```
let EncodedList = dynamic(['-encodedcommand', '-enc']);
let ReconVariables = dynamic(['Get-ADGroupMember', 'Get-ADComputer', 'Get-ADUser', 'Get-NetGPOGroup', 'net user', 'whoami', 'net group', 'hostname', 'netsh firewall', 'tasklist', 'arp', 'systeminfo']);
let TimeFrame = 48h; //Customizable h = hours, d = days
DeviceProcessEvents
| where Timestamp > ago(TimeFrame)
| where ProcessCommandLine contains "powershell" or InitiatingProcessCommandLine contains "powershell"
| where ProcessCommandLine has_any (EncodedList) or InitiatingProcessCommandLine has_any (EncodedList)
| extend base64String = extract(@'\s+([A-Za-z0-9+/]{20}\S+$)', 1, ProcessCommandLine)
| extend DecodedCommandLine = base64_decode_tostring(base64String)
| extend DecodedCommandLineReplaceEmptyPlaces = replace_string(DecodedCommandLine, '\u0000', '')
| where isnotempty(base64String) and isnotempty(DecodedCommandLineReplaceEmptyPlaces)
| where DecodedCommandLineReplaceEmptyPlaces has_any (ReconVariables)
| project
     Timestamp,
     ActionType,
     DecodedCommandLineReplaceEmptyPlaces,
     ProcessCommandLine,
     InitiatingProcessCommandLine,
     DeviceName,
     AccountName,
     AccountDomain

```
### Sentinel
```
let EncodedList = dynamic(['-encodedcommand', '-enc']);
let ReconVariables = dynamic(['Get-ADGroupMember', 'Get-ADComputer', 'Get-ADUser', 'Get-NetGPOGroup', 'net user', 'whoami', 'net group', 'hostname', 'netsh firewall', 'tasklist', 'arp', 'systeminfo']);
let TimeFrame = 48h; //Customizable h = hours, d = days
DeviceProcessEvents
| where TimeGenerated > ago(TimeFrame)
| where ProcessCommandLine contains "powershell" or InitiatingProcessCommandLine contains "powershell"
| where ProcessCommandLine has_any (EncodedList) or InitiatingProcessCommandLine has_any (EncodedList)
| extend base64String = extract(@'\s+([A-Za-z0-9+/]{20}\S+$)', 1, ProcessCommandLine)
| extend DecodedCommandLine = base64_decode_tostring(base64String)
| extend DecodedCommandLineReplaceEmptyPlaces = replace_string(DecodedCommandLine, '\u0000', '')
| where isnotempty(base64String) and isnotempty(DecodedCommandLineReplaceEmptyPlaces)
| where DecodedCommandLineReplaceEmptyPlaces has_any (ReconVariables)
| project
     TimeGenerated,
     ActionType,
     DecodedCommandLineReplaceEmptyPlaces,
     ProcessCommandLine,
     InitiatingProcessCommandLine,
     DeviceName,
     AccountName,
     AccountDomain
```



