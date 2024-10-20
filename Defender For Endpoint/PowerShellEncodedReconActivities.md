# Encoded Powershell Commands That Have Potentially Performed Recon Activities

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1027 | Obfuscated Files or Information |https://attack.mitre.org/techniques/T1027/ |
| T1087.004 | Account Discovery: Cloud Account | https://attack.mitre.org/techniques/T1087/004/ |

#### Description
PowerShell can be used send discovery requests, for example listing AD users or Groups. This can also be done with encoded powershell commands to evade detection. This query lists all encoded powershell executions that possible discovery activities. 

#### Risk
An advasary uses an encoded PowerShell command to collect information on of other systems or Active Directory. 

#### References
- https://unit42.paloaltonetworks.com/unit42-pulling-back-the-curtains-on-encodedcommand-powershell-attacks/
- https://community.sophos.com/sophos-labs/b/blog/posts/decoding-malicious-powershell
- https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/tracking-detecting-and-thwarting-powershell-based-malware-and-attacks

## Defender XDR

```
let EncodedList = dynamic(['-encodedcommand', '-enc']); 
// For more results use line below en filter one above. This will also return more FPs.
// let EncodedList = dynamic(['-encodedcommand', '-enc', '-e']);
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
// Search in the decoded commandline for Recon variables
| where DecodedCommandLineReplaceEmptyPlaces has_any (ReconVariables)
| project-reorder 
     Timestamp,
     ActionType,
     DecodedCommandLineReplaceEmptyPlaces,
     ProcessCommandLine,
     InitiatingProcessCommandLine,
     DeviceName,
     AccountName,
     AccountDomain
```
## Sentinel
```
let EncodedList = dynamic(['-encodedcommand', '-enc']); 
// For more results use line below en filter one above. This will also return more FPs.
// let EncodedList = dynamic(['-encodedcommand', '-enc', '-e']);
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
// Search in the decoded commandline for Recon variables
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



