# Encoded Powershell Commands With Web Request

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1134.002 | Access Token Manipulation: Create Process with Token |Access Token Manipulation: Create Process with Token|

#### Description
PowerShell can be used to retrieve the payload of malware. This can also be done with encoded powershell commands to evade detection. This query lists all encoded powershell executions that contain web requests. 

#### Risk
An advasary uses an encoded PowerShell command to collect a payload. 

#### References
- https://unit42.paloaltonetworks.com/unit42-pulling-back-the-curtains-on-encodedcommand-powershell-attacks/
- https://community.sophos.com/sophos-labs/b/blog/posts/decoding-malicious-powershell
- https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/tracking-detecting-and-thwarting-powershell-based-malware-and-attacks

## Defender XDR
```
let EncodedList = dynamic(['-encodedcommand', '-enc']); 
// For more results use line below en filter one above. This will also return more FPs.
// let EncodedList = dynamic(['-encodedcommand', '-enc', '-e']);
let DownloadVariables = dynamic(['WebClient', 'DownloadFile', 'DownloadData', 'DownloadString', 'WebRequest', 'Shellcode', 'http', 'https']);
let TimeFrame = 48h; //Customizable h = hours, d = days
DeviceProcessEvents
| where Timestamp > ago(TimeFrame)
| where ProcessCommandLine contains "powershell" or InitiatingProcessCommandLine contains "powershell"
| where ProcessCommandLine has_any (EncodedList) or InitiatingProcessCommandLine has_any (EncodedList)
| extend base64String = extract(@'\s+([A-Za-z0-9+/]{20}\S+$)', 1, ProcessCommandLine)
| extend DecodedCommandLine = base64_decode_tostring(base64String)
| extend DecodedCommandLineReplaceEmptyPlaces = replace_string(DecodedCommandLine, '\u0000', '')
| where isnotempty(base64String) and isnotempty(DecodedCommandLineReplaceEmptyPlaces)
| where DecodedCommandLineReplaceEmptyPlaces has_any (DownloadVariables)
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
let DownloadVariables = dynamic(['WebClient', 'DownloadFile', 'DownloadData', 'DownloadString', 'WebRequest', 'Shellcode', 'http', 'https']);
let TimeFrame = 48h; //Customizable h = hours, d = days
DeviceProcessEvents
| where TimeGenerated > ago(TimeFrame)
| where ProcessCommandLine contains "powershell" or InitiatingProcessCommandLine contains "powershell"
| where ProcessCommandLine has_any (EncodedList) or InitiatingProcessCommandLine has_any (EncodedList)
| extend base64String = extract(@'\s+([A-Za-z0-9+/]{20}\S+$)', 1, ProcessCommandLine)
| extend DecodedCommandLine = base64_decode_tostring(base64String)
| extend DecodedCommandLineReplaceEmptyPlaces = replace_string(DecodedCommandLine, '\u0000', '')
| where isnotempty(base64String) and isnotempty(DecodedCommandLineReplaceEmptyPlaces)
| where DecodedCommandLineReplaceEmptyPlaces has_any (DownloadVariables)
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



