# Encoded Powershell Commands That Have Potentially Downloaded a File
----
### Defender For Endpoint

```
let EncodedList = dynamic(['-encodedcommand', '-enc']);
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



