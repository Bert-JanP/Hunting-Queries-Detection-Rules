# Encoded Powershell Executions by Device
----
### Defender For Endpoint

```
let EncodedList = dynamic(['-encodedcommand', '-enc']);
let TimeFrame = 48h; //Customizable h = hours, d = days
DeviceProcessEvents
| where Timestamp > ago(TimeFrame)
| where ProcessCommandLine contains "powershell" or InitiatingProcessCommandLine contains "powershell"
| where ProcessCommandLine has_any (EncodedList) or InitiatingProcessCommandLine has_any (EncodedList)
| extend base64String = extract(@'\s+([A-Za-z0-9+/]{20}\S+$)', 1, ProcessCommandLine)
| extend DecodedCommandLine = base64_decode_tostring(base64String)
| where not(isempty(base64String) and isempty(DecodedCommandLine))
| summarize TotalEncodedExecutions = count() by DeviceName
| sort by TotalEncodedExecutions
```
### Sentinel
```
let EncodedList = dynamic(['-encodedcommand', '-enc']);
let TimeFrame = 48h; //Customizable h = hours, d = days
DeviceProcessEvents
| where TimeGenerated > ago(TimeFrame)
| where ProcessCommandLine contains "powershell" or InitiatingProcessCommandLine contains "powershell"
| where ProcessCommandLine has_any (EncodedList) or InitiatingProcessCommandLine has_any (EncodedList)
| extend base64String = extract(@'\s+([A-Za-z0-9+/]{20}\S+$)', 1, ProcessCommandLine)
| extend DecodedCommandLine = base64_decode_tostring(base64String)
| where not(isempty(base64String) and isempty(DecodedCommandLine))
| summarize TotalEncodedExecutions = count() by DeviceName
| sort by TotalEncodedExecutions
```



