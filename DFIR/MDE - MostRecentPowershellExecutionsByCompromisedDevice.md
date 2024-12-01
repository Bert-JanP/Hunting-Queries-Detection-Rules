# Show the last 100 Powershell executions from a compromised device
----
## Defender XDR

```
let CompromisedDevice = "laptop.contoso.com";
let SearchWindow = 48h; //Customizable h = hours, d = days
DeviceProcessEvents
| where Timestamp > ago(SearchWindow)
| where DeviceName == CompromisedDevice
| where AccountName != "system" // If you suspect that the system user is compromised, remove this filter.
| where InitiatingProcessFileName == "powershell.exe"
| sort by Timestamp
| top 100 by Timestamp
| project
     Timestamp,
     DeviceName,
     ActionType,
     FileName,
     ProcessCommandLine,
     AccountDomain,
     AccountName,
     InitiatingProcessCommandLine
```
## Sentinel
```
let CompromisedDevice = "laptop.contoso.com";
let SearchWindow = 48h; //Customizable h = hours, d = days
DeviceProcessEvents
| where TimeGenerated > ago(SearchWindow)
| where DeviceName == CompromisedDevice
| where AccountName != "system" // If you suspect that the system user is compromised, remove this filter.
| where InitiatingProcessFileName == "powershell.exe"
| sort by TimeGenerated
| top 100 by TimeGenerated
| project
     TimeGenerated,
     DeviceName,
     ActionType,
     FileName,
     ProcessCommandLine,
     AccountDomain,
     AccountName,
     InitiatingProcessCommandLine
```



