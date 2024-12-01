# Find all the activities that launched a browser to open a URL from a compromised device.

## Defender XDR

```
let CompromisedDevice = "laptop.contoso.com";
let SearchWindow = 48h; //Customizable h = hours, d = days
DeviceEvents
| where Timestamp > ago(SearchWindow)
| where DeviceName == CompromisedDevice
| where ActionType == "BrowserLaunchedToOpenUrl"
| where InitiatingProcessFileName == "outlook.exe"
| where RemoteUrl startswith "http"
| project
     Timestamp,
     DeviceName,
     RemoteUrl,
     InitiatingProcessFileName,
     InitiatingProcessCommandLine,
     InitiatingProcessFolderPath
```
## Sentinel
```
let CompromisedDevice = "laptop.contoso.com";
let SearchWindow = 48h; //Customizable h = hours, d = days
DeviceEvents
| where TimeGenerated > ago(SearchWindow)
| where DeviceName == CompromisedDevice
| where ActionType == "BrowserLaunchedToOpenUrl"
| where InitiatingProcessFileName == "outlook.exe"
| where RemoteUrl startswith "http"
| project
     TimeGenerated,
     DeviceName,
     RemoteUrl,
     InitiatingProcessFileName,
     InitiatingProcessCommandLine,
     InitiatingProcessFolderPath
```



