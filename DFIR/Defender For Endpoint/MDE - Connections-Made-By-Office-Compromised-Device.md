# Find all the connections that have been made by Office from a compromised device. 
----
## Defender XDR

```
let ConnectionsMadeByOfficeRegKey = @'\SOFTWARE\Microsoft\Office\16.0\Common\Internet\Server Cache';
let CompromisedDevice = "laptop1";
let SearchWindow = 7d; //Customizable h = hours, d = days
DeviceRegistryEvents
| where Timestamp > ago(SearchWindow)
| where DeviceName == CompromisedDevice
| where ActionType == "RegistryValueSet"
| where RegistryKey contains ConnectionsMadeByOfficeRegKey
| extend Connection = split(RegistryKey, @"SOFTWARE\Microsoft\Office\16.0\Common\Internet\Server Cache", 1)
| extend Domain = extract(@"([a-z0-9|-]+\.)*[a-z0-9|-]+\.[a-z]+", 0, RegistryKey)
| project-reorder Domain, Connection
```
## Sentinel
```
let ConnectionsMadeByOfficeRegKey = @'\SOFTWARE\Microsoft\Office\16.0\Common\Internet\Server Cache';
let CompromisedDevice = "laptop1";
let SearchWindow = 7d; //Customizable h = hours, d = days
DeviceRegistryEvents
| where TimeGenerated > ago(SearchWindow)
| where DeviceName == CompromisedDevice
| where ActionType == "RegistryValueSet"
| where RegistryKey contains ConnectionsMadeByOfficeRegKey
| extend Connection = split(RegistryKey, @"SOFTWARE\Microsoft\Office\16.0\Common\Internet\Server Cache", 1)
| extend Domain = extract(@"([a-z0-9|-]+\.)*[a-z0-9|-]+\.[a-z]+", 0, RegistryKey)
| project-reorder Domain, Connection
```



