# Hunt for the 20 most unusual connections made by Office. 

## Query Information

#### Description
Hunt for the 20 most unusual connections made by Office. 

## Defender XDR
```KQL
let ConnectionsMadeByOfficeRegKey = @'\SOFTWARE\Microsoft\Office\16.0\Common\Internet\Server Cache';
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryKey contains ConnectionsMadeByOfficeRegKey
| extend Connection = split(RegistryKey, ConnectionsMadeByOfficeRegKey, 1)
| extend Domain = extract(@"([a-z0-9|-]+\.)*[a-z0-9|-]+\.[a-z]+", 0, RegistryKey)
| summarize count(), InitatingDevices = make_set(DeviceName) by Domain
| top 20 by count_ asc
```

## Sentinel
```KQL
let ConnectionsMadeByOfficeRegKey = @'\SOFTWARE\Microsoft\Office\16.0\Common\Internet\Server Cache';
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryKey contains ConnectionsMadeByOfficeRegKey
| extend Connection = split(RegistryKey, ConnectionsMadeByOfficeRegKey, 1)
| extend Domain = extract(@"([a-z0-9|-]+\.)*[a-z0-9|-]+\.[a-z]+", 0, RegistryKey)
| summarize count(), InitatingDevices = make_set(DeviceName) by Domain
| top 20 by count_ asc
```
