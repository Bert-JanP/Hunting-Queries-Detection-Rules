# AbuseCH Botnet C2 Indicators Of Compromise

#### Source: AbuseCH
#### Feed information: https://feodotracker.abuse.ch/blocklist/
#### Feed link: https://feodotracker.abuse.ch/downloads/ipblocklist.txt

### Defender For Endpoint
```
let BotnetIP = externaldata(IP: string)[@"https://feodotracker.abuse.ch/downloads/ipblocklist.txt"] with (format="txt", ignoreFirstRecord=True);
let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';
let MaliciousIP = materialize (
     BotnetIP
     | where IP matches regex IPRegex
     | distinct IP
     );
DeviceNetworkEvents
| where RemoteIP in (MaliciousIP)
| extend GeoIPInfo = geo_info_from_ip_address(RemoteIP)
| extend country = tostring(parse_json(GeoIPInfo).country), state = tostring(parse_json(GeoIPInfo).state), city = tostring(parse_json(GeoIPInfo).city), latitude = tostring(parse_json(GeoIPInfo).latitude), longitude = tostring(parse_json(GeoIPInfo).longitude)
| project-reorder
     Timestamp,
     ActionType,
     RemoteIP,
     RemotePort,
     LocalPort,
     Protocol,
     DeviceName,
     InitiatingProcessCommandLine,
     InitiatingProcessFolderPath
```


### Sentinel
```
let BotnetIP = externaldata(IP: string)[@"https://feodotracker.abuse.ch/downloads/ipblocklist.txt"] with (format="txt", ignoreFirstRecord=True);
let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';
let MaliciousIP = materialize (
     BotnetIP
     | where IP matches regex IPRegex
     | distinct IP
     );
DeviceNetworkEvents
| where RemoteIP in (MaliciousIP)
| extend GeoIPInfo = geo_info_from_ip_address(RemoteIP)
| extend country = tostring(parse_json(GeoIPInfo).country), state = tostring(parse_json(GeoIPInfo).state), city = tostring(parse_json(GeoIPInfo).city), latitude = tostring(parse_json(GeoIPInfo).latitude), longitude = tostring(parse_json(GeoIPInfo).longitude)
| project-reorder
     TimeGenerated,
     ActionType,
     RemoteIP,
     RemotePort,
     LocalPort,
     Protocol,
     DeviceName,
     InitiatingProcessCommandLine,
     InitiatingProcessFolderPath
```