# MontySecurity C2 Tracker All IPs

#### Source: MontySecurity
#### Feed information: https://github.com/montysecurity/C2-Tracker
#### Feed link: https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/all.txt

### Defender For Endpoint
```
let ThreatIntelFeed = externaldata(DestIP: string)[@"https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/all.txt"] with (format="txt", ignoreFirstRecord=True);
let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';
let MaliciousIP = materialize (
       ThreatIntelFeed
       | where DestIP matches regex IPRegex
       | distinct DestIP
        );
DeviceNetworkEvents
| where RemoteIP in (MaliciousIP)
| extend GeoIPInfo = geo_info_from_ip_address(RemoteIP)
| extend country = tostring(parse_json(GeoIPInfo).country), state = tostring(parse_json(GeoIPInfo).state), city = tostring(parse_json(GeoIPInfo).city), latitude = tostring(parse_json(GeoIPInfo).latitude), longitude = tostring(parse_json(GeoIPInfo).longitude)
| project-reorder Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessAccountName
```


### Sentinel
```
let ThreatIntelFeed = externaldata(DestIP: string)[@"https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/all.txt"] with (format="txt", ignoreFirstRecord=True);
let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';
let MaliciousIP = materialize (
       ThreatIntelFeed
       | where DestIP matches regex IPRegex
       | distinct DestIP
        );
DeviceNetworkEvents
| where RemoteIP in (MaliciousIP)
| extend GeoIPInfo = geo_info_from_ip_address(RemoteIP)
| extend country = tostring(parse_json(GeoIPInfo).country), state = tostring(parse_json(GeoIPInfo).state), city = tostring(parse_json(GeoIPInfo).city), latitude = tostring(parse_json(GeoIPInfo).latitude), longitude = tostring(parse_json(GeoIPInfo).longitude)
| project-reorder TimeGenerated, DeviceName, RemoteIP, RemotePort, InitiatingProcessAccountName
```

