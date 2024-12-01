# DigitalSide Threat-Intel suspicious and/or malicious IP addresses

#### Source: DigitalSide Threat-Intel
#### Feed information: https://osint.digitalside.it/
#### Feed link: https://osint.digitalside.it/Threat-Intel/lists/latestips.txt

## Defender XDR
```KQL
let ThreatIntelFeed = externaldata(DestIP: string)[@"https://osint.digitalside.it/Threat-Intel/lists/latestips.txt"] with (format="txt", ignoreFirstRecord=True);
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

## Sentinel
```KQL
let ThreatIntelFeed = externaldata(DestIP: string)[@"https://osint.digitalside.it/Threat-Intel/lists/latestips.txt"] with (format="txt", ignoreFirstRecord=True);
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
