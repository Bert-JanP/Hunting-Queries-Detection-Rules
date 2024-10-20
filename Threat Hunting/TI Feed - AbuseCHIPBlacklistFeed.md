# Abuse.ch Botnet C2 IP Blacklist to detect external C2 connections

#### Source: Abuse.ch
#### Feed link: https://sslbl.abuse.ch/blacklist/sslipblacklist.txt

### Defender XDR
```
let ThreatIntelFeed = externaldata(DestIP: string)[@"https://sslbl.abuse.ch/blacklist/sslipblacklist.txt"] with (format="txt", ignoreFirstRecord=True);
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
```


### Sentinel
```
let ThreatIntelFeed = externaldata(DestIP: string)[@"https://sslbl.abuse.ch/blacklist/sslipblacklist.txt"] with (format="txt", ignoreFirstRecord=True);
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
```
