# NetAPI IP addresses that have attacked NetAPI honeypot sensors in the last 48 hours

#### Source: NetAPI
#### Feed information: https://netapi.com/compromised-ips/
#### Feed link: https://netapi.com/api2/?method=compromised&dataset_type=ip

## Defender XDR
```
let ThreatIntelFeed = externaldata(DestIP: string)[@"https://netapi.com/api2/?method=compromised&dataset_type=ip"] with (format="txt", ignoreFirstRecord=True);
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


## Sentinel
```
let ThreatIntelFeed = externaldata(DestIP: string)[@"https://netapi.com/api2/?method=compromised&dataset_type=ip"] with (format="txt", ignoreFirstRecord=True);
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
