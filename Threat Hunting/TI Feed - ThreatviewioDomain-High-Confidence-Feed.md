# Threatview Domain High Confidence Feed

#### Source: Threatview
#### Feed information: https://threatview.io/
#### Feed link: https://threatview.io/Downloads/DOMAIN-High-Confidence-Feed.txt

### Defender XDR
```KQL
let ThreatIntelFeed = externaldata(Domain: string)[@"https://threatview.io/Downloads/DOMAIN-High-Confidence-Feed.txt"] with (format="txt", ignoreFirstRecord=True);
let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';
DeviceNetworkEvents
| where tolower(RemoteUrl) has_any (ThreatIntelFeed)
| extend GeoIPInfo = geo_info_from_ip_address(RemoteIP)
| extend country = tostring(parse_json(GeoIPInfo).country), state = tostring(parse_json(GeoIPInfo).state), city = tostring(parse_json(GeoIPInfo).city), latitude = tostring(parse_json(GeoIPInfo).latitude), longitude = tostring(parse_json(GeoIPInfo).longitude)
| project-reorder Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessAccountName
```

### Sentinel
```KQL
let ThreatIntelFeed = externaldata(Domain: string)[@"https://threatview.io/Downloads/DOMAIN-High-Confidence-Feed.txt"] with (format="txt", ignoreFirstRecord=True);
let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';
DeviceNetworkEvents
| where tolower(RemoteUrl) has_any (ThreatIntelFeed)
| extend GeoIPInfo = geo_info_from_ip_address(RemoteIP)
| extend country = tostring(parse_json(GeoIPInfo).country), state = tostring(parse_json(GeoIPInfo).state), city = tostring(parse_json(GeoIPInfo).city), latitude = tostring(parse_json(GeoIPInfo).latitude), longitude = tostring(parse_json(GeoIPInfo).longitude)
| project-reorder TimeGenerated, DeviceName, RemoteIP, RemotePort, InitiatingProcessAccountName
```

