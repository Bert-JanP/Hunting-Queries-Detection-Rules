# Command & Control intel Feeds (Domain Based)

#### Source: https://github.com/drb-ra
#### Feed information: https://github.com/drb-ra/C2IntelFeeds
#### Feed link: https://github.com/drb-ra/C2IntelFeeds/blob/master/feeds/domainC2swithURLwithIP-filter-abused.csv

## Defender XDR
```
// Collect Remote data
let C2IntelFeeds = externaldata(Domain: string, ioc:string, path:string, IP:string)[@"https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/domainC2swithURLwithIP-filter-abused.csv"] with (format="csv", ignoreFirstRecord=True);
// Generate list that can be used to filter DeviceNetworkEvents
let DomainList = C2IntelFeeds
| distinct Domain;
DeviceNetworkEvents
// Filter only on C2 Domains
| extend ToLowerUrl = tolower(RemoteUrl)
| where RemoteUrl has_any (DomainList)
// Lookup the C2IntelFeed information.
| lookup C2IntelFeeds on $left.RemoteIP == $right.IP
| extend GeoIPInfo = geo_info_from_ip_address(RemoteIP)
| extend country = tostring(parse_json(GeoIPInfo).country), state = tostring(parse_json(GeoIPInfo).state), city = tostring(parse_json(GeoIPInfo).city), latitude = tostring(parse_json(GeoIPInfo).latitude), longitude = tostring(parse_json(GeoIPInfo).longitude)
| project-reorder Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl
```


## Sentinel
```
// Collect Remote data
let C2IntelFeeds = externaldata(Domain: string, ioc:string, path:string, IP:string)[@"https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/domainC2swithURLwithIP-filter-abused.csv"] with (format="csv", ignoreFirstRecord=True);
// Generate list that can be used to filter DeviceNetworkEvents
let DomainList = C2IntelFeeds
| distinct Domain;
DeviceNetworkEvents
// Filter only on C2 Domains
| extend ToLowerUrl = tolower(RemoteUrl)
| where RemoteUrl has_any (DomainList)
// Lookup the C2IntelFeed information.
| lookup C2IntelFeeds on $left.RemoteIP == $right.IP
| extend GeoIPInfo = geo_info_from_ip_address(RemoteIP)
| extend country = tostring(parse_json(GeoIPInfo).country), state = tostring(parse_json(GeoIPInfo).state), city = tostring(parse_json(GeoIPInfo).city), latitude = tostring(parse_json(GeoIPInfo).latitude), longitude = tostring(parse_json(GeoIPInfo).longitude)
| project-reorder TimeGenerated, DeviceName, RemoteIP, RemotePort, RemoteUrl
```


