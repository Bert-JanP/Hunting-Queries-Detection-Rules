# Command & Control intel Feeds (IP Based)

#### Source: https://github.com/drb-ra
#### Feed information: https://github.com/drb-ra/C2IntelFeeds
#### Feed link: https://github.com/drb-ra/C2IntelFeeds/blob/master/feeds/IPC2s-30day.csv

## Defender XDR
```
let C2IntelFeeds = externaldata(IP: string, ioc:string)[@"https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv"] with (format="csv", ignoreFirstRecord=True);
let IPList = C2IntelFeeds
| project IP;
DeviceNetworkEvents
| where RemoteIP in (IPList)
| join C2IntelFeeds on $left.RemoteIP == $right.IP
| extend GeoIPInfo = geo_info_from_ip_address(RemoteIP)
| extend country = tostring(parse_json(GeoIPInfo).country), state = tostring(parse_json(GeoIPInfo).state), city = tostring(parse_json(GeoIPInfo).city), latitude = tostring(parse_json(GeoIPInfo).latitude), longitude = tostring(parse_json(GeoIPInfo).longitude)
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, ioc
```


## Sentinel
```
let C2IntelFeeds = externaldata(IP: string, ioc:string)[@"https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv"] with (format="csv", ignoreFirstRecord=True);
let IPList = C2IntelFeeds
| project IP;
DeviceNetworkEvents
| where RemoteIP in (IPList)
| join C2IntelFeeds on $left.RemoteIP == $right.IP
| extend GeoIPInfo = geo_info_from_ip_address(RemoteIP)
| extend country = tostring(parse_json(GeoIPInfo).country), state = tostring(parse_json(GeoIPInfo).state), city = tostring(parse_json(GeoIPInfo).city), latitude = tostring(parse_json(GeoIPInfo).latitude), longitude = tostring(parse_json(GeoIPInfo).longitude)
| project TimeGenerated, DeviceName, RemoteIP, RemotePort, RemoteUrl, ioc
```

