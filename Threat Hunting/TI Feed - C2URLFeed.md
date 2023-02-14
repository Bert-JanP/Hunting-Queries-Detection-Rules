# Command & Control intel Feeds (Domain Based)

#### Source: https://github.com/drb-ra
#### Feed information: https://github.com/drb-ra/C2IntelFeeds
#### Feed link: https://github.com/drb-ra/C2IntelFeeds/blob/master/feeds/domainC2swithURLwithIP.csv

### Defender For Endpoint
```
// Collect Remote data
let C2IntelFeeds = externaldata(Domain: string, ioc:string, path:string, ip:string)[@"https://github.com/drb-ra/C2IntelFeeds/blob/master/feeds/domainC2swithURLwithIP.csv"] with (format="csv", ignoreFirstRecord=True);
// Generate list that can be used to filter DeviceNetworkEvents
let DomainList = C2IntelFeeds
| project Domain;
DeviceNetworkEvents
// Filter only on C2 Domains
| where RemoteIP has_any (DomainList)
// Join the C2IntelFeed information
| join C2IntelFeeds on $left.RemoteIP == $right.IP
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, ioc, path
```


### Sentinel
```
// Collect Remote data
let C2IntelFeeds = externaldata(Domain: string, ioc:string, path:string, ip:string)[@"https://github.com/drb-ra/C2IntelFeeds/blob/master/feeds/domainC2swithURLwithIP.csv"] with (format="csv", ignoreFirstRecord=True);
// Generate list that can be used to filter DeviceNetworkEvents
let DomainList = C2IntelFeeds
| project Domain;
DeviceNetworkEvents
// Filter only on C2 Domains
| where RemoteIP has_any (DomainList)
// Join the C2IntelFeed information
| join C2IntelFeeds on $left.RemoteIP == $right.IP
| project TimeGenerated, DeviceName, RemoteIP, RemotePort, RemoteUrl, ioc, path
```


