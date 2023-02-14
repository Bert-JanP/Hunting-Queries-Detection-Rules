# Command & Control intel Feeds (IP Based)

#### Source: https://github.com/drb-ra
#### Feed information: https://github.com/drb-ra/C2IntelFeeds
#### Feed link: https://github.com/drb-ra/C2IntelFeeds/blob/master/feeds/IPC2s-30day.csv

### Defender For Endpoint
```
let C2IntelFeeds = externaldata(IP: string, ioc:string)[@"https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv"] with (format="csv", ignoreFirstRecord=True);
let IPList = C2IntelFeeds
| project IP;
DeviceNetworkEvents
| where RemoteIP in (IPList)
| join C2IntelFeeds on $left.RemoteIP == $right.IP
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, ioc
```


### Sentinel
```
let C2IntelFeeds = externaldata(IP: string, ioc:string)[@"https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv"] with (format="csv", ignoreFirstRecord=True);
let IPList = C2IntelFeeds
| project IP;
DeviceNetworkEvents
| where RemoteIP in (IPList)
| join C2IntelFeeds on $left.RemoteIP == $right.IP
| project TimeGenerated, DeviceName, RemoteIP, RemotePort, RemoteUrl, ioc
```

