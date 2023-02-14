# IPSum suspicious and/or malicious IP addresses (Level 5)

#### Source: IPSum
#### Feed information: https://github.com/stamparm/ipsum/
#### Feed link: https://raw.githubusercontent.com/stamparm/ipsum/master/levels/5.txt

### Defender For Endpoint
```
let ThreatIntelFeed = externaldata(DestIP: string)[@"https://raw.githubusercontent.com/stamparm/ipsum/master/levels/5.txt"] with (format="txt", ignoreFirstRecord=True);
let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';
let MaliciousIP = materialize (
       ThreatIntelFeed
       | where DestIP matches regex IPRegex
       | distinct DestIP
        );
DeviceNetworkEvents
| where RemoteIP in (MaliciousIP)
| project-reorder Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessAccountName
```


### Sentinel
```
let ThreatIntelFeed = externaldata(DestIP: string)[@"https://raw.githubusercontent.com/stamparm/ipsum/master/levels/5.txt"] with (format="txt", ignoreFirstRecord=True);
let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';
let MaliciousIP = materialize (
       ThreatIntelFeed
       | where DestIP matches regex IPRegex
       | distinct DestIP
        );
DeviceNetworkEvents
| where RemoteIP in (MaliciousIP)
| project-reorder TimeGenerated, DeviceName, RemoteIP, RemotePort, InitiatingProcessAccountName
```

