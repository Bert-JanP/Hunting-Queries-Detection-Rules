# AbuseCH Botnet C2 Indicators Of Compromise

#### Source: AbuseCH
#### Feed information: https://feodotracker.abuse.ch/blocklist/
#### Feed link: https://feodotracker.abuse.ch/downloads/ipblocklist.txt

### Defender For Endpoint
```
let BotnetIP = externaldata(IP: string)[@"https://feodotracker.abuse.ch/downloads/ipblocklist.txt"] with (format="txt", ignoreFirstRecord=True);
let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';
let MaliciousIP = materialize (
     BotnetIP
     | where IP matches regex IPRegex
     | distinct IP
     );
DeviceNetworkEvents
| where RemoteIP in (MaliciousIP)
| project-reorder
     Timestamp,
     ActionType,
     RemoteIP,
     RemotePort,
     LocalPort,
     Protocol,
     DeviceName,
     InitiatingProcessCommandLine,
     InitiatingProcessFolderPath
```


### Sentinel
```
let BotnetIP = externaldata(IP: string)[@"https://feodotracker.abuse.ch/downloads/ipblocklist.txt"] with (format="txt", ignoreFirstRecord=True);
let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';
let MaliciousIP = materialize (
     BotnetIP
     | where IP matches regex IPRegex
     | distinct IP
     );
DeviceNetworkEvents
| where RemoteIP in (MaliciousIP)
| project-reorder
     TimeGenerated,
     ActionType,
     RemoteIP,
     RemotePort,
     LocalPort,
     Protocol,
     DeviceName,
     InitiatingProcessCommandLine,
     InitiatingProcessFolderPath
```