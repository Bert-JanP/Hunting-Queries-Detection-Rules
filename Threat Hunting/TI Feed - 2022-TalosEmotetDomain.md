# Emotet Domain IOC Feed

#### Source: Talos Intelligence
#### Feed information: https://blog.talosintelligence.com/emotet-coming-in-hot/
#### Feed link: https://github.com/Cisco-Talos/IOCs/blob/main/2022/11/Emotet_contacted_domains.txt

### Defender For Endpoint
```
let EmotetDomain = externaldata(Domain: string)[@"https://raw.githubusercontent.com/Cisco-Talos/IOCs/main/2022/11/Emotet_contacted_domains.txt"] with (format="txt", ignoreFirstRecord=True);
DeviceNetworkEvents
| where RemoteUrl in~ (EmotetDomain)
| project Timestamp, RemoteUrl, RemoteIP, DeviceName, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountDomain, InitiatingProcessAccountName
```


### Sentinel
```
let EmotetDomain = externaldata(Domain: string)[@"https://raw.githubusercontent.com/Cisco-Talos/IOCs/main/2022/11/Emotet_contacted_domains.txt"] with (format="txt", ignoreFirstRecord=True);
DeviceNetworkEvents
| where RemoteUrl in~ (EmotetDomain)
| project TimeGenerated, RemoteUrl, RemoteIP, DeviceName, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountDomain, InitiatingProcessAccountName
```

