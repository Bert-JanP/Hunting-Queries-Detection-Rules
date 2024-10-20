# DigitalSide Threat-Intel suspicious and/or malicious domains

#### Source: DigitalSide Threat-Intel
#### Feed information: https://osint.digitalside.it/
#### Feed link: https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt

### Defender XDR
```KQL
let ThreatIntelFeed = externaldata(Domain: string)[@"https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt"] with (format="txt", ignoreFirstRecord=True);
DeviceNetworkEvents
| where RemoteUrl has_any (ThreatIntelFeed)
| project Timestamp, RemoteUrl, RemoteIP, DeviceName, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountDomain, InitiatingProcessAccountName
```

### Sentinel
```KQL
let ThreatIntelFeed = externaldata(Domain: string)[@"https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt"] with (format="txt", ignoreFirstRecord=True);
DeviceNetworkEvents
| where RemoteUrl has_any (ThreatIntelFeed)
| project TimeGenerated, RemoteUrl, RemoteIP, DeviceName, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountDomain, InitiatingProcessAccountName
```
