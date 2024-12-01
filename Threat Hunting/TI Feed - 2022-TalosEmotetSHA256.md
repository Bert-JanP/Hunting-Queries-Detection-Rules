# Emotet SHA256 IOC Feed

## Query Information

#### Description
Emotet SHA256 IOC Feed
Source: Talos Intelligence
Feed information: https://blog.talosintelligence.com/emotet-coming-in-hot/
Feed link: https://github.com/Cisco-Talos/IOCs/blob/main/2022/11/Emotet_parents.txt

## Defender XDR
```KQL
let Emotetsha256 = externaldata(sha256: string)[@"https://githubraw.com/Cisco-Talos/IOCs/main/2022/11/Emotet_parents.txt"] with (format="txt", ignoreFirstRecord=True);
DeviceFileEvents
| where SHA256 in (Emotetsha256)
| project Timestamp, FileName, SHA256, DeviceName, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountDomain, InitiatingProcessAccountName
```

## Sentinel
```KQL
let Emotetsha256 = externaldata(sha256: string)[@"https://githubraw.com/Cisco-Talos/IOCs/main/2022/11/Emotet_parents.txt"] with (format="txt", ignoreFirstRecord=True);
DeviceFileEvents
| where SHA256 in (Emotetsha256)
| project TimeGenerated, FileName, SHA256, DeviceName, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountDomain, InitiatingProcessAccountName
```