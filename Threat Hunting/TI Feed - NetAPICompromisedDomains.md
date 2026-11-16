# NetAPI Compromised Domains (malware and phishing, listed in the last 24 hours)

#### Source: NetAPI
#### Feed information: https://netapi.com/compromised-urls/
#### Feed link: https://netapi.com/api2/?method=compromised&dataset_type=url

## Defender XDR
```
let ThreatIntelFeed = externaldata(Domain: string)[@"https://netapi.com/api2/?method=compromised&dataset_type=url"] with (format="txt", ignoreFirstRecord=True);
let MalwareDomains = materialize (
     ThreatIntelFeed
     | extend Domain = tolower(trim(@"\s", Domain))
     | where isnotempty(Domain)
     | distinct Domain
     );
DeviceNetworkEvents
| where isnotempty(RemoteUrl)
| extend Host = tolower(tostring(parse_url(iff(RemoteUrl has "://", RemoteUrl, strcat("http://", RemoteUrl))).Host))
| extend Host = trim_start(@"www\.", Host)
| where Host in (MalwareDomains)
| project Timestamp, RemoteUrl, RemoteIP, DeviceName, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountDomain, InitiatingProcessAccountName
```


## Sentinel
```
let ThreatIntelFeed = externaldata(Domain: string)[@"https://netapi.com/api2/?method=compromised&dataset_type=url"] with (format="txt", ignoreFirstRecord=True);
let MalwareDomains = materialize (
     ThreatIntelFeed
     | extend Domain = tolower(trim(@"\s", Domain))
     | where isnotempty(Domain)
     | distinct Domain
     );
DeviceNetworkEvents
| where isnotempty(RemoteUrl)
| extend Host = tolower(tostring(parse_url(iff(RemoteUrl has "://", RemoteUrl, strcat("http://", RemoteUrl))).Host))
| extend Host = trim_start(@"www\.", Host)
| where Host in (MalwareDomains)
| project TimeGenerated, RemoteUrl, RemoteIP, DeviceName, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountDomain, InitiatingProcessAccountName
```
