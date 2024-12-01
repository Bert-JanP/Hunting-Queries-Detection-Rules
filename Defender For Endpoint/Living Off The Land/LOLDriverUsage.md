# LOL Driver Usage

## Query Information

#### Description
This query uses different tables to list all actions related to LOL drivers. It combines DeviceFileEvents, DeviceProcessEvents and DeviceImageLoadEvents to list the results. The lol drivers project is a curated list of Windows drivers used by adversaries to bypass security controls and carry out attacks. The project helps security professionals stay informed and mitigate potential threats. Those drivers should preferable be removed from your environment.

#### Risk
An adversary uses a loldriver to perform malicious activities.

#### References
- https://www.loldrivers.io/

## Defender XDR
```KQL
let LolDriverSHA1 = externaldata(SHA1: string)[@"https://raw.githubusercontent.com/magicsword-io/LOLDrivers/main/detections/hashes/authentihash_samples.sha1"] with (format="txt", ignoreFirstRecord=False);
// Combine results to get ImageLoads, FileActions and Process Events
union isfuzzy=true
(DeviceFileEvents
| where SHA1 in~ (LolDriverSHA1)),
(DeviceProcessEvents
| where InitiatingProcessSHA1 in~ (LolDriverSHA1) or SHA1 in~ (LolDriverSHA1)),
(DeviceImageLoadEvents
| where SHA1 in (LolDriverSHA1))
| project-reorder Timestamp, DeviceName, FolderPath, ProcessCommandLine
```
## Sentinel
```KQL
let LolDriverSHA1 = externaldata(SHA1: string)[@"https://raw.githubusercontent.com/magicsword-io/LOLDrivers/main/detections/hashes/authentihash_samples.sha1"] with (format="txt", ignoreFirstRecord=False);
// Combine results to get ImageLoads, FileActions and Process Events
union isfuzzy=true
(DeviceFileEvents
| where SHA1 in~ (LolDriverSHA1)),
(DeviceProcessEvents
| where InitiatingProcessSHA1 in~ (LolDriverSHA1) or SHA1 in~ (LolDriverSHA1)),
(DeviceImageLoadEvents
| where SHA1 in (LolDriverSHA1))
| project-reorder TimeGenerated, DeviceName, FolderPath, ProcessCommandLine
```


