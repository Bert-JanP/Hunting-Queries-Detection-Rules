# JA3 Fingerprint Blacklist

#### Source: https://sslbl.abuse.ch/blacklist/#ja3-fingerprints-csv
#### Feed information: https://sslbl.abuse.ch/blacklist/#ja3-fingerprints-csv
#### Feed link: https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv

### Defender For Endpoint
```KQL
let JA3Feed = externaldata(ja3_md5:string) [@"https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv"] with (format="txt", ignoreFirstRecord=True);
// Extract JA3 Hashes From Feed
let ExtractedJA3Hashes = JA3Feed
    | extend JA3Hash = extract('[a-f0-9]{32}', 0, ja3_md5)
    | where isnotempty(JA3Hash)
    | distinct JA3Hash;
DeviceNetworkEvents
| where isnotempty(parse_json(AdditionalFields).ja3)
| extend JA3 = tostring(parse_json(AdditionalFields).ja3)
| where JA3 in~ (ExtractedJA3Hashes)
| project-reorder Timestamp, DeviceName, RemoteIP, RemoteUrl, JA3
```

### Sentinel
```KQL
let JA3Feed = externaldata(ja3_md5:string) [@"https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv"] with (format="txt", ignoreFirstRecord=True);
// Extract JA3 Hashes From Feed
let ExtractedJA3Hashes = JA3Feed
    | extend JA3Hash = extract('[a-f0-9]{32}', 0, ja3_md5)
    | where isnotempty(JA3Hash)
    | distinct JA3Hash;
DeviceNetworkEvents
| where isnotempty(parse_json(AdditionalFields).ja3)
| extend JA3 = tostring(parse_json(AdditionalFields).ja3)
| where JA3 in~ (ExtractedJA3Hashes)
| project-reorder TimeGenerated, DeviceName, RemoteIP, RemoteUrl, JA3
```

