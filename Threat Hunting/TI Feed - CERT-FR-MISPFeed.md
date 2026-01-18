# Hunt for malicious files that have been identified by CERT-FR

#### Source: CERT-FR
#### Feed link: https://misp.cert.ssi.gouv.fr/feed-misp/hashes.csv

## Defender XDR

```KQL
let CERTFRFeed = externaldata (SHA1: string, threatid :string) ["https://misp.cert.ssi.gouv.fr/feed-misp/hashes.csv"];
DeviceFileEvents
| join kind=inner CERTFRFeed on SHA1
// Additional information about the hash is available by using the ThreatInfoLink field.
| extend ThreatInfoLink = strcat("https://misp.cert.ssi.gouv.fr/feed-misp/", threatid, ".json")
| project-reorder Timestamp, SHA1, ThreatInfoLink, DeviceName
```

## Sentinel
```KQL
let CERTFRFeed = externaldata (SHA1: string, threatid :string) ["https://misp.cert.ssi.gouv.fr/feed-misp/hashes.csv"];
DeviceFileEvents
| join kind=inner CERTFRFeed on SHA1
// Additional information about the hash is available by using the ThreatInfoLink field.
| extend ThreatInfoLink = strcat("https://misp.cert.ssi.gouv.fr/feed-misp/", threatid, ".json")
| project-reorder TimeGenerated, SHA1, ThreatInfoLink, DeviceName
```



