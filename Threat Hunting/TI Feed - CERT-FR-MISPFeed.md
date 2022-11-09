# Hunt for malicious files that have been identified by CERT-FR
----
### Defender For Endpoint

```
let CERTFRFeed = externaldata (SHA1: string, threatid :string) ["https://misp.cert.ssi.gouv.fr/feed-misp/hashes.csv"];
DeviceFileEvents
| join CERTFRFeed on SHA1
// Additional information about the hash is available by using the ThreatInfoLink field.
| extend ThreatInfoLink = strcat("https://misp.cert.ssi.gouv.fr/feed-misp/", threatid, ".json")
| project-reorder Timestamp, SHA1, ThreatInfoLink, DeviceName
```
### Sentinel
```
let CERTFRFeed = externaldata (SHA1: string, threatid :string) ["https://misp.cert.ssi.gouv.fr/feed-misp/hashes.csv"];
DeviceFileEvents
| join CERTFRFeed on SHA1
// Additional information about the hash is available by using the ThreatInfoLink field.
| extend ThreatInfoLink = strcat("https://misp.cert.ssi.gouv.fr/feed-misp/", threatid, ".json")
| project-reorder TimeGenerated, SHA1, ThreatInfoLink, DeviceName
```



