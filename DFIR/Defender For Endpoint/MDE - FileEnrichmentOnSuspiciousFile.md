# File Enrichment on Suspicious File
----
## Defender XDR

```
let SuspiciousDownloadName = 'GoogleUpdateSetup.exe';
DeviceFileEvents
| where FileName == SuspiciousDownloadName
| summarize
     arg_max(Timestamp, *),
     DeviceList = make_set(DeviceName),
     FileLocations = make_set(FolderPath)
     by SHA1
// Add file details, for more details see: https://docs.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-fileprofile-function?view=o365-worldwide
| invoke FileProfile(SHA1, 1000)
| project-reorder
     Timestamp,
     SHA1,
     // GlobalPrevalence = Number of instances of the entity observed by Microsoft globally. The more instances, the more likely it is benign.
     GlobalPrevalence,
     GlobalFirstSeen,
     Signer,
     ThreatName,
     DeviceList,
     FileLocations
```

This query is not available in Sentinel, since FileProfile() is not supported. 
