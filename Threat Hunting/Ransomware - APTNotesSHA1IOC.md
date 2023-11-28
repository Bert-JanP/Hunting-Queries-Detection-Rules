# Hunt for files that have been used by APTs since 2015

## Query Information

#### Description
This query uses a external csv that contains APT Ransomware note hashes. This list is used to search your environment for hash based matches on those ransomware notes.

#### Risk
An Threat Actor is deploying ransomware in your environment.

## Defender For Endpoint

```KQL
let APTInfo = externaldata(Filename: string, Title: string, Source: string, Link: string, SHA1: string, Date: datetime, Year: int)[@"https://raw.githubusercontent.com/aptnotes/data/master/APTnotes.csv"] 
with (format="csv", ignoreFirstRecord=True);
let SHA1IOC = APTInfo
     | where Year > 2015 //first IOC reported in 2008
     | distinct SHA1;
DeviceFileEvents
| where SHA1 has_any (SHA1IOC)
| project
     Timestamp,
     DeviceName,
     InitiatingProcessAccountName,
     InitiatingProcessAccountDomain,
     FileName,
     FolderPath,
     InitiatingProcessCommandLine,
     SHA1
```
## Sentinel
```KQL
let APTInfo = externaldata(Filename: string, Title: string, Source: string, Link: string, SHA1: string, Date: datetime, Year: int)[@"https://raw.githubusercontent.com/aptnotes/data/master/APTnotes.csv"] 
with (format="csv", ignoreFirstRecord=True);
let SHA1IOC = APTInfo
     | where Year > 2015 //first IOC reported in 2008
     | distinct SHA1;
DeviceFileEvents
| where SHA1 has_any (SHA1IOC)
| project
     TimeGenerated,
     DeviceName,
     InitiatingProcessAccountName,
     InitiatingProcessAccountDomain,
     FileName,
     FolderPath,
     InitiatingProcessCommandLine,
     SHA1

```