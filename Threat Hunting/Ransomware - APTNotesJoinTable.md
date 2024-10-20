# APTNotes table that can be used to join with other data connectors
----
### Defender XDR

```
let APTInfo = externaldata(Filename: string, Title: string, Source: 
string, Link: string, SHA1: string, Date: datetime, Year: int)
[@"https://raw.githubusercontent.com/aptnotes/data/master/APTnotes.csv"] 
with (format="csv", ignoreFirstRecord=True);
APTInfo
| where Year > 2015
```
### Sentinel
```
let APTInfo = externaldata(Filename: string, Title: string, Source: 
string, Link: string, SHA1: string, Date: datetime, Year: int)
[@"https://raw.githubusercontent.com/aptnotes/data/master/APTnotes.csv"] 
with (format="csv", ignoreFirstRecord=True);
APTInfo
| where Year > 2015

```
