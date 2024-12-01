# Triggers when a know ransomware note is found

## Query Information

#### Description
This query triggers when a known ransomware note is found.

#### Risk
The file might indicate that files are encryped for ransomware.

#### References
- https://github.com/eshlomo1/Ransomware-NOTE

## Defender XDR
```KQL
let RansomwareNotes  = externaldata(RansomwareNote: string)[@"https://raw.githubusercontent.com/eshlomo1/Ransomware-NOTE/main/ransomware-notes.txt"] with (format="txt", ignoreFirstRecord=True);
let RansomwareNotesAddition = dynamic(['thisisanadditionalransomwarenote.txt']); // Add your missing / new extensions in this list.
let FalsePostiveWhitelist = dynamic(['whitelist.txt']); // Add the files that trigger a lot of false positives to this whitelist.
let RansomwareNoteRaw = RansomwareNotes
     | extend RansomwareNoteRaw = replace_string(RansomwareNote, "*", '')
     | distinct RansomwareNoteRaw;
DeviceFileEvents
| where (FileName has_any (RansomwareNoteRaw) or FileName has_any (RansomwareNotesAddition)) and not(FileName has_any (FalsePostiveWhitelist))
| project-reorder Timestamp, FileName, FolderPath, DeviceName, InitiatingProcessAccountName
```
## Sentinel
```KQL
let RansomwareNotes  = externaldata(RansomwareNote: string)[@"https://raw.githubusercontent.com/eshlomo1/Ransomware-NOTE/main/ransomware-notes.txt"] with (format="txt", ignoreFirstRecord=True);
let RansomwareNotesAddition = dynamic(['.thisisanadditionalransomwarenote']); // Add your missing / new extensions in this list.
let FalsePostiveWhitelist = dynamic(['.xxxxxxxxx']); // Add the files that trigger a lot of false positives to this whitelist.
let RansomwareNoteRaw = RansomwareNotes
     | extend RansomwareNoteRaw = replace_string(RansomwareNote, "*", '')
     | distinct RansomwareNoteRaw;
DeviceFileEvents
| where (FileName has_any (RansomwareNoteRaw) or FileName has_any (RansomwareNotesAddition)) and not(FileName has_any (FalsePostiveWhitelist))
| project-reorder TimeGenerated, FileName, FolderPath, DeviceName, InitiatingProcessAccountName
```

