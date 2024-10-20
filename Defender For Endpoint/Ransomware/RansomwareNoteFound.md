# Triggers when a know ransomware note is found
----
### Defender XDR

```
let RansomwareNotes  = externaldata(RansomwareNote: string)[@"https://raw.githubusercontent.com/eshlomo1/Ransomware-NOTE/main/ransomware-notes.txt"] with (format="txt", ignoreFirstRecord=True);
let RansomwareNotesAddition = dynamic(['thisisanadditionalransomwarenote.txt']); // Add your missing / new extensions in this list.
let FalsePostiveWhitelist = dynamic(['whitelist.txt']); // Add the files that trigger a lot of false positives to this whitelist.
let RansomwareNoteRaw = materialize (
     RansomwareNotes
     | extend RansomwareNoteRaw = replace_string(RansomwareNote, "*", '')
     | distinct RansomwareNoteRaw
     );
DeviceFileEvents
| where (FileName has_any (RansomwareNoteRaw) or FileName has_any (RansomwareNotesAddition)) and not(FileName has_any (FalsePostiveWhitelist))
| project-reorder Timestamp, FileName, FolderPath, DeviceName, InitiatingProcessAccountName

```
### Sentinel
```
let RansomwareNotes  = externaldata(RansomwareNote: string)[@"https://raw.githubusercontent.com/eshlomo1/Ransomware-NOTE/main/ransomware-notes.txt"] with (format="txt", ignoreFirstRecord=True);
let RansomwareNotesAddition = dynamic(['.thisisanadditionalransomwarenote']); // Add your missing / new extensions in this list.
let FalsePostiveWhitelist = dynamic(['.xxxxxxxxx']); // Add the files that trigger a lot of false positives to this whitelist.
let RansomwareNoteRaw = materialize (
     RansomwareNotes
     | extend RansomwareNoteRaw = replace_string(RansomwareNote, "*", '')
     | distinct RansomwareNoteRaw
     );
DeviceFileEvents
| where (FileName has_any (RansomwareNoteRaw) or FileName has_any (RansomwareNotesAddition)) and not(FileName has_any (FalsePostiveWhitelist))
| project-reorder TimeGenerated, FileName, FolderPath, DeviceName, InitiatingProcessAccountName
```



