## Detects KillNets Ransomware note and the file extension that has been used to encrypt files

Source: https://www.virustotal.com/gui/file/db1c8ddcdfea93031a565001366ffa9fdb41a689bddab46aec7611a46bb4dc50/detection

### Defender For Endpoint

```
let killnetRansomNote = "ru.txt";
let killnetRansomExtension = ".killnet";
DeviceFileEvents
| where FileName =~ killnetRansomNote or FileName endswith killnetRansomExtension
| project-reorder Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine
```
### Sentinel
```
let killnetRansomNote = "ru.txt";
let killnetRansomExtension = ".killnet";
DeviceFileEvents
| where FileName =~ killnetRansomNote or FileName endswith killnetRansomExtension
| project-reorder TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine
```



