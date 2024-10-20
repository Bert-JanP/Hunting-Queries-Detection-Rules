# Hunt for rare ISO files on devices

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1553.005 | Subvert Trust Controls: Mark-of-the-Web Bypass | https://attack.mitre.org/techniques/T1553/005/ |

#### Description
Adversaries may use ISO files to obfuscate their malicious intentions and gain initail access. Those files may be send via mail. A common Actor that sends ISO attachments is Lokibot. To reduce the attack surface consider disabling auto mounting of disk images. This hunting query lets you search for rare ISO files in your organisation. The threshold for the query is that the ISO file has a global prevalence of less then 100, this can be adjusted to your needs. This query does not look for mounted ISO files, it only searches for ISO files on disk. 

A false positive would be a benign file that has a low global prevalance, for example some Linux distros. This can be validated via the hash if the file is indeed benign.

Note that this query can only be executed on Defender For Endpoint, since the function FileProfile() is not supported in Sentinel.

#### Risk
A actor can use a malicious mounted ISO to gain initial access.

#### References
- https://redcanary.com/blog/iso-files/
- https://www.bleepingcomputer.com/news/security/uptick-seen-in-iso-email-attachments-delivering-malware/
- https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/automount
- https://www.cisa.gov/uscert/ncas/alerts/aa20-266a

## Defender XDR
```
let Threshold = 100;
DeviceFileEvents
// Extract the FileExtentsion from the filename
| extend FileExtension = tostring(extract(@'.*\.(.*)', 1, FileName))
// Filter only on ISO files
| where FileExtension =~ 'iso'
// Do not filter on File Rename activities, since this does not change 
the hash of the file.
| where ActionType != 'FileRenamed'
| where isnotempty(SHA1)
// Enrich file information
| invoke FileProfile("SHA1", 10000)
// Depending on your hunting activities you can alter the threshold for 
applications that are less rare.
| where GlobalPrevalence <= Threshold
| project
     DeviceName,
     ActionType,
     GlobalPrevalence,
     GlobalFirstSeen,
     FolderPath,
     SHA1,
     FileOriginUrl
| sort by GlobalPrevalence, SHA1
```
