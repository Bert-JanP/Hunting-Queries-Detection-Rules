# WMIC Antivirus Discovery

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1518.001 | Software Discovery: Security Software Discovery| https://attack.mitre.org/techniques/T1518/001/ |
| T1047 | Windows Management Instrumentation | https://attack.mitre.org/techniques/T1047/ |

#### Description
Adversaries can use WMIC to run queries to detect which antivirus solution has been installed on the device. This is usefull for an adversary, because they know what the maturity of the solution is. More advanced groups might even test there malware samples in a contained environment, before running it on the infrected system. There are some common tools that also use WMIC to list the antivirus solutions, in this query they have been filtered. More applications can be added to the list, it is reccommended to use hashes instead of filenames. Because of the various verions of the tools, it is in this case choosen to only list filenames. The common command the is used for this is:

```
cmd.exe WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
```

#### Risk
An actor uses WMIC to list the installed antivirus solutions

#### References
- https://www.malwarebytes.com/blog/threat-intelligence/2021/12/sidecopy-apt-connecting-lures-to-victims-payloads-to-infrastructure
- https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/jrat-new-anti-parsing-techniques
- https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/07195002/KL_AdwindPublicReport_2016.pdf

## Defender XDR
```
DeviceProcessEvents
// Filter only on WMIC executions
| where FileName =~ "WMIC.exe"
// Only serach for AntiVirusProduct lists in the commandline, actual malicious activity could look like cmd.exe WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
| where ProcessCommandLine contains "AntiVirusProduct"
| project Timestamp, DeviceName, ActionType, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine, AccountUpn, InitiatingProcessFileName
// Known Applications to trigger antiviruscheck, would be better to filter on hash but that needs to be done for your environment.
| where not(InitiatingProcessFileName in~('pycharm64.exe', 'pycharm.exe', 'idea64.exe', 'rider64.exe'))
```
## Sentinel
```
DeviceProcessEvents
// Filter only on WMIC executions
| where FileName =~ "WMIC.exe"
// Only serach for AntiVirusProduct lists in the commandline, actual malicious activity could look like cmd.exe WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
| where ProcessCommandLine contains "AntiVirusProduct"
| project TimeGenerated, DeviceName, ActionType, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine, AccountUpn, InitiatingProcessFileName
// Known Applications to trigger antiviruscheck, would be better to filter on hash but that needs to be done for your environment.
| where not(InitiatingProcessFileName in~('pycharm64.exe', 'pycharm.exe', 'idea64.exe', 'rider64.exe'))
```

