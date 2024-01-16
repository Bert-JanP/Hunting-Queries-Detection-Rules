# TTP Detection Rule: Abusing PowerShell to disable Defender components

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1562.001 | Impair Defenses: Disable or Modify Tools | [Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)|

#### Description
Detection opportunity: Abusing PowerShell to disable Defender components

We also observed at least one of these adversaries abusing PowerShell to exclude certain files or processes from Windows Defender scanning. Luckily, this is common tradecraft for which we’ve shared similar detection ideas on multiple occasions. The following may unearth this and other threats:

#### Risk
FIN7, ZLoader, and FakeBat have been observed performing this behaviour in recent intrusions. Adversaries may modify and/or disable security tools to avoid possible detection of their malware/tools and activities. 

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- [https://kqlquery.com/](https://redcanary.com/blog/msix-installers/)

## Defender For Endpoint
```KQL
//Detection opportunity 3: Abusing PowerShell to disable Defender components
DeviceProcessEvents
| where FileName =~ "powershell.exe" and ProcessCommandLine has_any ("Add-MpPreference","Set-MpPreference") and ProcessCommandLine has_any ("ExclusionProcess","ExclusionPath")
```
## Sentinel
```KQL
//Detection opportunity 3: Abusing PowerShell to disable Defender components
DeviceProcessEvents
| where FileName =~ "powershell.exe" and ProcessCommandLine has_any ("Add-MpPreference","Set-MpPreference") and ProcessCommandLine has_any ("ExclusionProcess","ExclusionPath")
```
