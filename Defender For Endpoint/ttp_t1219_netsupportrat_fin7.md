# TTP Detection Rule: NetSupport running from unexpected directory (FIN7)

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1219 | Remote Access Software | [Remote Access Software](https://attack.mitre.org/techniques/T1219/)|

#### Description
Detection opportunity: NetSupport running from unexpected directory

In the instances where the adversary delivered NetSupport Manager RAT as a follow-on payload, our existing detection coverage for malicious NetSupport installation served us well. Under normal circumstances, you should expect NetSupport Manager to run from the program files directory. If you find NetSupport Manager—often identifiable as client32.exe—running outside the program files directory, particularly from the programdata directory, then it’s worth investigating.

#### Risk
FIN7 have been observed performing this behaviour in recent intrusions. FIN7 activity has frequently preceded ransomware deployment. We’ve detected activity within this cluster attempting to install malicious instances of NetSupport Manager RAT. In the detections we’ve observed within this cluster, the adversary leverages the MSIX-PackageSupportFramework tool to create their malicious MSIX files. When the victim opens the MSIX, the StartingScriptWrapper.ps1 component of the MSIX package support framework launches an embedded PowerShell script from the windowsapps directory.

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
// Detection opportunity 2: NetSupport running from unexpected directory
DeviceProcessEvents
| where ( ProcessVersionInfoCompanyName contains "netsupport" or ProcessVersionInfoProductName contains "netsupport" ProcessVersionInfoCompanyName contains "Crosstec" or ProcessVersionInfoProductName contains "Crosstec") and not ( FolderPath has_any ("Program Files (x86)\\","Program Files\\"))
```
## Sentinel
```KQL
// Detection opportunity 2: NetSupport running from unexpected directory
DeviceProcessEvents
| where ( ProcessVersionInfoCompanyName contains "netsupport" or ProcessVersionInfoProductName contains "netsupport" ProcessVersionInfoCompanyName contains "Crosstec" or ProcessVersionInfoProductName contains "Crosstec") and not ( FolderPath has_any ("Program Files (x86)\\","Program Files\\"))
```
