# TTP Detection Rule: Suspicious network connection from MSBuild

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
|  T1127.001 | Trusted Developer Utilities Proxy Execution: MSBuild | [MSBuild](https://attack.mitre.org/techniques/T1562/001/)|

#### Description
Detection opportunity: MSBuild without commands

In some detections, we observed the Microsoft Build Engine (msbuild.exe) making outbound network connections to IPs associated with the ArechClient2 remote access tool. In general, it is suspicious for msbuild.exe to execute without a corresponding command line, which is precisely what we observed here. Simply looking for execution of msbuild.exe without a corresponding command line and examining surrounding activity for suspicious network connections and child processes could help detect this threat.

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
// Detection opportunity 5: MSBuild without commands
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "msbuild.exe" and (isempty(InitiatingProcessCommandLine) or InitiatingProcessCommandLine =~ "msbuild.exe")
```
## Sentinel
```KQL
// Detection opportunity 5: MSBuild without commands
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "msbuild.exe" and (isempty(InitiatingProcessCommandLine) or InitiatingProcessCommandLine =~ "msbuild.exe")
```
