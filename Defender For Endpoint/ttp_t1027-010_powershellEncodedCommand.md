# TTP Detection Rule: PowerShell -encodedcommand switch

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1027.010 | Obfuscated Files or Information: Command Obfuscation | [Command Obfuscation](https://attack.mitre.org/techniques/T1027/010/)|

#### Description
Detection opportunity 4: PowerShell -encodedcommand switch

We also observed at least one of these adversaries abusing the shortened -encoded PowerShell command switch to encode PowerShell commands. This is another common bit of tradecraft. The following should help detect and hunt for the behaviour.

#### Risk
FIN7, ZLoader, and FakeBat have been observed performing this behaviour in recent intrusions. Adversaries may encode commands to evade defenses.

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
//this will be noisy and no good for a SIEM analytic
DeviceProcessEvents
| where FileName =~ "powershell.exe" and ProcessCommandLine has_any ("-e","-en","-enc","-enco","-encod","-encode","-encoded","-encodedc","-encodedco","-encodedcom","-encodedcomm","-encodedcomma","-encodedcomman","-encodedcommand")
```
## Sentinel
```KQL
//this will be noisy and no good for a SIEM analytic
DeviceProcessEvents
| where FileName =~ "powershell.exe" and ProcessCommandLine has_any ("-e","-en","-enc","-enco","-encod","-encode","-encoded","-encodedc","-encodedco","-encodedcom","-encodedcomm","-encodedcomma","-encodedcomman","-encodedcommand")
```
