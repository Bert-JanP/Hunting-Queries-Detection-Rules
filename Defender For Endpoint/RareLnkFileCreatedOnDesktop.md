# Rare .lnk File Created on Desktop

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1027.012 | Obfuscated Files or Information: LNK Icon Smuggling | https://attack.mitre.org/techniques/T1027/012/ |

#### Description
This query detects rare `.lnk` (shortcut) files created on the desktop of a device. Attackers often place malicious shortcut files on the desktop to trick users into executing malware, or to establish persistence. The query uses the `FileProfile` function to filter out commonly seen files and only surfaces shortcuts with a low global prevalence, making it suitable for hunting uncommon or suspicious shortcut drops.

#### Risk
A rare `.lnk` file placed on the desktop may indicate an attacker attempting to establish persistence, trick a user into executing malicious code, or maintain access to a compromised system via a malicious shortcut.

#### References
- https://blog.talosintelligence.com/gamaredon-campaign-distribute-remcos/

## Defender XDR
```KQL
let Threshold = 1000;
DeviceEvents
| where ActionType =~ 'ShellLinkCreateFileEvent'
| where FolderPath has 'Desktop'
| extend ShellLinkIconPath = parse_json(AdditionalFields).ShellLinkIconPath, ShellLinkWorkingDirectory = parse_json(AdditionalFields).ShellLinkWorkingDirectory
// Enrich data with FileProfile
| invoke FileProfile(InitiatingProcessSHA256, 10000)
| where GlobalPrevalence <= Threshold or isempty(GlobalPrevalence)
| project-reorder Timestamp, ActionType, FolderPath, ShellLinkIconPath, ShellLinkWorkingDirectory, InitiatingProcessAccountUpn
```

## Sentinel
```KQL
let Threshold = 1000;
DeviceEvents
| where ActionType =~ 'ShellLinkCreateFileEvent'
| where FolderPath has 'Desktop'
| extend ShellLinkIconPath = parse_json(AdditionalFields).ShellLinkIconPath, ShellLinkWorkingDirectory = parse_json(AdditionalFields).ShellLinkWorkingDirectory
// Enrich data with FileProfile
| invoke FileProfile(InitiatingProcessSHA256, 10000)
| where GlobalPrevalence <= Threshold or isempty(GlobalPrevalence)
| project-reorder TimeGenerated, ActionType, FolderPath, ShellLinkIconPath, ShellLinkWorkingDirectory, InitiatingProcessAccountUpn
```