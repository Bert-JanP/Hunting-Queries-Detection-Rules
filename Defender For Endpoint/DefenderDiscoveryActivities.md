# List Defender Discovery Activities

## List Defender Discovery Activities

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1518.001 | Software Discovery: Security Software Discovery| https://attack.mitre.org/techniques/T1518/001/ |

#### Description
This query lists the execution of Get-MpPreference, this function lists the preferences for the Windows Defender scans and updates, including the configured exclusions. Adversaries may use the information from Security Software Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions. Adversaries can abuse exclusions to execute malicious code. 

False positives can be related to admins that configure/list certain settings.

#### Risk
Adversaries can use Get-MpPreference to list exclusions, those exclusions can be abused to execute malicious content.

#### References
- https://learn.microsoft.com/en-us/powershell/module/defender/get-mppreference?view=windowsserver2022-ps
- https://cloudbrothers.info/en/create-persistent-defender-av-exclusions-circumvent-defender-endpoint-detection/

## Defender XDR
```KQL
let ProcessBased = DeviceProcessEvents
| where ProcessCommandLine has "Get-MpPreference"
| extend Table = "DeviceProcessEvents"
| project-reorder Table, Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName;
let EventBased = DeviceEvents
| extend Command = parse_json(AdditionalFields).Command
| where  Command == "Get-MpPreference"
| extend ScriptLocation = extract(@"literalPath '(.*?)'", 0, InitiatingProcessCommandLine)
| extend Table = "DeviceEvents"
| project-reorder Table, Timestamp, DeviceName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, ScriptLocation;
union ProcessBased, EventBased
```
## Sentinel
```KQL
let ProcessBased = DeviceProcessEvents
| where ProcessCommandLine has "Get-MpPreference"
| extend Table = "DeviceProcessEvents"
| project-reorder Table, Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName;
let EventBased = DeviceEvents
| extend Command = parse_json(AdditionalFields).Command
| where  Command == "Get-MpPreference"
| extend ScriptLocation = extract(@"literalPath '(.*?)'", 0, InitiatingProcessCommandLine)
| extend Table = "DeviceEvents"
| project-reorder Table, TimeGenerated, DeviceName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, ScriptLocation;
union ProcessBased, EventBased
```
