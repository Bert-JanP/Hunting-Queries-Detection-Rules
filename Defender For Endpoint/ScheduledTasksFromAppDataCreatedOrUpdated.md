# Scheduled Tasks from AppData Created or Updated

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1053.005 | Scheduled Task/Job: Scheduled Task | https://attack.mitre.org/techniques/T1053/005/ |

#### Description
This query detects scheduled tasks that are created or updated with executables or scripts located in the `AppData` directory (including `%localappdata%` and `%appdata%`). This is a common technique used by malware and attackers to persist on a system without requiring administrative privileges. OneDrive-related tasks are excluded as a known false positive.

#### Risk
Scheduled tasks pointing to AppData directories are a strong indicator of persistence mechanisms used by malware. Since AppData is user-writable, attackers can plant payloads and schedule them for execution without needing elevated privileges.

#### References
- https://www.thedfirspot.com/post/evil-on-schedule-investigating-malicious-windows-tasks

## Defender XDR
```KQL
let Filters = dynamic(['AppData', '%localappdata%', '%appdata%']);
let Exclusions = dynamic([@'\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe', 'OneDriveLauncher.exe']);
DeviceEvents
| where ActionType in ('ScheduledTaskCreated', 'ScheduledTaskUpdated')
| where AdditionalFields has_any (Filters)
| extend ParsedAdditionalFields = parse_json(AdditionalFields)
| extend ScheduledTaskName = ParsedAdditionalFields.TaskName, Details = parse_json(ParsedAdditionalFields.TaskContent)
| where not(Details has_any (Exclusions))
| project-reorder Timestamp, DeviceName, ActionType, InitiatingProcessAccountUpn, ScheduledTaskName, Details
```

## Sentinel
```KQL
let Filters = dynamic(['AppData', '%localappdata%', '%appdata%']);
let Exclusions = dynamic([@'\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe', 'OneDriveLauncher.exe']);
DeviceEvents
| where ActionType in ('ScheduledTaskCreated', 'ScheduledTaskUpdated')
| where AdditionalFields has_any (Filters)
| extend ParsedAdditionalFields = parse_json(AdditionalFields)
| extend ScheduledTaskName = ParsedAdditionalFields.TaskName, Details = parse_json(ParsedAdditionalFields.TaskContent)
| where not(Details has_any (Exclusions))
| project-reorder TimeGenerated, DeviceName, ActionType, InitiatingProcessAccountUpn, ScheduledTaskName, Details
```