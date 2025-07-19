# Advanced Feature Disabled

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1562.001 | Impair Defenses: Disable or Modify Tool | https://attack.mitre.org/techniques/T1562/001/ |

### Description
Defender For Endpoint Advanced Features are very powerful, some examples are:
- Enable/Disable EDR in block mode
- Enable/Disable Live Response
- Enable/Disable Live Response unsigned script execution
- Enable/Disable Tamper protection

The query below returns results if an Advanced Feature has been disabled in your tenant, disabling an advanced feature can increase your attack surface significantly.

### References
- https://learn.microsoft.com/en-us/defender-endpoint/advanced-features
- https://kqlquery.com/posts/audit-defender-xdr/

## Defender XDR
```KQL
CloudAppEvents
| where ActionType == "SetAdvancedFeatures"
| extend WorkLoad = tostring(parse_json(RawEventData).Workload),
    SettingsNewValue = tobool(parse_json(RawEventData).SettingsNewValue),
    SettingName = tostring(parse_json(RawEventData).SettingName),
    UserId = tostring(parse_json(RawEventData).UserId)
| where SettingsNewValue == 0
| project-reorder Timestamp, WorkLoad, SettingName, SettingsNewValue, UserId
```
## Sentinel
```KQL
CloudAppEvents
| where ActionType == "SetAdvancedFeatures"
| extend WorkLoad = tostring(parse_json(RawEventData).Workload),
    SettingsNewValue = tobool(parse_json(RawEventData).SettingsNewValue),
    SettingName = tostring(parse_json(RawEventData).SettingName),
    UserId = tostring(parse_json(RawEventData).UserId)
| where SettingsNewValue == 0
| project-reorder Timestamp, WorkLoad, SettingName, SettingsNewValue, UserId
```
