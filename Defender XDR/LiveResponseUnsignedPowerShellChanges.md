# List Live Response Unsigned Script Setting Changes

## Query Information

### Description
This query lists all changes to the Live Response Unsigned Script settings in the Advanced Features in Defender For Endpoint. You want to monitor this because allowing the use of unsigned scripts may increase your exposure to threats.

### References
- https://kqlquery.com/posts/leveraging-live-response/
- https://learn.microsoft.com/en-us/defender-endpoint/live-response
- https://kqlquery.com/posts/audit-defender-xdr/


## Defender XDR
```
CloudAppEvents
| where ActionType == "SetAdvancedFeatures"
| extend SettingName = tostring(parse_json(RawEventData).SettingName), SettingsNewValue = tostring(parse_json(RawEventData).SettingsNewValue)
| where SettingName == "Live Response unsigned script execution"
| project-reorder Timestamp, AccountId, ActionType, SettingName, SettingsNewValue
```
## Sentinel
```
CloudAppEvents
| where ActionType == "SetAdvancedFeatures"
| extend SettingName = tostring(parse_json(RawEventData).SettingName), SettingsNewValue = tostring(parse_json(RawEventData).SettingsNewValue)
| where SettingName == "Live Response unsigned script execution"
| project-reorder TimeGenerated, AccountId, ActionType, SettingName, SettingsNewValue
```
