# Triggers when a user performs a SmartScreen Override action
----
### Defender For Endpoint

```
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "SmartScreenUserOverride"
```
### Sentinel
```
DeviceEvents
| where TimeGenerated > ago(7d)
| where ActionType == "SmartScreenUserOverride"
```



