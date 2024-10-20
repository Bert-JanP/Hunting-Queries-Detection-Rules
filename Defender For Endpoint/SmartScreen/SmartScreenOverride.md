# Triggers when a user performs a SmartScreen Override action
----
### Defender XDR

```KQL
DeviceEvents
| where ingestion_time() > ago(7d)
| where ActionType == "SmartScreenUserOverride"
```
### Sentinel
```KQL
DeviceEvents
| where ingestion_time() > ago(7d)
| where ActionType == "SmartScreenUserOverride"
```



