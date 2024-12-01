# Triggers when a user performs a SmartScreen Override action

## Query Information

#### Description
This query lists all SmartScreen override related events.

#### References
- https://learn.microsoft.com/en-us/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen/

## Defender XDR
```KQL
DeviceEvents
| where ingestion_time() > ago(7d)
| where ActionType == "SmartScreenUserOverride"
```
## Sentinel
```KQL
DeviceEvents
| where ingestion_time() > ago(7d)
| where ActionType == "SmartScreenUserOverride"
```

