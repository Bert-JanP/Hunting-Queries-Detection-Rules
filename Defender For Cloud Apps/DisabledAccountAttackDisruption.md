# Disabled Account Attack Disruption

## Query Information

#### Description
Attack disruption disabled a cloud/hybrid account due to suspicious activities. The query lists the accounts that have been disabled by MDI.

#### Risk
The account has been disabled due to suspicious activities. 

#### References
- https://learn.microsoft.com/en-us/defender-cloud-apps/protect-azure
- https://learn.microsoft.com/en-us/defender-xdr/automatic-attack-disruption

## Defender XDR
```KQL
CloudAppEvents
| where ActionType == "Disable account."
// Disabled by Microsoft Defender for Identity
| where AccountId == "60ca1954-583c-4d1f-86de-39d835f3e452"
| extend DisabledAccount = tostring(RawEventData.ObjectId)
| project Timestamp, ActionType, DisabledAccount
```

## Sentinel
```KQL
CloudAppEvents
| where ActionType == "Disable account."
// Disabled by Microsoft Defender for Identity
| where AccountId == "60ca1954-583c-4d1f-86de-39d835f3e452"
| extend DisabledAccount = tostring(RawEventData.ObjectId)
| project TimeGenerated, ActionType, DisabledAccount
```
