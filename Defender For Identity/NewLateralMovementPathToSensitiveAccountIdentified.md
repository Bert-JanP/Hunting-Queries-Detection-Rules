# Hunt for newly identified lateral movment paths to sensitive accounts
----
### Defender For Endpoint

```
IdentityDirectoryEvents
| where ActionType == "Potential lateral movement path identified"
| extend AdditionalInfo = parse_json(AdditionalFields)
| extend LateralMovementPathToSensitiveAccount = AdditionalFields.['ACTOR.ACCOUNT']
| extend FromAccount = AdditionalFields.['FROM.ACCOUNT']
| project
     Timestamp,
     LateralMovementPathToSensitiveAccount,
     FromAccount,
     DeviceName,
     AccountName,
     AccountDomain
```
### Sentinel
```
IdentityDirectoryEvents
| where ActionType == "Potential lateral movement path identified"
| extend AdditionalInfo = parse_json(AdditionalFields)
| extend LateralMovementPathToSensitiveAccount = AdditionalFields.['ACTOR.ACCOUNT']
| extend FromAccount = AdditionalFields.['FROM.ACCOUNT']
| project
     TimeGenerated,
     LateralMovementPathToSensitiveAccount,
     FromAccount,
     DeviceName,
     AccountName,
     AccountDomain
```



