# Hunt for newly identified lateral movement paths to sensitive accounts

## Query Information

#### Description
Defender For Identity identifies lateral movement paths to all sensitive accounts (if possible). This is similar to a Bloodhound output. A newly identified path can mean that a sensitive account can be taken over if the path is followed. 

#### References
- https://learn.microsoft.com/en-us/defender-for-identity/understand-lateral-movement-paths

## Defender For Endpoint

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
## Sentinel
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



