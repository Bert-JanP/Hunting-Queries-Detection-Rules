# Detect when an account has been changed in order for the password to never expire

## Query Information

#### Description
In Windows a password can be set so that it will never expire. This is normaly not desirable, because a password must be changed every x period. This query detects when a useraccount is set to Account Password Never Expires.

#### Risk
A account that has as password that never exprided on and it has a weak password. That makes it vulnerable for Brute Force attacks. 

## Defender XDR
```KQL
IdentityDirectoryEvents
| where ActionType == "Account Password Never Expires changed"
| extend AdditionalInfo = parse_json(AdditionalFields)
| extend OriginalValue = AdditionalInfo.['FROM Account Password Never Expires']
| extend NewValue = AdditionalInfo.['TO Account Password Never Expires']
| where NewValue == true
| project
     Timestamp,
     AccountName,
     AccountDomain,
     OriginalValue,
     NewValue,
     ReportId,
     DeviceName
```

## Sentinel
```KQL
IdentityDirectoryEvents
| where ActionType == "Account Password Never Expires changed"
| extend AdditionalInfo = parse_json(AdditionalFields)
| extend OriginalValue = AdditionalInfo.['FROM Account Password Never Expires']
| extend NewValue = AdditionalInfo.['TO Account Password Never Expires']
| where NewValue == true
| project
     TimeGenerated,
     AccountName,
     AccountDomain,
     OriginalValue,
     NewValue,
     ReportId,
     DeviceName
```



