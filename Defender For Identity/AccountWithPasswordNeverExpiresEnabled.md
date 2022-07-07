# Detect when an account has been changed in order for the password to never expire
----
### Defender For Endpoint

```
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
### Sentinel
```
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



