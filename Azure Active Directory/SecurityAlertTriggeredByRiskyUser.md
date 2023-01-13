# Security Alerts triggered by users at risk

## Query Information

#### Description
This query identifies the users that are currently at risk. Based on that it performs a lookup on the security alerts that have been triggered with that user as entity. This can indicate that a useraccount has been compromised, because it has peformed risky sign in activities as well as malicious activities defined by security products or custom detection rules. 

#### Risk
Alerts on a user at risk may indicate that the useraccount has been compromised. Investigate the useraccount in more detail and disable the user if malicious activity is confirmed. 

#### References
- https://learn.microsoft.com/en-us/azure/active-directory/identity-protection/howto-identity-protection-remediate-unblock
- https://learn.microsoft.com/en-us/azure/active-directory/authentication/tutorial-risk-based-sspr-mfa

## Sentinel
```
let RiskyUsers = AADRiskyUsers
     | where TimeGenerated > ago(90d)
     // Only user active risky users. If you want to look for all users that have been risky, remove the line below.
     | where RiskState == 'atRisk'
     | distinct UserPrincipalName;
SecurityAlert
// Only get the latest status of each alert
| summarize arg_max(TimeGenerated, *) by SystemAlertId
// Filter only on RiskyUsers
| where Entities has_any (RiskyUsers)
// Collect the user from the entities
| extend
     DisplayName = extract(@',"DisplayName":"(.*?)"', 1, Entities),
     Upn = extract(@'"Upn":"(.*?)"', 1, Entities),
     UserPrincipalName = extract(@'"UserPrincipalName":"(.*?)"', 1, Entities)
// Combine the entity fields into one field
| extend User = iff(isnotempty(DisplayName), DisplayName, iff(isnotempty(Upn), Upn, iff(isnotempty(UserPrincipalName), UserPrincipalName, 'See Entities')))
| project AlertName, AlertSeverity, User, Entities
```