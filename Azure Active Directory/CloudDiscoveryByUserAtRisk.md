# Cloud Discovery Performed by User At Risk

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1069.003 | Permission Groups Discovery: Cloud Groups | https://attack.mitre.org/techniques/T1069/003/ |

#### Description
This query detects discovery events that have been performed by a user at risk, this is done based on the subset DiscoveryEvents. You can add other items to the list if you feel the need to do so, because the list is currently limited. If you think additions are needed please raise a pull request. 

The discovery events are related to downloading group members and getting tenant information, which would be a logical step for an attacker if he gained access to your Azure tenant. 

#### Risk
A user at risk that also performs discovery events is more likely to be compromised. Investigate the useraccount in more detail and disable the user if malicious activity is confirmed. 

#### References
- https://learn.microsoft.com/en-us/azure/active-directory/identity-protection/howto-identity-protection-remediate-unblock
- https://learn.microsoft.com/en-us/azure/active-directory/authentication/tutorial-risk-based-sspr-mfa

## Sentinel
```KQL
// Define DiscoveryEvents, list can be appended with other events or your choosing
let DiscoveryEvents = dynamic(["Export", "Download group members", "Get tenant details", "Download Users", "Download Devices"]);
let RiskyUsers = AADRiskyUsers
     | where TimeGenerated > ago(90d)
     | summarize arg_max(TimeGenerated, *) by Id
     // Only user active risky users. If you want to look for all users that have been risky, remove the line below.
     | where RiskState in~ ('atRisk', 'confirmedCompromised')
     | distinct UserDisplayName;
AuditLogs
// Filter only on the RiskyUsers defined
| where Identity in~ (RiskyUsers)
// Filter on DiscoveryEvents
| where OperationName has_any (DiscoveryEvents)
| project TimeGenerated, Identity, OperationName, Category, 
ResultDescription, Result
```
#### Versions
| Version | Comment |
| ---  | --- |
| 1.0 | Initial commit |
| 1.1 | addition confirmedCompromised to risk state & collect last event from risky user |
