# Cloud Persistence Activities by User At Risk

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1136.003 | Create Account: Cloud Account | https://attack.mitre.org/techniques/T1136/003/ |
|  T1078.004          | Valid Accounts: Cloud Accounts | https://attack.mitre.org/techniques/T1078/004/|

#### Description
This query detects Persistence events that have been performed by a user at risk, this is done based on the subset PersistenceEvents. You can add other items to the list if you feel the need to do so, because the list is currently limited. If you think additions are needed please raise a pull request. 

The persistence events are related to adding groups, devices, service principles and users to your tenant. An adversery can perform thos activities to ensure that he will keep access to the environment. He can add external users or add a new device, which can then be user to sign in from.

A false positive can be a administrator that triggered a risky event, after that he performed benign administrative task which would trigger this incident. 

#### Risk
A user at risk that also performs persistence events is more likely to be compromised. Investigate the useraccount in more detail and disable the user if malicious activity is confirmed. 

#### References
- https://learn.microsoft.com/en-us/azure/active-directory/identity-protection/howto-identity-protection-remediate-unblock
- https://learn.microsoft.com/en-us/azure/active-directory/authentication/tutorial-risk-based-sspr-mfa
- https://www.crowdstrike.com/blog/observations-from-the-stellarparticle-campaign/
- https://www.microsoft.com/en-us/security/blog/2021/10/25/nobelium-targeting-delegated-administrative-privileges-to-facilitate-broader-attacks/
- https://www.microsoft.com/en-us/security/blog/2022/03/22/dev-0537-criminal-actor-targeting-organizations-for-data-exfiltration-and-destruction/

## Sentinel
```
// Define PersistenceEvents, list can be appended with other events or your choosing
let PersistenceEvents = dynamic(["add member", "add device", "register device", "add service principal", "add user", "enable account", "add group", "Invite external user", "Add application", "add app"]);
let RiskyUsers = AADRiskyUsers
     | where TimeGenerated > ago(90d)
     // Only user active risky users. If you want to look for all users that have been risky, remove the line below.
     | where RiskState == 'atRisk'
     | distinct UserDisplayName;
AuditLogs
// Filter only on the RiskyUsers defined
| where Identity in~ (RiskyUsers)
// Filter on DiscoveryEvents
| where OperationName has_any (PersistenceEvents)
| project TimeGenerated, Identity, OperationName, Category, ResultDescription, Result
```
