# CA User SignIn Failures

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1078.004 | Valid Accounts: Cloud Accounts | https://attack.mitre.org/techniques/T1078/004/|

#### Description
This KQL query lists all users that trigger failed signin requests due to conditional access failures. This can indicate that a certain policy is not well configured and need to be changed in order for accounts to be able to access the application. On the other hand it can also be that the failed signins are valid credentials that adversaries have obtained and they are used to try and gain acces to certain applications in your environment. The CA policy will only block if the previous authentication requirements have already been met (e.g. username + password (+mfa)). It can be beneficial to understand why certain users trigger a large amount of CA policies, either their credentials are leaked/stolen or they do not follow the right procedures to access the cloud environment.

#### Risk
Adversaries have access to cloud credentials and are stopped due to CA policies.

#### References
- https://learn.microsoft.com/en-us/azure/active-directory/architecture/security-operations-consumer-accounts
- https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/


## Sentinel
```KQL
SigninLogs
| where ResultType != 0
| where ResultDescription has "Conditional Access"
| summarize Total = count(), ResultTypes = make_set(ResultType), ResultDescriptions = make_set(ResultDescription) by UserPrincipalName
| sort by Total
```