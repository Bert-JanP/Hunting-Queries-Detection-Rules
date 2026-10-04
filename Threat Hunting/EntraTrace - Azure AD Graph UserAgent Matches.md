# EntraTrace - Azure AD Graph UserAgent Matches

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title | Link |
| --- | --- | --- |
| T1087.004 | Account Discovery: Cloud Account | https://attack.mitre.org/techniques/T1087/004/ |
| T1069.003 | Permission Groups Discovery: Cloud Groups | https://attack.mitre.org/techniques/T1069/003/ |

#### Description

Hunts for legacy Azure AD Graph API requests whose `UserAgent` matches an entry extracted from offensive tool profiles in [EntraTrace](https://github.com/Bert-JanP/EntraTrace). The query dynamically retrieves the [UserAgents.csv indicator list](https://github.com/Bert-JanP/EntraTrace/blob/main/Indicator%20Lists/UserAgents.csv) at execution time, so coverage changes as the project updates its profiles.

#### Risk
Offensive tooling can use legacy Azure AD Graph to enumerate users, groups, devices, applications, and directory permissions, supporting discovery of privileged identities and attack paths. Hunting only modern Microsoft Graph logs can miss activity recorded in this separate source. A match is an investigation lead, not proof of compromise. Pivot to the underlying requests to examine identities, applications, `CallerIpAddress`, request URIs, response status codes, and related sign-ins. Validate whether the activity is expected or part of an authorized assessment before escalation.

#### References

- https://github.com/Bert-JanP/EntraTrace
- https://www.invictus-ir.com/news/the-missing-link-aadgraphactivitylogs-finally-arrives
- https://cloudbrothers.info/en/detect-threats-microsoft-graph-logs-part-1/


## Sentinel

```KQL
let EntraTraceUserAgents = externaldata(Toolname:string,UserAgent:string)["https://raw.githubusercontent.com/Bert-JanP/EntraTrace/refs/heads/main/Indicator%20Lists/UserAgents.csv"] with (format="csv",ignoreFirstRecord=true);
let UniqueUserAgents = EntraTraceUserAgents
| distinct UserAgent;
AADGraphActivityLogs
| where UserAgent in~ (UniqueUserAgents)
| extend ObjectId = coalesce(ServicePrincipalId, UserId)
| summarize TotalEvents = count(), UniqueObject = dcount(ObjectId), UniqueUsers = dcount(UserId), UniqueServicePrincipals = dcount(ServicePrincipalId) by UserAgent
| join kind=leftouter EntraTraceUserAgents on UserAgent
| project-away *1
```