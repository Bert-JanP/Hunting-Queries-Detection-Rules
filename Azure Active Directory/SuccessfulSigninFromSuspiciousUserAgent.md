# Successful sign-in from suspicious user agent

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title | Link |
| --- | --- | --- |
| T1078 | Valid Accounts | https://attack.mitre.org/techniques/T1078/ |

#### Description
This detection identifies successful Azure AD/Entra ID sign-ins for a specific UPN where the user agent string matches a list of suspicious or tool-based user agents (such as `python-requests`, `Go-http-client`, or `azurehound`). It filters for successful sign-ins (`ErrorCode == 0`) by the target account and highlights sign-ins performed via known credential validation tools or phishinkits.

#### Risk
Attackers commonly use scripts, automation frameworks, and offensive tools to perform reconnaissance and abuse compromised accounts. These tools often expose themselves via distinctive user agent strings. Successful sign-ins with these user agents can indicate scripted account abuse, abuse of OAuth tokens, or automated reconnaissance against Azure AD and related services.

#### References
- https://bloodhound.readthedocs.io/

## Defender XDR
```KQL
let SuspiciousUserAgents = externaldata(http_user_agent:string,metadata_description:string,metadata_tool:string,metadata_category:string,metadata_link:string,metadata_priority:string,metadata_fp_risk:string,metadata_severity:string,metadata_usage:string,metadata_flow_from_external:string,metadata_flow_from_internal:string,metadata_flow_to_internal:string,metadata_flow_to_external:string,metadata_for_successful_external_login_events:string,metadata_comment:string)["https://raw.githubusercontent.com/mthcht/awesome-lists/refs/heads/main/Lists/suspicious_http_user_agents_list.csv"] with (format="csv", ignoreFirstRecord=true);
let UserAgentsOfInterest = SuspiciousUserAgents
| where metadata_category in~ ("Credential Access",
    "Phishing",
    "phishing",
    "Reconnaissance",
    "Exploit",
    "Exploitation",
    "Exploitation tool",
    "Defense Evasion",
    "POST Exploitation",
    "Bots & Vulnerability Scanner",
    "uncommun user agent")
| extend StandardizedUserAgent = replace_string(http_user_agent, "*", "")
| distinct StandardizedUserAgent;
EntraIdSignInEvents
| where ErrorCode == 0
| where UserAgent has_any (UserAgentsOfInterest)
| project-reorder Timestamp, AccountUpn, LogonType, UserAgent, ErrorCode, SessionId
```

## Sentinel
```KQL
let SuspiciousUserAgents = externaldata(http_user_agent:string,metadata_description:string,metadata_tool:string,metadata_category:string,metadata_link:string,metadata_priority:string,metadata_fp_risk:string,metadata_severity:string,metadata_usage:string,metadata_flow_from_external:string,metadata_flow_from_internal:string,metadata_flow_to_internal:string,metadata_flow_to_external:string,metadata_for_successful_external_login_events:string,metadata_comment:string)["https://raw.githubusercontent.com/mthcht/awesome-lists/refs/heads/main/Lists/suspicious_http_user_agents_list.csv"] with (format="csv", ignoreFirstRecord=true);
let UserAgentsOfInterest = SuspiciousUserAgents
| where metadata_category in~ ("Credential Access",
    "Phishing",
    "phishing",
    "Reconnaissance",
    "Exploit",
    "Exploitation",
    "Exploitation tool",
    "Defense Evasion",
    "POST Exploitation",
    "Bots & Vulnerability Scanner",
    "uncommun user agent")
| extend StandardizedUserAgent = replace_string(http_user_agent, "*", "")
| distinct StandardizedUserAgent;
SigninLogs
| where ResultType == 0
| where UserAgent has_any (UserAgentsOfInterest)
| project-reorder TimeGenerated, UserPrincipalName, UserAgent, ResultType, ResultDescription, SessionId
```