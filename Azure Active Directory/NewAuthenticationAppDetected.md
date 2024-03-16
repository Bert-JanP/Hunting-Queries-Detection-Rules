# New Authentication App Detected

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1078.004 | Valid Accounts: Cloud Accounts | https://attack.mitre.org/techniques/T1078/004 |

#### Description
Detect a new app that is used to send authentication request to your tenant. The authentication requests do not have to be successful. The app can eighter be an internal app, then the AppID is filled, if that is not the case then it is an external app. A false positive is a new app that is used within your organization. 

#### Risk
A malicious actor installs a malicious app in your environment. This app can then be used for malicious purposes, depending on the privileges that the app has. Such as AD Recon, collecting tokens or internal spear phishing.

#### References
- https://learn.microsoft.com/en-us/azure/active-directory/develop/reference-aadsts-error-codes
- https://www.varonis.com/blog/using-malicious-azure-apps-to-infiltrate-a-microsoft-365-tenant
- https://learn.microsoft.com/en-us/security/compass/incident-response-playbook-compromised-malicious-app
- https://www.lares.com/blog/malicious-azure-ad-application-registrations/

## Defender For Endpoint
```KQL
let KnownApps = AADSignInEventsBeta
// Adjust the timerange depending on the retention period
| where Timestamp  between (ago(30d) .. ago(2d))
| distinct Application;
AADSignInEventsBeta
| where Timestamp > ago(2d)
| where not(Application in~ (KnownApps))
// If the AppID is empty then it is a third party App.
| extend IsExternalApp = iff(isempty(ApplicationId), "True", "False")
| project-reorder IsExternalApp, Application, AccountObjectId, IPAddress, ClientAppUsed
// For ResultType Reference see: https://learn.microsoft.com/en-us/azure/active-directory/develop/reference-aadsts-error-codes
```

## Sentinel
```KQL
let KnownApps = SigninLogs
// Adjust the timerange depending on the retention period
| where TimeGenerated between (ago(90d) .. ago(2d))
| distinct AppDisplayName;
SigninLogs
| where TimeGenerated > ago(2d)
| where not(AppDisplayName in~ (KnownApps))
// If the AppID is empty then it is a third party App.
| extend IsExternalApp = iff(isempty(AppId), "True", "False")
| project-reorder IsExternalApp, AppDisplayName, Identity, IPAddress, ClientAppUsed
// For ResultType Reference see: https://learn.microsoft.com/en-us/azure/active-directory/develop/reference-aadsts-error-codes
```

