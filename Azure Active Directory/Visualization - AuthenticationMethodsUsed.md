# Visualization authentication Methods Used

## Query Information

#### Description
This visualisation shows the authentication methods that have been used based on the selected TimeFrame.

#### References
- https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-methods

## Sentinel
```KQL
let TimeFrame = 30d;
SigninLogs
| where TimeGenerated > ago(TimeFrame)
| where ResultType == 0
| summarize Total = count() by AuthenticationProtocol, bin(TimeGenerated, 1d)
```
