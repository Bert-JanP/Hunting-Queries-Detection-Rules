# Multiple Accounts Locked

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1110 | Brute Force | https://attack.mitre.org/techniques/T1110/ |

#### Description
Detect when multiple accounts are locked in your Azure tenant in a short timeframe, this can indicate brute force or password spray attacks. This detection is based on error code 50053 wich results from two different reasons:
- IdsLocked - The account is locked because the user tried to sign in too many times with an incorrect user ID or password. The user is blocked due to repeated sign-in attempts
- Sign-in was blocked because it came from an IP address with malicious activity

#### Risk
Explain what risk this detection tries to cover

#### References
- https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes

## Sentinel
```KQL
let Threshold = 3;
let TimeFrame = 15m;
SigninLogs
| where ResultType == 50053
| summarize TotalAccounts = dcount(UserPrincipalName), Accounts = make_set(UserPrincipalName), UserAgentDetails = make_set(UserAgent) by bin(TimeGenerated, TimeFrame), IPAddress
| where TotalAccounts >= Threshold
| extend GeoIPInfo = geo_info_from_ip_address(IPAddress)
| extend country = tostring(parse_json(GeoIPInfo).country), state = tostring(parse_json(GeoIPInfo).state), city = tostring(parse_json(GeoIPInfo).city)
```