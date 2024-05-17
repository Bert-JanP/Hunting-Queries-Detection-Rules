# Detect when login is performed using a specified account (Cloud break glass account)

## Query Information

#### Description
It is best practice to have break glass accounts, which are excluded from all conditional access policies. To monitor all login activities under a specified account, this Detection Rule can be used. If any activity is performed using the specified account, an alert will be generated.

#### Risk
If an attacker could get access to a break glass account, this account could be used to bypass all conditional access rules, and get unrestricted access to the environment.

#### Author
- **Github: https://github.com/erikgruetter**

## Defender For Endpoint
```
AADSignInEventsBeta
| where AccountDisplayName  == "Input display name of account here"
| project AccountDisplayName,
     Country,
     IPAddress,
     Timestamp,
     Application,
     DeviceName,
     ReportId,
     LogonType,
     SessionId,
     OSPlatform,
     AccountObjectId,
     AccountUpn
```

## Sentinel
```
SigninLogs
| where UserDisplayName  == "Input display name of account here"
| project UserDisplayName,
     Location,
     IPAddress,
     TimeGenerated,
     AppDisplayName,
     DeviceDetail,
     UserPrincipalName
```


