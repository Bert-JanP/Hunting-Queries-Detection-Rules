# Password change after succesful brute force

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1098 | Account Manipulation | https://attack.mitre.org/techniques/T1098/ |
| T1110 | Brute Force | https://attack.mitre.org/techniques/T1110/ |

#### Description
Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained. Without knowledge of the password for an account or set of accounts, an adversary may systematically guess the password using a repetitive or iterative mechanism. This query combines the brute force indicators with a followed password change after the adversary has gained access to an account. 

The query uses a variety of different variables which determine the result.
- *FailedLogonsThreshold* - The minimum amount of failed logons.
- *SuccessfulLogonsThreshold* - The minimum amount of successful logons.
- *TimeWindow* - Timewindow in which the failed and successful thresholds must be met.
- *SearchWindow* - Time between the successful brute force and the password change.

#### Risk
An adversary has successfully performed a brute force on an account and changes the password to keep persistence

#### References
- https://attack.mitre.org/datasources/DS0002/#User%20Account%20Modification

## Defender XDR
```KQL
let FailedLogonsThreshold = 20;
let SuccessfulLogonsThreshold = 1;
let TimeWindow = 15m;
// Time between the succesful brute force and password change. Difference should be added in minutes
let SearchWindow = 120;
IdentityLogonEvents
// Filter emtpy UPN
| where isnotempty(AccountUpn)
| summarize
    TotalAttempts = count(),
    SuccessfulAttempts = countif(ActionType == "LogonSuccess"),
    FailedAttempts = countif(ActionType == "LogonFailed")
    by bin(Timestamp, TimeWindow), AccountUpn
// Use variables to define brute force attack
| where SuccessfulAttempts >= SuccessfulLogonsThreshold and FailedAttempts >= FailedLogonsThreshold
// join password changes
| join kind=inner (IdentityDirectoryEvents
    | where Timestamp > ago(30d)
    | where ActionType == "Account Password changed"
    | where isnotempty(TargetAccountUpn)
    | extend PasswordChangeTime = Timestamp
    | project PasswordChangeTime, TargetAccountUpn)
    on $left.AccountUpn == $right.TargetAccountUpn
// Collect timedifference between brute force (note that is uses the bin time) and the password change
| extend TimeDifference = datetime_diff('minute', PasswordChangeTime, Timestamp)
// Remove all entries where the password change took place before the brute force
| where TimeDifference > 0
| where TimeDifference <= SearchWindow
```

## Sentinel
```KQL
let FailedLogonsThreshold = 20;
let SuccessfulLogonsThreshold = 1;
let TimeWindow = 15m;
// Time between the succesful brute force and password change. Difference should be added in minutes
let SearchWindow = 120;
IdentityLogonEvents
// Filter emtpy UPN
| where isnotempty(AccountUpn)
| summarize
    TotalAttempts = count(),
    SuccessfulAttempts = countif(ActionType == "LogonSuccess"),
    FailedAttempts = countif(ActionType == "LogonFailed")
    by bin(TimeGenerated, TimeWindow), AccountUpn
// Use variables to define brute force attack
| where SuccessfulAttempts >= SuccessfulLogonsThreshold and FailedAttempts >= FailedLogonsThreshold
// join password changes
| join kind=inner (IdentityDirectoryEvents
    | where TimeGenerated > ago(30d)
    | where ActionType == "Account Password changed"
    | where isnotempty(TargetAccountUpn)
    | extend PasswordChangeTime = TimeGenerated
    | project PasswordChangeTime, TargetAccountUpn)
    on $left.AccountUpn == $right.TargetAccountUpn
// Collect timedifference between brute force (note that is uses the bin time) and the password change
| extend TimeDifference = datetime_diff('minute', PasswordChangeTime, TimeGenerated)
// Remove all entries where the password change took place before the brute force
| where TimeDifference > 0
| where TimeDifference <= SearchWindow
```
