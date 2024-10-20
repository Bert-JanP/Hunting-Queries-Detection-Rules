# Visualise Time Of Last Password Reset

## Query Information

#### Description
Visualise the time of which a password reset has last taken place, the information is grouped in buckets of 10 days. While password expiration requirements do more harm than good it is still recommended to take a look at the accounts from which the password has not changed for years. This is due to the changes in the password policy, if the policy has been changed after the latest password change of that account is it likely that the account does not adhere to the currenct password policy. Every next password policy is in most cases an improvement, therefore it is expected that accounts that have not changed their password after the latest policy update do not meet the current complexity requirements.

#### Risk
If a password has not been changed for years, it might be that the account does not adhere to the current password policy. This can have potential impact, since the password complexity is most likely weaker then expected.

#### References
- https://learn.microsoft.com/en-us/microsoft-365/admin/misc/password-policy-recommendations?view=o365-worldwide

## Defender XDR
```KQL
AADSignInEventsBeta
| where Timestamp > ago(30d)
// Collect the last event for each account
| summarize arg_max(Timestamp, *) by AccountObjectId
| where isnotempty(LastPasswordChangeTimestamp)
// Calculate the period between now and the last password change
| extend DaysSinceLastPasswordChange = datetime_diff('day', now(), LastPasswordChangeTimestamp)
// put the results into bins of 10 days
| summarize TotalAccounts = count() by  bin(DaysSinceLastPasswordChange, 10)
| sort by DaysSinceLastPasswordChange asc
| render columnchart with(xtitle="Days since last password change", ytitle="Total accounts")
```

