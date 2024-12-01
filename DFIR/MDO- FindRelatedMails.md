# Find Related Emails

## Query Information

#### Description
The EmailClusterId which can be assigned to a mail is the identifier for the group of similar emails clustered based on heuristic analysis of their contents. Therefore this identifier can be leveraged to find related mails. This is not a hash value of the mail. Once you have identified a suspicious mail, you can run the query below to determine if there are related mails send to your users. This can for example be from a different sender or the content of the mail has changed from *Hello Bob* to *Hello Alice* but the rest of the contents has stayed the same.

#### References
- https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-emailevents-table?view=o365-worldwide

## Defender XDR
```
let MaliciousEmailCluseriId = "3163234347533"; // Input the EmailClusterId here
EmailEvents
| where EmailClusterId == MaliciousEmailCluseriId
```

## Sentinel
```
let MaliciousEmailCluseriId = "3163234347533"; // Input the EmailClusterId here
EmailEvents
| where EmailClusterId == MaliciousEmailCluseriId
```



