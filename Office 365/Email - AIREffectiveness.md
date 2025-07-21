# Automated investigation and response effectiveness

## Query Information

#### Description
THis query only returns results if automated investigation and response is enabled in Defender For Office. The query is aimed to display the effectiveness of AIR, it could be that these automatic response actions fail, hence it is important to review these on a periodic basis.
The query lists the statistics by day and result.


#### References
- https://learn.microsoft.com/en-us/defender-office-365/air-about

## Defender XDR
```KQL
EmailPostDeliveryEvents
 where ActionType =~ Automated Remediation
 summarize TotalNetworkMessages = dcount(NetworkMessageId) by bin(Timestamp, 1d), ActionResult
```

## Sentinel
```KQL
EmailPostDeliveryEvents
 where ActionType =~ Automated Remediation
 summarize TotalNetworkMessages = dcount(NetworkMessageId) by bin(Timestamp, 1d), ActionResult
```
