# List the top 10 external applications with the most consented users

## Query Information

#### Description
The query below lists the top 10 external applications with the most consented users. It is highly recommended to review newly added applications in which only user consent is given.

#### Risk
Individual users can allow applications that do not require admin consent to be active in your environment.

## Defender XDR
```KQL
let PrivilegeLevelInput = pack_array('Medium', 'High');
OAuthAppInfo
| where AppOrigin == "External"
| where ConsentedUsersCount > 0
| summarize arg_max(Timestamp, *) by OAuthAppId
| where PrivilegeLevel in (PrivilegeLevelInput)
| extend PublisherName = tostring(VerifiedPublisher.displayName), DateAdded = todatetime(VerifiedPublisher.addedDateTime)
| project AppName, OAuthAppId, ServicePrincipalId, AddedOnTime, PublisherName, AppOwnerTenantId, ConsentedUsersCount
| top 10 by ConsentedUsersCount
```

## Sentinel
```KQL
let PrivilegeLevelInput = pack_array('Medium', 'High');
OAuthAppInfo
| where AppOrigin == "External"
| where ConsentedUsersCount > 0
| summarize arg_max(TimeGenerated, *) by OAuthAppId
| where PrivilegeLevel in (PrivilegeLevelInput)
| extend PublisherName = tostring(VerifiedPublisher.displayName), DateAdded = todatetime(VerifiedPublisher.addedDateTime)
| project AppName, OAuthAppId, ServicePrincipalId, AddedOnTime, PublisherName, AppOwnerTenantId, ConsentedUsersCount
| top 10 by ConsentedUsersCount
```
