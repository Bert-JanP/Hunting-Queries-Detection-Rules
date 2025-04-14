# List external applications with highly privileged permissions

## Query Information

#### Description
The query below lists the external applications with highly privileged permissions. It is highly recommended to periodicly review the high priviliged external applications.

#### Risk
A third party application can be abused to steal information from your organization.

## Defender XDR
```KQL
OAuthAppInfo
| where AppOrigin == "External"
| where PrivilegeLevel == "High"
| summarize arg_max(Timestamp, *) by OAuthAppId
| extend PublisherName = tostring(VerifiedPublisher.displayName), DateAdded = todatetime(VerifiedPublisher.addedDateTime)
| project AppName, OAuthAppId, ServicePrincipalId, AddedOnTime, PublisherName, AppOwnerTenantId
```

## Sentinel
```KQL
OAuthAppInfo
| where AppOrigin == "External"
| where PrivilegeLevel == "High"
| summarize arg_max(TimeGenerated, *) by OAuthAppId
| extend PublisherName = tostring(VerifiedPublisher.displayName), DateAdded = todatetime(VerifiedPublisher.addedDateTime)
| project AppName, OAuthAppId, ServicePrincipalId, AddedOnTime, PublisherName, AppOwnerTenantId
```
