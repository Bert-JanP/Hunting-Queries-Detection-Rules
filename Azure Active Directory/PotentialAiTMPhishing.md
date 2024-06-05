# Potential Adversary in the middle Phishing

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1557 | Adversary-in-the-Middle | https://attack.mitre.org/techniques/T1557/ |

#### Description
List potential adversary in the middle phishing attempts that have been identified by the **OfficeHome** application in combination with an empty deviceid. The OfficeHome application is known to be the default of some AiTM phishing kits. An empty deviceid is the result of an device that is not onboarded/known to your organization. If only onboarded devices should sign in to your orgs cloud apps, an empty id should raise alarms, since it is an unknown device. If the resultype 0 is included in the results a successful sign-in is performed.  

The query can be futher refined by only filtering on sign-ins with a risklevel during the sign-in phase. 

#### Risk
Adversary in the middle phishing has successfully been peformed on a user and they have tried to sign in or have successfully signed in depending on the resulttype. 

#### References
- https://twitter.com/ITguySoCal/status/1743785230396514464
- https://techcommunity.microsoft.com/t5/azure-data-explorer-blog/aitm-amp-bec-threat-hunting-with-kql/ba-p/3885166
- https://jeffreyappel.nl/aitm-mfa-phishing-attacks-in-combination-with-new-microsoft-protections-2023-edt/

## Defender For Endpoint
```KQL
AADSignInEventsBeta
| where Application == "OfficeHome"
| where AccountUpn has "@"
| where isempty(AadDeviceId)
| summarize RiskLevels = make_set(RiskLevelDuringSignIn), ResultTypes = make_set(ErrorCode), IPs = make_set(IPAddress) by CorrelationId, AccountUpn
// Optional to only filter on events with a RiskLevel during the sign-in
//| where RiskLevels has_any (10, 50, 100)
```
## Sentinel
```KQL
SigninLogs
| where AppDisplayName == "OfficeHome"
| where UserPrincipalName has "@"
| extend deviceId = tostring(DeviceDetail.deviceId), displayName = tostring(DeviceDetail.displayName)
| where isempty(deviceId)
| summarize RiskLevels = make_set(RiskLevelDuringSignIn), ResultTypes = make_set(ResultType), IPs = make_set(IPAddress) by CorrelationId, UserPrincipalName
// Optional to only filter on events with a RiskLevel during the sign-in
//| where RiskLevels has_any ("low", "medium", "high")
```