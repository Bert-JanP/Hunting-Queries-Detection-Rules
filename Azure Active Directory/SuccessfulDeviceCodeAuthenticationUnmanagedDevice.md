# Successful device code sign-in from unmanaged device

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566.002 | Phishing: Spearphishing Link | https://attack.mitre.org/techniques/T1566/002/ |

#### Description
This query lists successful Entra ID sign-ins were device code authentication is used from an unmanaged device. This means that a device which is not managed by your organization has succesfully met the conditions to sign-in to your tenant using a managment API In addition you can filter on the previously set conditions in combination with a risk during sign-in to filter on cases that may have more priority.

The solutions for Sentinel (SigninLogs) and Defender XDR (AADSignInEventsBeta) differ slightly, but have the same output.

#### Risk
An adversary managed to succesfully sign-in to your organization using device code authentication.

#### References
- https://jeffreyappel.nl/how-to-protect-against-device-code-flow-abuse-storm-2372-attacks-and-block-the-authentication-flow/
- https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/

## Defender XDR
```KQL
AADSignInEventsBeta
// Filter only successful sign-ins
| where ErrorCode == 0
| where EndpointCall == "Cmsi:Cmsi"
// Filter on unmanaged devices
| where isempty(AadDeviceId)
// Optionally filter only on sign-ins with a risklevel assiciated with the sign-in
//| where RiskLevelDuringSignIn in(10, 50, 100)
| project-reorder TimeGenerated, AccountUpn, EndpointCall, ErrorCode, RiskLevelDuringSignIn, Application, ApplicationId, Country, IPAddress
```

## Sentinel
```KQL
SigninLogs
// Filter only successful sign-ins
| where ResultType == 0
| where AuthenticationProtocol == "deviceCode"
// Filter on unmanaged devices
| where isempty(DeviceDetail.deviceId)
| extend operatingSystem = tostring(DeviceDetail.operatingSystem)
// Optionally filter only on sign-ins with a risklevel assiciated with the sign-in
//| where RiskLevelDuringSignIn != "none"
| project-reorder TimeGenerated, UserPrincipalName, AuthenticationProtocol, ResultType, RiskLevelDuringSignIn, AppDisplayName, AppId, Location, IPAddress
```
