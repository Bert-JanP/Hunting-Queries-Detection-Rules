# Find all the executed LDAP queries from a compromised device

## Defender XDR

```
let CompromisedDevice = "laptop1.com";
let SearchWindow = 48h; //Customizable h = hours, d = days
IdentityQueryEvents
| where Timestamp > ago(SearchWindow)
| where DeviceName == CompromisedDevice
| where Protocol == "Ldap"
| project
     Timestamp,
     QueryType,
     Query,
     Protocol,
     DeviceName,
     DestinationDeviceName,
     TargetAccountUpn
```
## Sentinel
```
let CompromisedDevice = "laptop1.com";
let SearchWindow = 48h; //Customizable h = hours, d = days
IdentityQueryEvents
| where TimeGenerated > ago(SearchWindow)
| where DeviceName == CompromisedDevice
| where Protocol == "Ldap"
| project
     TimeGenerated,
     QueryType,
     Query,
     Protocol,
     DeviceName,
     DestinationDeviceName,
     TargetAccountUpn
```



