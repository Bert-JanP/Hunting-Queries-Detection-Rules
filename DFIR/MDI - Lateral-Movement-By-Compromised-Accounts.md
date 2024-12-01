# Find which devices have been accessed by a list of compromised accounts and which protocol was used to connect
----
## Defender XDR

```
let ComprimsedUsers = dynamic(['user1', 'user2']);
let SearchWindow = 48h; //Customizable h = hours, d = days
IdentityLogonEvents
| where Timestamp > (now() - SearchWindow)
| where AccountName has_any (ComprimsedUsers)
| where isnotempty(TargetDeviceName)
| where ActionType == "LogonSuccess"
| project Timestamp, AccountName, Protocol, TargetDeviceName


```
## Sentinel
```
let ComprimsedUsers = dynamic(['user1', 'user2']);
let SearchWindow = 48h; //Customizable h = hours, d = days
IdentityLogonEvents
| where TimeGenerated > (now() - SearchWindow)
| where AccountName has_any (ComprimsedUsers)
| where isnotempty(TargetDeviceName)
| where ActionType == "LogonSuccess"
| project TimeGenerated, AccountName, Protocol, TargetDeviceName

```



