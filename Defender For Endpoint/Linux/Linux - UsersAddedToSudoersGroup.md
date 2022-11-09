# Hunt for users that have been added to the sudoers group (List is not complete)
----
### Defender For Endpoint

```
let Commands = dynamic([@"usermod -aG sudo", @"usermod -a -G sudo"]);
DeviceProcessEvents
| extend RegexGroupAddition = extract("adduser(.*) sudo", 0, ProcessCommandLine)
| where ProcessCommandLine has_any (Commands) or isnotempty(RegexGroupAddition)
```
### Sentinel
```
let Commands = dynamic([@"usermod -aG sudo", @"usermod -a -G sudo"]);
DeviceProcessEvents
| extend RegexGroupAddition = extract("adduser(.*) sudo", 0, ProcessCommandLine)
| where ProcessCommandLine has_any (Commands) or isnotempty(RegexGroupAddition)
```



