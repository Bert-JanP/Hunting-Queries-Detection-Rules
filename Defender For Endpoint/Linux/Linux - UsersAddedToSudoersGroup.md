# Hunt for users that have been added to the sudoers group

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1548.003 | Abuse Elevation Control Mechanism: Sudo and Sudo Caching|https://attack.mitre.org/techniques/T1548/003|

#### Description
This query allows you to hunt for users that have been added to the sudo group. The current list doest not contain all additions, but it covers most common additions. More can be added in the commandslist. Users that have been added to the sudoers group have root privilges.

#### Risk
A advasary adds itself to the sudoers group and can perform actions with root privileges. 

## Defender XDR

```
let Commands = dynamic([@"usermod -aG sudo", @"usermod -a -G sudo"]);
DeviceProcessEvents
| extend RegexGroupAddition = extract("adduser(.*) sudo", 0, ProcessCommandLine)
| where ProcessCommandLine has_any (Commands) or isnotempty(RegexGroupAddition)
```
## Sentinel
```
let Commands = dynamic([@"usermod -aG sudo", @"usermod -a -G sudo"]);
DeviceProcessEvents
| extend RegexGroupAddition = extract("adduser(.*) sudo", 0, ProcessCommandLine)
| where ProcessCommandLine has_any (Commands) or isnotempty(RegexGroupAddition)
```



