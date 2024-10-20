# Threat Hunting Nighthawk RAT

#### IOC Source: https://raw.githubusercontent.com/fboldewin/YARA-rules/master/nighthawk.yar
#### Publish Date: 22 November 2022

### Defender XDR

```
let NighthawkRat = dynamic(['0551ca07f05c2a8278229c1dc651a2b1273a39914857231b075733753cb2b988', '9a57919cc5c194e28acd62719487c563a8f0ef1205b65adbe535386e34e418b8', '38881b87826f184cc91559555a3456ecf00128e01986a9df36a72d60fb179ccf', 'f3bba2bfd4ed48b5426e36eba3b7613973226983a784d24d7a20fcf9df0de74e', 'b775a8f7629966592cc7727e2081924a7d7cf83edd7447aa60627a2b67d87c94']);
DeviceFileEvents
| where SHA256 in (NighthawkRat)
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine
```
### Sentinel
```
let NighthawkRat = dynamic(['0551ca07f05c2a8278229c1dc651a2b1273a39914857231b075733753cb2b988', '9a57919cc5c194e28acd62719487c563a8f0ef1205b65adbe535386e34e418b8', '38881b87826f184cc91559555a3456ecf00128e01986a9df36a72d60fb179ccf', 'f3bba2bfd4ed48b5426e36eba3b7613973226983a784d24d7a20fcf9df0de74e', 'b775a8f7629966592cc7727e2081924a7d7cf83edd7447aa60627a2b67d87c94']);
DeviceFileEvents
| where SHA256 in (NighthawkRat)
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine
```



