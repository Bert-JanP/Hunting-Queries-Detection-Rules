# Total Sign In actions by Operating System

## Query Information

#### Description
This query can be used to detect rare operating systems that are used to sign into your tenant. For example your company only has Windows company devices and you have sign ins with MacOS, those can ben intersting to investigate.

The query can be extended by filtering on failed or succesful sign ins.

## Defender For Endpoint
```
AADSignInEventsBeta
| summarize count() by OSPlatform
| sort by count_
```

## Sentinel
```
SigninLogs
| extend
     Browser = tostring(parse_json(DeviceDetail).browser),
     OS = tostring(parse_json(DeviceDetail).operatingSystem)
| summarize count() by OS
| sort by count_
```
