# Total Succesful Sign-Ins by Operating System

## Query Information

#### Description
This query can be used to detect rare operating systems that are used to sign into your tenant. For example your company only has Windows company devices and you have sign ins with MacOS, those can ben intersting to investigate.

This query can also be used to determine with Operting Systems need to be added to your Conditional Access Policies.

## Defender For Endpoint
```KQL
AADSignInEventsBeta
| where isnotempty(UserAgent)
// Filter for successful sign ins only
| where ErrorCode == 0
| extend ParsedAgent = parse_json(parse_user_agent(UserAgent, "os"))
| extend OperatingSystem = strcat(tostring(ParsedAgent.OperatingSystem.Family), " ", tostring(ParsedAgent.OperatingSystem.MajorVersion))
| summarize Total = count() by OperatingSystem
| sort by Total
```

## Sentinel
```KQL
SigninLogs
| where isnotempty(UserAgent)
// Filter for successful sign ins only
| where ResultType == 0
| extend ParsedAgent = parse_json(parse_user_agent(UserAgent, "os"))
| extend OperatingSystem = strcat(tostring(ParsedAgent.OperatingSystem.Family), " ", tostring(ParsedAgent.OperatingSystem.MajorVersion))
| summarize Total = count() by OperatingSystem
| sort by Total
```

