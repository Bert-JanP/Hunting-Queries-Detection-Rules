# Total Succesful Sign-Ins by Browser

## Query Information

#### Description
This query lists all the different browsers that are used to succesfully sign in to your Entra ID Tenant. This could be used to detect rare browsers that are used to sign into your tenant.


## Defender XDR
```KQLAADSignInEventsBeta
| where isnotempty(UserAgent)
// Filter for successful sign ins only
| where ErrorCode == 0
| extend ParsedAgent = parse_json(parse_user_agent(UserAgent, "browser"))
| extend Browser = strcat(tostring(ParsedAgent.Browser.Family), " ", tostring(ParsedAgent.Browser.MajorVersion), ".", tostring(ParsedAgent.Browser.MinorVersion))
| summarize Total = count() by Browser
| sort by Total
```

## Sentinel
```KQL
SigninLogs
| where isnotempty(UserAgent)
// Filter for successful sign ins only
| where ResultType == 0
| extend ParsedAgent = parse_json(parse_user_agent(UserAgent, "browser"))
| extend Browser = strcat(tostring(ParsedAgent.Browser.Family), " ", tostring(ParsedAgent.Browser.MajorVersion), ".", tostring(ParsedAgent.Browser.MinorVersion))
| summarize Total = count() by Browser
| sort by Total
```

