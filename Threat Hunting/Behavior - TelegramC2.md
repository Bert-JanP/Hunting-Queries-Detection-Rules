# Threat Hunting for telegram as a Commmand & Control channel

#### Behaviour sources:
- https://blog.sucuri.net/2020/09/phishing-page-targets-atts-employee-multi-factor-authentication.html
- https://cyware.com/news/malware-authors-leveraging-telegram-based-command-and-control-7010f17b
- https://twitter.com/adamtheanalyst/status/1592561452803829760?s=46&t=0s88GjPSLLjtgcGdFsC9XQ

### Defender For Endpoint

```
DeviceNetworkEvents
| where RemoteUrl contains "api.telegram.org"
| project 
    Timestamp,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName,
    InitiatingProcessAccountDomain
```
### Sentinel
```
DeviceNetworkEvents
| where RemoteUrl contains "api.telegram.org"
| project 
    TimeGenerated,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName,
    InitiatingProcessAccountDomain
```



