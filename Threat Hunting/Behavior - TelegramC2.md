# Threat Hunting for telegram as a Commmand & Control channel

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1071.001 | Application Layer Protocol: Web Protocols | https://attack.mitre.org/techniques/T1071/001 |

#### Description
Telegram can be used as a C2 channel, this can be done by leveraging the Telegram API. Multiple actors have used this in the wild, also for exfiltration methods (see references). With this detection rule we focus on the api if telegram (api.telegram.org).

#### Risk
An actor can use telgram as a Command & Control channel, while the attackers disguise the communication as Telegram traffic.

#### References
- https://www.mandiant.com/resources/blog/telegram-malware-iranian-espionage 
- https://blog.sucuri.net/2020/09/phishing-page-targets-atts-employee-multi-factor-authentication.html
- https://cyware.com/news/malware-authors-leveraging-telegram-based-command-and-control-7010f17b
- https://twitter.com/adamtheanalyst/status/1592561452803829760?s=46&t=0s88GjPSLLjtgcGdFsC9XQ

## Defender XDR
```KQL
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

## Sentinel
```KQL
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



