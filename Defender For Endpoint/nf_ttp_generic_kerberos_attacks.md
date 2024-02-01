# Kerberos attacks

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title                       | Link                                      |
|--------------|-----------------------------|-------------------------------------------|
|T1649 |Steal or Forge Authentication Certificates |  https://attack.mitre.org/techniques/T1649/ |
|T1558.003 |Kerberoasting |  https://attack.mitre.org/techniques/T1558/003/ |
|T1558 |Steal or Forge Kerberos Tickets |  https://attack.mitre.org/techniques/T1558/ |
|T1558.004 |AS-REP Roasting | https://attack.mitre.org/techniques/T1558/004/  |
|T1558.001 |Golden Ticket | https://attack.mitre.org/techniques/T1558/001/  |
|T1550.003 |Pass the Ticket |  https://attack.mitre.org/techniques/T1550/003/ |
|T1550.003 |Pass the Ticket |  https://attack.mitre.org/techniques/T1550/003/ |
|T1110 |Brute Force |  https://attack.mitre.org/techniques/T1110/ |
|T1558.002 |Silver Ticket | https://attack.mitre.org/techniques/T1558/002/  |

#### Description

#### Risk

#### Author 
- **Name:** Gavin Knapp
- **Github:** [https://github.com/m4nbat](https://github.com/m4nbat)
- **Twitter:** [https://twitter.com/knappresearchlb](https://twitter.com/knappresearchlb)
- **LinkedIn:** [https://www.linkedin.com/in/grjk83/](https://www.linkedin.com/in/grjk83/)
- **Website:**

#### References
- Microsoft TI (Closed)
- [stuff](link)

## Advanced Hunting

### Microsoft Defender Antivirus Detections

```KQL
AlertInfo 
| where Title has_any ("Successful logon using overpass-the-hash with potentially stolen credentials","Command line used for possible overpass-the-hash")
```

#### The following alerts might also indicate activity associated with this threat. These alerts, however, can be triggered by unrelated threat activity and are not monitored in the status cards provided with this report:

```KQL
AlertInfo 
| where Title has_any ("AD reconnaissance activities","Process related to possible AD reconnaissance","Suspicious Lsass Process Access","Bloodhound post-exploitation tool")
```

### Microsoft Defender for Identity Detection
```KQL
IdentityDirectoryEvents
| where ActionType == "Potential lateral movement path identified"
| project Timestamp, ActionType, Application, AccountName, AccountDomain, AccountSid, AccountDisplayName, DeviceName, AdditionalFields
```

### Common Mimikatz command lines 

```KQL
DeviceProcessEvents
| where ProcessCommandLine has_any ('sekurlsa::tickets /export', 'kerberos::ptt')
| project Timestamp, AccountName, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
```

### Common Rubeus command lines 

```KQL
DeviceProcessEvents
| where ProcessCommandLine has_any ('ptt /ticket', ' monitor /interval', ' asktgt', ' asktgs', ' golden', ' silver', ' kerberoast', ' asreproast', ' renew', ' brute')
| project Timestamp, AccountName, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
```
