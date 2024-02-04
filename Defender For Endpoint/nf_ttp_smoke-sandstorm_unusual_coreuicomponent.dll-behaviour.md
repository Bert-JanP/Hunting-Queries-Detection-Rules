# Smoke Sandstorm - SnailResin and SlugResin Infection Detection

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title                       | Link                                      |
|--------------|-----------------------------|-------------------------------------------|
| T1574.002    | Hijack Execution Flow: DLL Search Order Hijacking | [Hijack Execution Flow: DLL Search Order Hijacking](https://attack.mitre.org/techniques/T1574/002/) |
| T1059.003    | Command and Scripting Interpreter: Windows Command Shell | [Command and Scripting Interpreter: Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/) |

#### Description
SlugResin infection involves the use of a legitimate file to load a malicious binary through DLL search order hijacking, delivering the SlugResin backdoor onto the target's device. This backdoor grants the actor access to the compromised device, potentially leading to further malicious activities like malware deployment, credential theft, privilege escalation, and lateral movement. The infection involves a two-stage process with the SnailResin loader and SlugResin backdoor, both associated with the Smoke Sandstorm threat group. The infection chain includes the use of a zip file ("bringthemhome.zip") containing malicious DLL files and a benign executable, which leads to the execution of the backdoor and establishment of a command-and-control connection.

#### Risk
The risk addressed by this detection is the stealthy execution of malicious code through DLL hijacking, enabling persistent access and control over compromised systems. The ability of this technique to blend in with normal activity makes it particularly dangerous.

#### Author 
- **Name:** Gavin Knapp
- **Github:** [https://github.com/m4nbat](https://github.com/m4nbat)
- **Twitter:** [https://twitter.com/knappresearchlb](https://twitter.com/knappresearchlb)
- **LinkedIn:** [https://www.linkedin.com/in/grjk83/](https://www.linkedin.com/in/grjk83/)
- **Website:**

#### References
- Microsoft TI (Closed)
- [Microsoft Documentation on DLL Search Order Hijacking](https://docs.microsoft.com/en-us/security/engineering/dll-search-order-hijacking)

## Advanced Hunting

### Unusual CoreUIComponent.dll Behaviour Detection

```KQL
DeviceImageLoadEvents
| where FileName == 'CoreUIComponent.dll'
| where not(FolderPath has_any (@"\Windows\System32", @"\Windows\SysWOW64", @"\winsxs\", @"\program files"))
```

### Microsoft Defender Antivirus Detections

```KQL
AlertInfo 
| where Title has_any ("An executable loaded an unexpected dll","DLL search order hijack","Possible Sideload stealer activity","Possible S1deload stealer activity","Smoke Sandstorm activity group")
```
### Microsoft Defender for Endpoint Alerts

```KQL
let malware = datatable (name:string)["Trojan:Win64/SnailResin","Backdoor:Win64/SlugResin","Trojan:Win32/BassBreaker"];
AlertInfo 
| join AlertEvidence on AlertId
| extend Malware = tostring(parse_json(AdditionalFields).Name)
| where ( EntityType =~ "Malware" ) and isnotempty(Malware)  and Malware has_any(malware)
```







