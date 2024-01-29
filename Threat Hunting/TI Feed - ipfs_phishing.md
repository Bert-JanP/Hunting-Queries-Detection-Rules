# TTP Detection Rule: Check for Phishing Emails Using IPFS in Phishing Campaigns

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title                       | Link                                     |
|--------------|-----------------------------|------------------------------------------|
| T1566.002    | Phishing: Spearphishing Link| [Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/) |

#### Description
This detection rule focuses on identifying phishing emails that potentially use the InterPlanetary File System (IPFS) to host malicious content. The usage of IPFS in phishing campaigns is a sophisticated technique as it can bypass conventional security measures. The rule involves checking for subsequent connections to IPFS-hosted sites, which could indicate the execution of a phishing attack utilizing this decentralized file hosting system.

#### Risk
The risk targeted by this detection rule is the exploitation of IPFS in phishing campaigns, a method that could lead to successful phishing attacks due to the unconventional nature of IPFS as a hosting platform. Phishing attacks using IPFS can be more difficult to detect and can pose a significant threat to organizational security.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** [https://github.com/m4nbat](https://github.com/m4nbat)
- **Twitter:** [https://twitter.com/knappresearchlb](https://twitter.com/knappresearchlb)
- **LinkedIn:** [https://www.linkedin.com/in/grjk83/](https://www.linkedin.com/in/grjk83/)
- **Website:**

#### References
- [Talos Intelligence on IPFS Abuse](https://blog.talosintelligence.com/ipfs-abuse/)
- [Cisco-Talos IOCs](https://github.com/Cisco-Talos/IOCs/tree/main/2022/11)
- [Volexity Threat Intel](https://raw.githubusercontent.com/volexity/threat-intel/main/2023/2023-06-28%20POWERSTAR/attachments/ipfs.txt)

## Defender For Endpoint

```KQL
//check for phishing emails potentially using ipfs to host malicious content used in phishing campaigns.
let domains = externaldata (data:string)[h@"https://raw.githubusercontent.com/volexity/threat-intel/main/2023/2023-06-28%20POWERSTAR/attachments/ipfs.txt"];
EmailEvents
| where Timestamp > ago (30d)
| join EmailUrlInfo on NetworkMessageId
| where Url has_any (domains) and DeliveryAction !~ "Blocked"
```
## Sentinel

```KQL
//check for subsequent connections to the site
let domains = externaldata (data:string)
[h@"https://raw.githubusercontent.com/volexity/threat-intel/main/2023/2023-06-28%20POWERSTAR/attachments/ipfs.txt"];
DeviceNetworkEvents
| where TimeGenerated > ago (30d)
| where RemoteUrl has_any (domains)
```
