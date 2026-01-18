# Storm-0539 AiTM URLs - EmailEvents

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1557 | Adversary-in-the-Middle | https://attack.mitre.org/techniques/T1557/ |

#### Description
Microsoft Threat Intelligence has identified that the following url parts are used by Storm-0539 to deploy AiTM phishing pages:
- /Udlaps/
- /Usrlop/
- /adls/index.html
- /saml2/index.html

This query lists matches on the parts of the URL if found in emails.

#### Risk
These URLs lead to adversary-in-the-middle (AiTM) pages that allow Storm-0539 to steal credentials and session tokens.

#### References
- https://twitter.com/MsftSecIntel/status/1735351713907773711

## Defender XDR
```KQL
let URLs = dynamic([@'/Udlaps/', @'/Usrlop/', @'/adls/index.html', @'/saml2/index.html']);
EmailUrlInfo
| where Url has_any (URLs)
| join kind=inner EmailEvents on NetworkMessageId
```
## Sentinel
```KQL
let URLs = dynamic([@'/Udlaps/', @'/Usrlop/', @'/adls/index.html', @'/saml2/index.html']);
EmailUrlInfo
| where Url has_any (URLs)
| join kind=inner EmailEvents on NetworkMessageId
```
