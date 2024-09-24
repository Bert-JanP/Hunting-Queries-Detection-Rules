# Typosquatted Email Received

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566 | Phishing | https://attack.mitre.org/techniques/T1566/ |

#### Description
Adversaries may create typosquatted domains to mimic your domains. This detection can be used to detect typosquatted domains and alert on entries. You can configure the threshold yourself based on the *TypoSquatMin* and *TypoSquatMax*, these values represent the percentage of how many unicode characters match.

#### Risk
An actor typosquats your domain to phish employees.

## Defender XDR
```KQL
let TypoSquatMin = 0.75;
let TypoSquatMax = 0.99; // If set to 1.0 it equals the domain.
EmailEvents
| where EmailDirection == "Inbound"
| extend SenderDomainUnicode = unicode_codepoints_from_string(tolower(SenderFromDomain))
| extend TypoSquadPercentage = jaccard_index(UnicodeDomain, SenderDomainUnicode)
| where TypoSquadPercentage between (TypoSquatMin .. TypoSquatMax)
| project-reorder TimeGenerated, SenderFromDomain, TypoSquadPercentage, RecipientEmailAddress, Subject
```

## Sentinel
```KQL
let TypoSquatMin = 0.75;
let TypoSquatMax = 0.99; // If set to 1.0 it equals the domain.
EmailEvents
| where EmailDirection == "Inbound"
| extend SenderDomainUnicode = unicode_codepoints_from_string(tolower(SenderFromDomain))
| extend TypoSquadPercentage = jaccard_index(UnicodeDomain, SenderDomainUnicode)
| where TypoSquadPercentage between (TypoSquatMin .. TypoSquatMax)
| project-reorder TimeGenerated, SenderFromDomain, TypoSquadPercentage, RecipientEmailAddress, Subject
```

#### Versions
| Version | Comment |
| ---  | --- |
| 1.0 | Initial commit |
