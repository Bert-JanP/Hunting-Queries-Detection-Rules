# *Scattered Spider Defense Evasion via Conditional Access Policies Detection*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title                             | Link                                                  |
|--------------|-----------------------------------|-------------------------------------------------------|
| T1562.001    | Impair Defenses: Disable or Modify Tools | [Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/) |

#### Description
This detection rule focuses on identifying modifications to Conditional Access Policies, a tactic employed by threat actors like Scattered Spider for defense evasion. The rule includes two queries: one for detecting updates to conditional access policies, specifically changes in 'locations' and 'excludeLocations', and another for identifying the addition of trusted locations, which can be indicative of an attacker trying to bypass security measures.

#### Risk
The risk addressed here is the manipulation of access controls to evade detection and maintain persistent access. Modifying conditional access policies can allow attackers to operate undetected within a network, as these changes might weaken the security posture or create blind spots.

#### Author 
- **Name:** Gavin Knapp
- **Github:** [https://github.com/m4nbat](https://github.com/m4nbat)
- **Twitter:** [https://twitter.com/knappresearchlb](https://twitter.com/knappresearchlb)
- **LinkedIn:** [https://www.linkedin.com/in/grjk83/](https://www.linkedin.com/in/grjk83/)
- **Website:**

#### References
- [Microsoft Documentation on Conditional Access Policies](https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/)
- [MITRE ATT&CK on Defense Evasion](https://attack.mitre.org/tactics/TA0005/)

## Defender For Endpoint
```KQL
AuditLogs
| where OperationName =~ "Update conditional access policy" and TargetResources has_all ('locations','excludeLocations')
