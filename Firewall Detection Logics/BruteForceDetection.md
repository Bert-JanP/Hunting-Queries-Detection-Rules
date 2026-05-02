# *Brute Force Attempts to SSH/RDP/VPN (High)*

## Query Information
**Why it matters:** Credential guessing is common and often precedes access.

**Logic**: Many denies/failures from same source to auth-heavy ports.

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1110.001, T1110.002, T1110.003, T1110.004 | Brute Force Authentication Failures with Multi-Platform Log Correlation | https://attack.mitre.org/detectionstrategies/DET0463/ |

#### Description
Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained. Without knowledge of the password for an account or set of accounts, an adversary may systematically guess the password using a repetitive or iterative mechanism. Brute forcing passwords can take place via interaction with a service that will check the validity of those credentials or offline against previously acquired credential data, such as password hashes.

Brute forcing credentials may take place at various points during a breach. For example, adversaries may attempt to brute force access to Valid Accounts within a victim environment leveraging knowledge gathered from other post-compromise behaviors such as OS Credential Dumping, Account Discovery, or Password Policy Discovery. Adversaries may also combine brute forcing activity with behaviors such as External Remote Services as part of Initial Access.

If an adversary guesses the correct password but fails to login to a compromised account due to location-based conditional access policies, they may change their infrastructure until they match the victim’s location and therefore bypass those policies.

#### Risk
1. Unauthorized Access: Once a password or encryption key is cracked, attackers can access sensitive accounts, impersonate users, and manipulate systems. 

2. Data Theft and Exploitation: Personal information, financial data, and private communications can be stolen and used for fraud, phishing, or identity theft. 

3. Cascading Security Breaches: Compromising one account, especially an administrator account, can allow attackers to infiltrate multiple systems, escalating the damage.

4. Service Disruption: Brute force attacks can overwhelm authentication systems, causing network slowdowns or acting as a smokescreen for other attacks.

5. Emotional and Financial Impact: Victims may experience account lockouts, reputational damage, and significant time and effort to recover from breaches.

#### Author <Optional>
- **Name: Ravi Nandan Ray**
- **Github: https://github.com/Rajaravi99**
- **Twitter:**
- **LinkedIn: www.linkedin.com/in/ravi-nandan-ray-605465163**
- **Website:**

#### References
- https://documentation.wazuh.com/current/proof-of-concept-guide/detect-brute-force-attack.html
- https://attack.mitre.org/techniques/T1110/
- https://www.geeksforgeeks.org/computer-networks/how-to-detect-brute-force-attacks/

## Defender XDR
```KQL
let Lookback = 5m;
let AttemptThreshold = 150;
let AuthPorts = dynamic([22, 23, 25, 53, 80, 3389, 443, 445, 8443, 500, 4500, 10443]); // various common ports to monitor for brute force attempt
CommonSecurityLog
| where TimeGenerated > ago(Lookback)
| where DestinationPort in (AuthPorts)
| where ipv4_is_private(DestinationIP) == true
| where ipv4_is_private(SourceIP) == false
| where DeviceAction has_any ("deny","denied","drop","dropped","fail","failed","reject","rejected")
| summarize Attempts=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated),
          TargetHosts=dcount(DestinationIP), Hosts=make_set(DestinationIP, 20)
  by SourceIP, DestinationPort, DeviceVendor, DeviceProduct
| where Attempts >= AttemptThreshold
```

## Sentinel
```KQL
let Lookback = 5m;
let AttemptThreshold = 150;
let AuthPorts = dynamic([22, 23, 25, 53, 80, 3389, 443, 445, 8443, 500, 4500, 10443]); // various common ports to monitor for brute force attempt
CommonSecurityLog
| where TimeGenerated > ago(Lookback)
| where DestinationPort in (AuthPorts)
| where ipv4_is_private(DestinationIP) == true
| where ipv4_is_private(SourceIP) == false
| where DeviceAction has_any ("deny","denied","drop","dropped","fail","failed","reject","rejected")
| summarize Attempts=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated),
          TargetHosts=dcount(DestinationIP), Hosts=make_set(DestinationIP, 20)
  by SourceIP, DestinationPort, DeviceVendor, DeviceProduct
| where Attempts >= AttemptThreshold
```

## Furthure fine-tuning suggestions
1. Add or exclude known ports according to your need or your organizational network firewall configuration.
2. Adjust thresholds if your perimeter is noisy.
3. Any specific group of users or groups who are allowed to perform such acitivity for any vulnurability scanning.
