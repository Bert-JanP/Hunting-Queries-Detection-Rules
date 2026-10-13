# Risky Sign-in Followed by Key Vault Activity

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title | Link |
| --- | --- | --- |
| T1555.006 | Credentials from Password Stores: Cloud Secrets Management Stores | https://attack.mitre.org/techniques/T1555/006/ |

#### Description

Identifies user sign-ins with a `RiskLevelDuringSignIn` value of 10 (low), 50 (medium), or 100 (high) that are followed by Azure Key Vault activity associated with the sign-in's unique token identifier. Review the account, source IP address, user agent, sign-in error code, accessed vault, and activity to determine whether the activity is authorized.

#### Risk

A compromised identity or session may be used to enumerate Key Vault objects or retrieve secrets, keys, or certificates. Successful retrieval can expose credentials and enable access to additional resources. Investigate both successful and failed sign-ins, and verify that the subsequent Key Vault activity is expected for the user and source IP.

#### References

- https://www.microsoft.com/en-us/security/blog/2025/03/05/silk-typhoon-targeting-it-supply-chain/

## Defender XDR

```KQL
EntraIdSignInEvents
| where RiskLevelDuringSignIn in (10, 50, 100)
| project SignInTime = Timestamp, IPAddress, UserAgent, AccountUpn, UniqueTokenId, ErrorCode
| join kind=inner (
    CloudKeyVaultEvents
    | where AccountType == "user"
    | extend UniqueTokenIdentifier = tostring(AdditionalFields.UniqueTokenIdentifier)
    | project KeyVaultEventTime = Timestamp, UniqueTokenIdentifier, AzureResourceId, ActivityName
) on $left.UniqueTokenId == $right.UniqueTokenIdentifier
| where KeyVaultEventTime >= SignInTime
```