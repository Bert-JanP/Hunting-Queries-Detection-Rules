# Suspicious Key Vault Enumeration or Reads

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title | Link |
| --- | --- | --- |
| T1555.006 | Credentials from Password Stores: Cloud Secrets Management Stores | https://attack.mitre.org/techniques/T1555/006/ |

#### Description

Counts Key Vault secret, key, and certificate enumeration and read activities for each account. Enumeration includes listing objects, versions, and deleted objects. Use the counts and number of distinct vaults to identify unusual activity, then investigate the individual events and the account's expected responsibilities.

#### Risk

An attacker with access to an account or application that can access Azure Key Vault may enumerate stored objects or retrieve sensitive material. High-volume reads or access to multiple vaults can indicate credential harvesting. The query reports activity totals and intentionally does not apply a universal alert threshold; tune thresholds to normal activity in the tenant using `TotalEnumerationActivities` and `TotalReadActivities`.

#### References

- https://www.microsoft.com/en-us/security/blog/2025/03/05/silk-typhoon-targeting-it-supply-chain/

## Defender XDR

```KQL
// Adjust thresholds based on your own environment
let KeyVaultThreshold = 3;
let SecretReadActivitiesThreshold = 1;
let EnumerationActivitiesThreshold = 1;
let TimeFrame = 3h;
let EnumerationActivities = dynamic([
    "SecretList",
    "SecretListVersions",
    "SecretListDeleted",
    "KeyList",
    "KeyListVersions",
    "KeyListDeleted",
    "CertificateList",
    "CertificateListVersions",
    "CertificateListDeleted"
]);
let ReadActivities = dynamic([
    "SecretGet",
    "KeyGet",
    "CertificateGet"
]);
CloudKeyVaultEvents
| where ActivityName in~ (EnumerationActivities) or ActivityName in~ (ReadActivities)
| summarize Total = count(), UniqueKeyVaults = dcount(AzureResourceId), TotalEnumerationActivities = countif(ActivityName in~ (EnumerationActivities)), TotalReadActivities = countif(ActivityName in~ (ReadActivities)) by AccountObjectId, AccountType, bin(TimeGenerated, TimeFrame)
| where UniqueKeyVaults >= KeyVaultThreshold and TotalEnumerationActivities >= EnumerationActivitiesThreshold and TotalReadActivities >= SecretReadActivitiesThreshold
```