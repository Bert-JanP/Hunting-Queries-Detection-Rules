# Potential Kerberos Encryption Downgrade

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1558.003 | Steal or Forge Kerberos Tickets: Kerberoasting | https://attack.mitre.org/techniques/T1558/003/ |
| T1562.010 | Impair Defenses: Downgrade Attack | https://attack.mitre.org/techniques/T1562/010/ |

#### Description
Adversaries can use older kerberos encryption algorithms which are vulnerable to brute force attacks to crack passwords. This query can be used to detect changes in the support of kerberos encryption standards on domain joined devices. This query will list all changes that are performed after a device has joined the domain. If the results contain older encryption versions it could be an adversary trying to enable older ciphers to perform kerberoasting on a later stage.

What are weak algoritms? ([source](https://web.mit.edu/kerberos/krb5-latest/doc/admin/enctypes.html))
- des-cbc-crc	
- des-cbc-md4
- des-cbc-md5
- des3-cbc-sha1
- arcfour-hmac
- arcfour-hmac-exp

#### Risk
An adversary has performed an downgrade attack to be able to perform kerberoasting.

#### References
- https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos

## Defender XDR
```
IdentityDirectoryEvents
| where ActionType == "Account Supported Encryption Types changed"
| extend
    ToAccountSupportedEncryptionTypes = tostring(parse_json(AdditionalFields).['TO AccountSupportedEncryptionTypes']),
    FromAccountSupportedEncryptionTypes = tostring(parse_json(AdditionalFields).['FROM AccountSupportedEncryptionTypes']),
    TargetDevice = tostring(parse_json(AdditionalFields).['TARGET_OBJECT.DEVICE']),
    ActorDevice = tostring(parse_json(AdditionalFields).['ACTOR.DEVICE'])
// Exclude the devices that did already have a supported encryption enabled. This is mostly due to the deployment of a device.
| where FromAccountSupportedEncryptionTypes != "N/A"
| project Timestamp, DeviceName, FromAccountSupportedEncryptionTypes, ToAccountSupportedEncryptionTypes, ActorDevice, TargetDevice
```
## Sentinel
```
IdentityDirectoryEvents
| where ActionType == "Account Supported Encryption Types changed"
| extend
    ToAccountSupportedEncryptionTypes = tostring(parse_json(AdditionalFields).['TO AccountSupportedEncryptionTypes']),
    FromAccountSupportedEncryptionTypes = tostring(parse_json(AdditionalFields).['FROM AccountSupportedEncryptionTypes']),
    TargetDevice = tostring(parse_json(AdditionalFields).['TARGET_OBJECT.DEVICE']),
    ActorDevice = tostring(parse_json(AdditionalFields).['ACTOR.DEVICE'])
// Exclude the devices that did already have a supported encryption enabled. This is mostly due to the deployment of a device.
| where FromAccountSupportedEncryptionTypes != "N/A"
| project TimeGenerated, DeviceName, FromAccountSupportedEncryptionTypes, ToAccountSupportedEncryptionTypes, ActorDevice, TargetDevice
```
