# Commandline Group Addition

## Query Information

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1098.007 | Account Manipulation: Additional Local or Domain Groups | https://attack.mitre.org/techniques/T1098/007/ |

#### Description
This query is aimed to detect users that are added to a group via the commandline. Adding users to a group via the commandline is a common technique used by adversaries to gain additional permissions on systems/the domain. 

#### Risk
An attacker got access to a system and added an account to a group.

#### References
- https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708

## Defender XDR
```KQL
// Source Sensitive Groups: https://techcommunity.microsoft.com/t5/security-compliance-and-identity/alert-when-a-group-is-added-to-a-sensitive-active-directory/ba-p/3436868
let SensitiveGroupName = pack_array(  // Declare Sensitive Group names. Add any groups that you manually tagged as sensitive
    'Account Operators',
    'Administrators',
    'Domain Admins', 
    'Backup Operators',
    'Domain Controllers',
    'Enterprise Admins',
    'Enterprise Read-only Domain Controllers',
    'Group Policy Creator Owners',
    'Incoming Forest Trust Builders',
    'Microsoft Exchange Servers',
    'Network Configuration Operators',
    'Print Operators',
    'Read-only Domain Controllers',
    'Replicator',
    'Schema Admins',
    'Server Operators'
);
DeviceProcessEvents
| where FileName in ("net.exe", "net1.exe")
| where ProcessCommandLine has_all ("add", "group") 
| extend GroupIsSentitive = iff(ProcessCommandLine has_any (SensitiveGroupName), 1, 0)
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessCommandLine, GroupIsSentitive
```
## Sentinel
```KQL
// Source Sensitive Groups: https://techcommunity.microsoft.com/t5/security-compliance-and-identity/alert-when-a-group-is-added-to-a-sensitive-active-directory/ba-p/3436868
let SensitiveGroupName = pack_array(  // Declare Sensitive Group names. Add any groups that you manually tagged as sensitive
    'Account Operators',
    'Administrators',
    'Domain Admins', 
    'Backup Operators',
    'Domain Controllers',
    'Enterprise Admins',
    'Enterprise Read-only Domain Controllers',
    'Group Policy Creator Owners',
    'Incoming Forest Trust Builders',
    'Microsoft Exchange Servers',
    'Network Configuration Operators',
    'Print Operators',
    'Read-only Domain Controllers',
    'Replicator',
    'Schema Admins',
    'Server Operators'
);
DeviceProcessEvents
| where FileName in ("net.exe", "net1.exe")
| where ProcessCommandLine has_all ("add", "group") 
| extend GroupIsSentitive = iff(ProcessCommandLine has_any (SensitiveGroupName), 1, 0)
| project TimeGenerated, DeviceName, ProcessCommandLine, InitiatingProcessCommandLine, GroupIsSentitive
```
