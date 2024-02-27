# Multiple Sensitive Group Additions From Commandline

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1078.002 | Valid Accounts: Domain Accounts | https://attack.mitre.org/techniques/T1078/002/ |

#### Description
This query detects when multiple sentitive group additions have been initiated from the commandline within a certain timeframe. This timeframe can be configured using the *BinTimeFrame* variable. The *AlertThreshold* can be used to tweak the detection to met a certain threshold that you want to aim for, if set to one every commandline addition will be alerted.

#### Risk
An adversary got access to an account and tries to elevate permissions by adding themselves or a different account to a privileged group. 

#### References
- https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708

## Defender For Endpoint
```KQL
let BinTimeFrame = 1h;
let AlertThreshold = 3;
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
| summarize TotalCommands = dcount(ProcessCommandLine), ExecutedCommands = make_set(ProcessCommandLine), arg_max(Timestamp, *) by DeviceName, bin(Timestamp, BinTimeFrame)
| where TotalCommands >= AlertThreshold
```
## Sentinel
```KQL
let BinTimeFrame = 1h;
let AlertThreshold = 3;
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
| summarize TotalCommands = dcount(ProcessCommandLine), ExecutedCommands = make_set(ProcessCommandLine), arg_max(TimeGenerated, *) by DeviceName, bin(TimeGenerated, BinTimeFrame)
| where TotalCommands >= AlertThreshold
```