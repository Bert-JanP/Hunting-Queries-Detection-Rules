# *NTDS.DIT File Modifications*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1003 | OS Credential Dumping: NTDS  | [Link](https://attack.mitre.org/techniques/T1003/003/) |

#### Description
NTDS.DIT stands for New Technology Directory Services Directory Information Tree. It serves as the primary database file within Microsoft’s Active Directory Domain Services (AD DS). Adversaries may attempt to access or modify the Active Directory domain database in order to steal credential information or perform other types of attack. By default, the NTDS file (NTDS.dit) is located in %SystemRoot%\NTDS\Ntds.dit of a domain controller.

#### Risk / Analysis
The hunt query results contain a summary table, including the counts and a sample of the devices and files modified along with the processes responsible for such action, therefore legitimate backup solutions might appear here. Note that the query searches for any File Events table records matching the keywords "ntds" and "dit" which might be potentially linked to Write/Modification activity related to the AD domain DB file.

To get all devices or all files, instead of adding those fields to the group by statement, you can simply change the summarize function ```take_any``` to ```make_set```.

#### Author <Optional>
- **Name:** Alex Teixeira
- **Github:** https://github.com/inodee
- **Twitter:** https://x.com/ateixei
- **LinkedIn:** https://www.linkedin.com/in/inode
- **Website:** https://detect.fyi

#### References
- [Understanding NTDS.DIT: The Core of Active Directory](https://medium.com/@harikrishnanp006/understanding-ntds-dit-the-core-of-active-directory-faac54cc628a)
- [Introducing ntdissector, a swiss army knife for your NTDS.dit files](https://www.synacktiv.com/publications/introducing-ntdissector-a-swiss-army-knife-for-your-ntdsdit-files.html)


## Defender XDR
```KQL
// Author: Alex Teixeira (alex@opstune.com)
search in(DeviceFileEvents) "ntds" and "dit" and ActionType:"FileModified"
| where Timestamp > ago(90d)
| summarize Device_Count=dcount(DeviceId), Device_Sample=take_any(DeviceName), File_Count=dcount(FolderPath), File_Sample=take_any(FolderPath), Last_Seen=max(Timestamp) by InitiatingProcessParentFileName, InitiatingProcessFolderPath, InitiatingProcessAccountName
| sort by Device_Count desc, File_Count desc 


```
## Sentinel
```KQL
// Author: Alex Teixeira (alex@opstune.com)
search in(DeviceFileEvents) "ntds" and "dit" and ActionType:"FileModified"
| where TimeGenerated > ago(90d)
| summarize Device_Count=dcount(DeviceId), Device_Sample=take_any(DeviceName), File_Count=dcount(FolderPath), File_Sample=take_any(FolderPath), Last_Seen=max(Timestamp) by InitiatingProcessParentFileName, InitiatingProcessFolderPath, InitiatingProcessAccountName
| sort by Device_Count desc, File_Count desc 
```
