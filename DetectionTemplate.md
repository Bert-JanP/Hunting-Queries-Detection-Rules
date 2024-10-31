# *Detection Title*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1134.002 | Access Token Manipulation: Create Process with Token | https://attack.mitre.org/techniques/T1134/002/ |

#### Description
Description of the detection rule.

Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.

#### Risk
Explain what risk this detection tries to cover

#### Author <Optional>
- **Name:**
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References
- https://kqlquery.com/
- https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules
- example link 3

## Defender XDR
```KQL
// Paste your query here
DeviceProcessEvents
| where FileName == "Example.File"
```
## Sentinel
```KQL
// Paste your query here
DeviceProcessEvents
| where FileName == "Example.File"
```
