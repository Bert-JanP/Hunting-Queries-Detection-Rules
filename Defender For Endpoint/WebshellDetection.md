# Possible webshell on the endpoint

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1505.003 | Web Shell | <a href="https://attack.mitre.org/techniques/T1505/003">T1505.003: Web Shell</a>|

#### Description 
Attackers install web shells on servers by taking advantage of security gaps, typically vulnerabilities in web applications, in internet-facing servers. These attackers scan the internet, often using public scanning interfaces like shodan.io, to locate servers to target. They may use previously fixed vulnerabilities that unfortunately remain unpatched in many servers, but they are also known to quickly take advantage of newly disclosed vulnerabilities.

#### Risk
Attackers can run arbitrary code on a server by exploiting a vulnerable web application

#### References
- https://www.microsoft.com/en-us/security/blog/2021/02/11/web-shell-attacks-continue-to-rise/

#### Query 1
Look for suspicious process that IIS worker process (w3wp.exe), Apache HTTP server processes (httpd.exe, visualsvnserver.exe), etc. do not typically initiate (e.g., cmd.exe and powershell.exe)

```
DeviceProcessEvents
| where InitiatingProcessCommandLine has_any("beasvc.exe","coldfusion.exe","httpd.exe","owstimer.exe","visualsvnserver.exe","w3wp.exe") or InitiatingProcessCommandLine contains 'tomcat'
| where FileName != "csc.exe" // exclude csharp compiler
| where FileName != "php-cgi.exe" //exclude php group, fast cgi
| where FileName != "vbc.exe" //exclude Visual Basic Command Line Compiler
| summarize by FileName

```

#### Query 2 
Look for suspicious web shell execution, this can identify processes that are associated with remote execution and reconnaissance activity (example: “arp”, “certutil”, “cmd”, “echo”, “ipconfig”, “gpresult”, “hostname”, “net”, “netstat”, “nltest”, “nslookup”, “ping”, “powershell”, “psexec”, “qwinsta”, “route”, “systeminfo”, “tasklist”, “wget”, “whoami”, “wmic”, etc.)

```
DeviceProcessEvents
| where InitiatingProcessParentFileName in~("beasvc.exe","coldfusion.exe","httpd.exe","owstimer.exe","visualsvnserver.exe","w3wp.exe") or InitiatingProcessParentFileName startswith "tomcat"
| where InitiatingProcessFileName in~("powershell.exe","powershell_ise.exe","cmd.exe")
| where FileName != 'conhost.exe'
```

