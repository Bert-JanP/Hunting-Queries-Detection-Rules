# Visualise the outdated Operating Systems used to connect to your cloud environment

### Defender XDR

```
CloudAppEvents
| where UserAgentTags contains "Outdated operating system"
| summarize count() by OSPlatform
| render piechart with(title="Outdated Operating Systems Used")
```
### Sentinel
```
CloudAppEvents
| where UserAgentTags contains "Outdated operating system"
| summarize count() by OSPlatform
| render piechart with(title="Outdated Operating Systems Used")
```
