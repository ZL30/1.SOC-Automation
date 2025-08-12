# SOC-Automation
This project serves as a practical demonstration of Security Orchestration, Automation, and Response (SOAR) principles within a Security Operations Center (SOC) environment. The goal is to streamline and accelerate the initial incident response process by building an integrated and automated workflow that connects various security tools.

![SOC Automation Diagram](Security%20Analysis%20Automation/Diagram-SOC.png)

### 🛠 Steps

1️⃣ Wazuh Custom Rule 

```xml
<rule id="100002" level="10">
  <if_sid>92057</if_sid>
  <field name="win.eventdata.commandline" type="pcre2">(?i)-encodedcommand</field>
  <description>PowerShell EncodedCommand Detected</description>
  <mitre>
    <id>T1059.001</id>
  </mitre>
</rule>
```
Detects any PowerShell command containing -encodedCommand.

MITRE Technique: T1059.001 – PowerShell.
