# SOC-Automation
This project serves as a practical demonstration of Security Orchestration, Automation, and Response (SOAR) principles within a Security Operations Center (SOC) environment. The goal is to streamline and accelerate the initial incident response process by building an integrated and automated workflow that connects various security tools.

![SOC Automation Diagram](Security%20Analysis%20Automation/Diagram-SOC.png)

🔍 PowerShell EncodedCommand Detection & Automated Response

This project demonstrates how to detect malicious PowerShell commands using the -EncodedCommand flag with Wazuh, then automate the incident response using Shuffle.io, TheHive.

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

2️⃣ Testing

Run Administrator PowerShell on a Windows system with Wazuh Agent:

```xml
$command = 'Write-Host "Hello Attacker"'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encodedcommand = [Convert]::ToBase64String($bytes)
$encodedcommand
VwByAGkAdABlAC0ASABvAHMAdAAgACIASABlAGwAbABvACAAQQB0AHQAYQBjAGsAZQByACIA
```
```xml
powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIASABlAGwAbABvACAAQQB0AHQAYQBjAGsAZQByACIA
Hello Attacker
```

The alert should appear in Wazuh Dashboard.

![SOC Automation Diagram](Security%20Analysis%20Automation/Wazuh-alert.PNG)

3️⃣ Wazuh → Shuffle Integration

Add to /var/ossec/etc/ossec.conf:

```xml
<integration>
    <name>shuffle</name>
    <hook_url>https://shuffler.io/api/v1/hooks/webhook_xxxxxxxxxxx->
    <rule_id>100002</rule_id>
    <alert_format>json</alert_format>
</integration>
```
Restart Wazuh Manager:
```xml
sudo systemctl restart wazuh-manager
```
