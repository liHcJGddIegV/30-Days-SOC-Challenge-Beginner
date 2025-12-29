# Day#34- Incident Reporting and Documentation

---

## 🎯 Objective

To learn how to write clear, comprehensive incident reports that communicate technical findings to both technical and non-technical audiences, ensuring proper documentation for compliance, knowledge sharing, and continuous improvement.

---

## 🖥️ Lab Setup

### **System Requirements**
- **Word Processor:** Microsoft Word, Google Docs, or LibreOffice
- **Template Tools:** Markdown editor (optional)

### **Prerequisites**
- Understanding of incident response lifecycle (Day 11)
- Familiarity with MITRE ATT&CK (Day 32)
- Completed incident investigation scenarios from previous labs

---

## 📘 Why Incident Reporting Matters

**Incident documentation** is a critical SOC analyst skill that serves multiple purposes:

### **Key Purposes**
- **Compliance:** Regulatory requirements (GDPR, HIPAA, PCI DSS) mandate incident documentation
- **Legal Evidence:** May be used in legal proceedings or law enforcement investigations
- **Knowledge Sharing:** Helps other analysts learn from incidents
- **Metrics:** Provides data for measuring SOC performance (MTTD, MTTR)
- **Post-Incident Review:** Enables lessons learned and process improvement
- **Executive Communication:** Informs leadership of security posture
- **Insurance Claims:** Documentation required for cyber insurance claims

---

## 📋 Types of Incident Reports

### **1. Technical Incident Report**
**Audience:** SOC Team, IR Team, Security Engineers
**Purpose:** Detailed technical analysis for remediation and detection improvement

**Includes:**
- Complete timeline of events
- Technical IOCs (IPs, domains, hashes, file paths)
- MITRE ATT&CK technique mapping
- Detailed forensic findings
- Remediation steps taken
- Detection gaps identified

---

### **2. Executive Summary**
**Audience:** C-Suite, Board Members, Non-Technical Management
**Purpose:** High-level overview of business impact and response

**Includes:**
- What happened (in plain English)
- Business impact (downtime, data loss, financial impact)
- What was done to resolve it
- Recommendations to prevent recurrence
- No jargon, acronyms explained

---

### **3. Compliance Report**
**Audience:** Compliance Officers, Auditors, Regulators
**Purpose:** Demonstrate regulatory compliance

**Includes:**
- Incident classification per regulatory framework
- Timeline with evidence preservation
- Notification requirements met
- Affected data and individuals
- Remediation and controls implemented

---

### **4. After-Action Report (AAR)**
**Audience:** SOC Team, Management
**Purpose:** Lessons learned and process improvement

**Includes:**
- What went well
- What went poorly
- Process gaps identified
- Recommended improvements
- Training needs identified

---

## 📝 Technical Incident Report Template

```markdown
# INCIDENT REPORT

## EXECUTIVE SUMMARY
[2-3 sentences describing the incident for non-technical readers]

---

## INCIDENT DETAILS

| Field | Value |
|-------|-------|
| **Incident ID** | INC0012345 |
| **Severity** | High / Medium / Low |
| **Status** | Resolved / Ongoing / Monitoring |
| **Incident Type** | Malware / Phishing / Data Breach / Unauthorized Access |
| **Detected By** | SIEM Alert / User Report / Threat Hunt / Third Party |
| **Detection Date/Time** | YYYY-MM-DD HH:MM UTC |
| **Containment Date/Time** | YYYY-MM-DD HH:MM UTC |
| **Resolution Date/Time** | YYYY-MM-DD HH:MM UTC |
| **MTTD** | Mean Time To Detect (minutes) |
| **MTTR** | Mean Time To Respond (minutes) |
| **Lead Analyst** | [Your Name] |
| **Support Team** | [Names of others involved] |

---

## AFFECTED SYSTEMS

| Hostname | IP Address | OS | Department | Impact |
|----------|-----------|----|-----------
|--------|
| DESKTOP-WIN10-42 | 192.168.10.105 | Windows 10 | Finance | Compromised |
| WEB-SERVER-01 | 192.168.10.50 | Ubuntu 20.04 | IT | Scanned |

---

## INDICATORS OF COMPROMISE (IOCs)

### IP Addresses
- 203.0.113.45 (External attacker IP - Russia)
- 198.51.100.78 (C2 server - Netherlands)

### Domains
- malicious-payload[.]com
- data-exfil[.]ru

### File Hashes (SHA256)
- d41d8cd98f00b204e9800998ecf8427e (payload.exe)
- 7d865e959b2466918c9863afca942d0f (update.dll)

### File Paths
- C:\Temp\update.exe
- C:\Users\jdoe\AppData\Roaming\SystemUpdate\

### Registry Keys
- HKLM\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate

### User Accounts
- compromised_user: jdoe
- created_account: HelpDeskSupport (malicious)

---

## INCIDENT TIMELINE

| Date/Time (UTC) | Event | Source | Analyst Notes |
|-----------------|-------|--------|---------------|
| 2024-12-28 14:32 | Phishing email received | Email Gateway Logs | Subject: "Urgent: Password Reset Required" |
| 2024-12-28 14:45 | User opened malicious attachment | Endpoint logs | File: Invoice_Dec2024.xlsm |
| 2024-12-28 14:46 | Macro executed PowerShell | Event ID 4104 | Encoded command detected |
| 2024-12-28 14:47 | Download of secondary payload | Proxy logs | Downloaded from malicious-payload[.]com |
| 2024-12-28 14:50 | Scheduled task created | Event ID 4698 | Task: "WindowsUpdate" |
| 2024-12-28 15:00 | C2 communication established | Firewall logs | Outbound to 198.51.100.78:4444 |
| 2024-12-28 15:15 | **DETECTED** by EDR | Wazuh Alert | Alert: Suspicious outbound connection |
| 2024-12-28 15:20 | Analyst begins investigation | Ticket INC0012345 | Assigned to Jane Doe |
| 2024-12-28 15:45 | Host isolated from network | SOC Action | Network quarantine applied |
| 2024-12-28 16:00 | Malware removed | IR Team | AV scan + manual removal |
| 2024-12-28 16:30 | System reimaged | IT Team | Full rebuild from clean image |
| 2024-12-28 17:00 | User credentials reset | IT Help Desk | Password changed, MFA enforced |
| 2024-12-28 17:30 | **RESOLVED** | SOC Manager | Incident closed |

---

## ATTACK ANALYSIS (MITRE ATT&CK MAPPING)

| Tactic | Technique ID | Technique Name | Evidence |
|--------|--------------|----------------|----------|
| Initial Access | T1566.001 | Phishing: Spearphishing Attachment | Email with malicious Excel file |
| Execution | T1204.002 | User Execution: Malicious File | User enabled macros |
| Execution | T1059.001 | PowerShell | Macro executed encoded PowerShell |
| Persistence | T1053.005 | Scheduled Task/Job | Task "WindowsUpdate" created |
| Command and Control | T1071.001 | Web Protocols | HTTP C2 to 198.51.100.78:4444 |
| Defense Evasion | T1027 | Obfuscated Files or Information | Base64 encoded PowerShell |

---

## ROOT CAUSE ANALYSIS

**Primary Cause:**
User fell victim to phishing email and enabled macros in a malicious Excel file.

**Contributing Factors:**
1. Macros enabled by default on user workstation
2. User not trained on phishing awareness (last training: 18 months ago)
3. Email gateway did not flag attachment as malicious
4. EDR detected C2 communication but not initial execution

---

## BUSINESS IMPACT

- **Systems Affected:** 1 workstation (Finance department)
- **Data Compromised:** Potentially sensitive financial documents accessible to user jdoe
- **Downtime:** 2 hours (system rebuild)
- **Financial Impact:** Estimated $5,000 (analyst time + system rebuild)
- **Regulatory Impact:** None (no PII/PHI exfiltrated)
- **Reputational Impact:** None (contained before external exposure)

---

## RESPONSE ACTIONS TAKEN

### Containment
- ✅ Host 192.168.10.105 isolated from network at 15:45 UTC
- ✅ C2 IP 198.51.100.78 blocked at firewall
- ✅ Domain malicious-payload[.]com added to DNS blackhole

### Eradication
- ✅ Malware removed via AV scan
- ✅ Scheduled task "WindowsUpdate" deleted
- ✅ Registry persistence keys removed
- ✅ System reimaged from clean baseline

### Recovery
- ✅ System returned to production at 17:30 UTC
- ✅ User credentials reset with complex password
- ✅ Multi-Factor Authentication enforced for user

### Post-Incident
- ✅ IOCs added to threat intelligence platform
- ✅ Detection rule created for similar C2 traffic patterns
- ✅ Email gateway rules updated to block sender domain

---

## RECOMMENDATIONS

### Immediate (0-30 days)
1. **Disable macros by default** across all workstations (Group Policy)
2. **Mandatory phishing awareness training** for all Finance department users
3. **Deploy EDR** to all endpoints (currently 60% coverage)

### Short-Term (1-3 months)
4. **Implement email sandboxing** for attachment detonation
5. **Enable PowerShell Script Block Logging** on all Windows endpoints
6. **Create detection rule** for scheduled tasks with suspicious names

### Long-Term (3-6 months)
7. **Implement Zero Trust** network segmentation
8. **Quarterly phishing simulation** campaigns
9. **Threat hunting** for similar TTPs across environment

---

## LESSONS LEARNED

### What Went Well ✅
- EDR detected C2 communication within 15 minutes
- Incident response team responded quickly
- Containment was effective (no lateral movement)
- Clear communication between SOC and IT teams

### What Could Improve ⚠️
- Initial execution was not detected (macro + PowerShell)
- User training was outdated
- Email gateway missed malicious attachment
- No automated playbook for this incident type

### Action Items
- [ ] Update email security policies
- [ ] Schedule phishing training (due: 2025-01-15)
- [ ] Create automated playbook for malware infections
- [ ] Review EDR tuning to detect PowerShell abuse

---

## CONCLUSION

This incident demonstrates the continued effectiveness of phishing as an initial access vector. While the SOC successfully detected and contained the threat before significant damage occurred, several preventative controls failed. Implementation of the recommendations above will significantly reduce the likelihood of similar incidents in the future.

**Incident Status:** CLOSED
**Report Date:** 2024-12-29
**Report Author:** [Your Name], SOC Analyst
**Reviewed By:** [SOC Manager Name]

---

## APPENDICES

### Appendix A: Full Email Analysis
[Include email headers, body, attachment analysis]

### Appendix B: Forensic Evidence
[Include screenshots, log excerpts, memory dumps]

### Appendix C: IOC List (Machine-Readable)
[Include CSV or JSON format for ingestion into TIP]
```

---

## 🛠️ Lab Task: Write an Incident Report

### **Scenario: Ransomware Attack**

You are a SOC analyst who just resolved a ransomware incident. Using the timeline and information below, create a complete incident report.

**Incident Information:**
```
Detection Date: 2024-12-29 02:15 UTC
Alert Source: Wazuh EDR
Alert: Mass file modification detected
Affected Host: FILE-SERVER-03 (192.168.20.10, Windows Server 2019)
User Context: backup_service (service account)

Timeline:
- 01:00 UTC: VPN connection from user "admin_mike" from IP 89.187.162.45 (Romania) - unusual location
- 01:15 UTC: Multiple failed login attempts to file server
- 01:18 UTC: Successful login to file server using admin_mike credentials
- 01:20 UTC: New user account created: "TechSupport"
- 01:22 UTC: TechSupport added to Domain Admins group
- 01:30 UTC: Suspicious executable uploaded: C:\Windows\Temp\system_update.exe
- 01:35 UTC: system_update.exe executed
- 02:00 UTC: Mass file encryption begins (.locked extension)
- 02:15 UTC: **DETECTED** - Wazuh alerts on mass file modifications
- 02:20 UTC: Analyst begins investigation
- 02:25 UTC: File server shut down to prevent further encryption
- 02:30 UTC: Incident escalated to IR team
- 03:00 UTC: Backup restore initiated
- 06:00 UTC: Services restored from backup
- 06:30 UTC: Compromised credentials reset
- 07:00 UTC: System back online

IOCs:
- External IP: 89.187.162.45 (Romania)
- Malware Hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
- File Extension: .locked
- Ransom Note: C:\README_DECRYPT.txt
- Created Account: TechSupport
- Malware Path: C:\Windows\Temp\system_update.exe

Impact:
- 1,247 files encrypted
- 3.5 hours downtime
- No data loss (restored from backup)
- Affected department: Finance (shared drive)
```

### **Your Task:**

Using the template provided above, create a complete incident report that includes:

1. **Executive Summary** (non-technical, 2-3 sentences)
2. **Incident Details Table**
3. **Affected Systems Table**
4. **IOCs Section** (organized by type)
5. **Complete Timeline Table**
6. **MITRE ATT&CK Mapping** (identify at least 6 techniques)
7. **Root Cause Analysis**
8. **Business Impact Assessment**
9. **Response Actions** (Containment, Eradication, Recovery)
10. **Recommendations** (Immediate, Short-term, Long-term)
11. **Lessons Learned**

---

## 📸 Submission

Submit:
1. **Complete incident report** (2-4 pages) using the template format
2. **Executive summary** (separate, 1 paragraph for C-suite)
3. **MITRE ATT&CK mapping** with technique IDs and justification
4. **At least 5 recommendations** with priority levels

---

## 🎓 Learning Outcome

After completing this lab, you will:

- Write comprehensive incident reports following industry standards
- Document incidents for compliance and legal requirements
- Communicate technical findings to non-technical audiences
- Map incidents to MITRE ATT&CK framework for standardization
- Calculate and report MTTD and MTTR metrics
- Perform root cause analysis on security incidents
- Develop actionable recommendations from incident findings
- Create executive summaries that inform business decisions
- Maintain chain of custody for forensic evidence
- Document lessons learned for continuous improvement

---

## 💡 Key Takeaways

✅ **Documentation is evidence** - Treat reports as legal documents
✅ **Know your audience** - Technical vs. executive reports serve different purposes
✅ **Timeline is critical** - Accurate timestamps are essential
✅ **Be objective** - Stick to facts, avoid speculation
✅ **IOCs are actionable** - Provide indicators in machine-readable formats
✅ **Recommendations drive improvement** - Every incident should improve defenses
✅ **MITRE ATT&CK standardizes** - Use common language across industry
✅ **Lessons learned matter** - Failures are learning opportunities

---

## 📚 Additional Resources

- [NIST SP 800-61 Rev. 2: Incident Handling Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
- [SANS Incident Handler's Handbook](https://www.sans.org/white-papers/33901/)
- [CISA Incident Response Guide](https://www.cisa.gov/sites/default/files/publications/Federal_Government_Cybersecurity_Incident_and_Vulnerability_Response_Playbooks_508C.pdf)
- [GDPR Breach Notification Requirements](https://gdpr.eu/data-breach-notification/)
- [PCI DSS Incident Response Requirements](https://www.pcisecuritystandards.org/)
- [ISO 27035: Incident Management Standard](https://www.iso.org/standard/78974.html)
