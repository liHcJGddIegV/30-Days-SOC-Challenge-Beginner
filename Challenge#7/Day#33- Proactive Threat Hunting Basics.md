# Day#33- Proactive Threat Hunting Basics

---

## 🎯 Objective

To learn the fundamentals of proactive threat hunting, develop hypothesis-driven investigation skills, and use SIEM tools to hunt for threats that may have evaded automated detection systems.

---

## 🖥️ Lab Setup

### **System Requirements**
- **Operating System:** Windows or Linux
- **SIEM Platform:** Splunk (from Day 16-20) OR Wazuh (from Day 26-30)
- **Sample Logs:** SSH logs, HTTP logs, Windows Event logs

### **Prerequisites**
- Completed Challenge #4 (Splunk) or Challenge #6 (Wazuh)
- Understanding of MITRE ATT&CK (Day 32)
- Familiarity with log analysis

---

## 📘 What is Threat Hunting?

**Threat Hunting** is the proactive and iterative process of searching through networks, endpoints, and datasets to detect and isolate advanced threats that evade existing automated detection systems.

### **Reactive Detection vs. Proactive Hunting**

| Reactive Detection | Proactive Hunting |
|--------------------|-------------------|
| Wait for alerts to trigger | Actively search for threats |
| Signature-based (known threats) | Behavior-based (unknown threats) |
| Automated response | Human-driven investigation |
| "Alert fatigue" prone | Strategic and hypothesis-driven |
| Detects known IOCs | Discovers new TTPs |

---

## 🎯 The Threat Hunting Process

### **Step 1: Hypothesis Creation**
Develop a specific, testable hypothesis based on:
- Threat intelligence (what are adversaries doing?)
- MITRE ATT&CK techniques (what techniques are we vulnerable to?)
- Known vulnerabilities in your environment
- Anomalies or patterns observed

**Example Hypotheses:**
- *"An attacker may be using DNS tunneling to exfiltrate data"*
- *"Compromised accounts may be performing lateral movement via RDP during non-business hours"*
- *"Malware may be persisting via scheduled tasks with unusual names"*
- *"An insider may be accessing sensitive files they don't normally use"*

### **Step 2: Data Collection**
Identify and collect relevant data sources:
- SIEM logs (Splunk, Wazuh)
- EDR telemetry
- Network traffic (NetFlow, Zeek)
- Endpoint logs (Process creation, file access)

### **Step 3: Investigation**
Use queries, filters, and analysis to test the hypothesis:
- Search for indicators of the suspected technique
- Look for anomalies and outliers
- Correlate multiple data sources

### **Step 4: Pattern Analysis**
Identify deviations from normal behavior:
- Baseline vs. current activity
- Statistical anomalies
- Time-based patterns (after hours, weekends)
- Geographical anomalies

### **Step 5: Response**
- **If threat found:** Escalate to incident response
- **If no threat found:** Document findings, refine detection rules
- **Either way:** Improve detection capabilities

---

## 🔍 Threat Hunting Maturity Model

| Level | Description | Characteristics |
|-------|-------------|-----------------|
| **HMM0 - Initial** | No hunting capability | Rely entirely on automated alerts |
| **HMM1 - Minimal** | Ad-hoc hunts based on IOCs | Hunt using known indicators after an incident |
| **HMM2 - Procedural** | Follow hunt procedures and playbooks | Scheduled hunts using documented procedures |
| **HMM3 - Innovative** | Create new hypotheses based on TTPs | Hypothesis-driven, use threat intelligence |
| **HMM4 - Leading** | Automated hunting, machine learning | Advanced analytics, automation, continuous improvement |

**Goal:** Move from HMM0 → HMM2+ through practice

---

## 🛠️ Lab Task 1: Hunt for DNS Tunneling

### **Hypothesis**
*"An attacker may be using DNS tunneling to exfiltrate data from our network"*

### **Background: What is DNS Tunneling?**
Attackers encode data in DNS queries to bypass firewalls and exfiltrate information. Indicators:
- Unusually long DNS queries
- High volume of DNS requests to a single domain
- Suspicious domain names (random characters)
- DNS queries with unusual patterns

### **Hunt Plan**

**Step 1: Identify Baseline**
What is "normal" DNS activity in your environment?
- Typical query length: 20-40 characters
- Common domains: google.com, microsoft.com, internal domains
- Normal query volume: 10-50 per minute per host

**Step 2: Craft Splunk Query to Detect Anomalies**

```spl
index=dns
| eval query_length=len(query)
| where query_length > 60
| stats count by src_ip, query, query_length
| where count > 10
| sort -count
```

**What this finds:**
- DNS queries longer than 60 characters (abnormal)
- Repeated suspicious queries
- Source IPs making unusual requests

### **Step 3: Analyze Results**

Look for:
- Random-looking subdomains (e.g., `a8f3d9e2b1c4.malicious.com`)
- Base64-encoded patterns in queries
- Consistent pattern from a single host
- Domains not seen before in the environment

### **Step 4: Enrich with Threat Intelligence**

Check suspicious domains:
- VirusTotal
- Cisco Umbrella
- WHOIS registration data

### **Step 5: Document Findings**

```
THREAT HUNT REPORT
==================
Hypothesis: DNS tunneling for data exfiltration
Date: 2024-12-29
Hunter: [Your Name]

DATA SOURCES:
- DNS logs (last 7 days)
- Network traffic logs

QUERIES USED:
[List Splunk queries]

FINDINGS:
- Total DNS queries analyzed: 1,245,678
- Suspicious queries identified: 23
- Source IPs involved: 192.168.10.75

INDICATORS:
- Domain: data.exfil-domain.com
- Pattern: [Base64 encoded data in subdomain]
- Volume: 450 queries in 2 hours

CONCLUSION:
[Threat Confirmed / No Threat / Needs Further Investigation]

RECOMMENDED ACTIONS:
- Block domain at firewall
- Isolate host 192.168.10.75
- Escalate to IR team
```

---

## 🛠️ Lab Task 2: Hunt for Lateral Movement

### **Hypothesis**
*"Compromised accounts may be performing lateral movement via RDP during non-business hours"*

### **Background**
Attackers often move laterally after initial compromise. Red flags:
- RDP connections outside business hours
- Accounts connecting to multiple systems
- RDP from unusual source IPs
- Service accounts performing interactive logons

### **Hunt Plan**

**Step 1: Define "Non-Business Hours"**
- Business hours: Monday-Friday, 8 AM - 6 PM
- Non-business: Nights, weekends, holidays

**Step 2: Craft Splunk Query**

```spl
index=windows EventCode=4624 Logon_Type=10
| eval hour=strftime(_time, "%H")
| eval day=strftime(_time, "%A")
| where (hour < 8 OR hour > 18) OR day="Saturday" OR day="Sunday"
| stats count, values(src_ip) as source_ips, dc(dest) as unique_destinations by user
| where unique_destinations > 3
| sort -count
```

**What this detects:**
- Event 4624 (Successful Logon), Logon Type 10 (RDP)
- Outside business hours
- Users connecting to multiple destinations
- Potential lateral movement pattern

### **Step 3: Analyze Patterns**

Questions to answer:
- Is this user authorized for after-hours access?
- Why are they connecting to multiple systems?
- Are these systems related to their job function?
- Is the source IP expected (VPN, known workstation)?

### **Step 4: Correlate with Other Data**

Cross-reference with:
- Failed login attempts (Event 4625)
- Account changes (Event 4720, 4732)
- Process creation on target systems
- File access logs

---

## 🛠️ Lab Task 3: Hunt for Persistence via Scheduled Tasks

### **Hypothesis**
*"Malware may be creating scheduled tasks with unusual names or suspicious commands for persistence"*

### **Background**
Scheduled tasks are a common persistence mechanism. Suspicious indicators:
- Tasks with random names
- Tasks pointing to temp directories
- Tasks running PowerShell/cmd with encoded commands
- Tasks created by non-admin users

### **Hunt Plan**

**Splunk Query for Windows Event ID 4698 (Scheduled Task Created):**

```spl
index=windows EventCode=4698
| rex field=Task_Name "(?<task_name>[^\\\]+$)"
| where match(task_name, "^[a-f0-9]{8,}$") OR match(Task_Content, "(?i)(temp|appdata|powershell -enc)")
| table _time, host, user, task_name, Task_Content
| sort -_time
```

**What this detects:**
- Tasks with hexadecimal names (potential malware)
- Tasks executing from temp directories
- Tasks using encoded PowerShell

### **Hunt Checklist**

Investigate each suspicious task:
- [ ] What is the task name?
- [ ] Who created it?
- [ ] What does it execute?
- [ ] When does it run?
- [ ] Is the binary signed?
- [ ] Is it in VirusTotal?
- [ ] Does it exist on other systems?

---

## 🧠 Advanced Hunting Techniques

### **1. Stack Counting**
Find rare occurrences (outliers):

```spl
index=windows EventCode=4688
| stats count by Process_Name
| sort count
| head 20
```

**Look for:** Processes with very few occurrences (may be malicious)

### **2. Time-Based Analysis**
Detect after-hours activity:

```spl
index=* earliest=-7d
| timechart span=1h count by user
```

**Look for:** Spikes at unusual times

### **3. Geolocation Anomalies**
VPN connections from unexpected countries:

```spl
index=vpn
| iplocation src_ip
| where Country!="United States"
| stats count by user, Country, City
```

### **4. Process Ancestry Analysis**
Unusual parent-child relationships:

```spl
index=windows EventCode=4688
| where (Parent_Process="winword.exe" AND Process_Name="powershell.exe")
```

**Why suspicious:** Microsoft Word should not spawn PowerShell

---

## 📸 Submission

Submit the following:

1. **DNS Tunneling Hunt:**
   - Hypothesis statement
   - Splunk query used
   - Results summary (# of events, suspicious domains found)
   - Threat assessment (True Positive / False Positive)

2. **Lateral Movement Hunt:**
   - Query used to detect after-hours RDP
   - At least 3 findings (can be from sample data)
   - Analysis of whether each is legitimate or suspicious

3. **Scheduled Task Hunt:**
   - Query for suspicious scheduled tasks
   - Document at least 2 suspicious tasks
   - Analysis: What makes them suspicious?

4. **Hunt Report:**
   - Choose ONE hypothesis above
   - Write a complete hunt report using the template provided
   - Include findings, IOCs, and recommended actions

---

## 🎓 Learning Outcome

After completing this lab, you will:

- Understand the difference between reactive detection and proactive hunting
- Develop testable hypotheses based on threat intelligence and TTPs
- Use Splunk to search for indicators of advanced threats
- Identify behavioral anomalies and outliers in log data
- Establish baselines to detect deviations from normal activity
- Correlate multiple data sources for comprehensive investigations
- Document hunt findings in professional reports
- Apply MITRE ATT&CK techniques to hunting scenarios
- Build custom detection rules from hunting discoveries
- Understand the threat hunting maturity model and progression

---

## 💡 Key Takeaways

✅ **Hunting is proactive, not reactive** - Don't wait for alerts
✅ **Hypotheses drive hunts** - Random searching is inefficient
✅ **Baselines are critical** - You can't detect anomalies without knowing "normal"
✅ **Document everything** - Failed hunts are still valuable for tuning
✅ **Hunting improves detection** - Every hunt should result in better rules
✅ **Use threat intelligence** - Know what adversaries are doing in the wild
✅ **Think like an attacker** - Use MITRE ATT&CK to guide your hunts

---

## 📚 Additional Resources

- [MITRE ATT&CK for Threat Hunting](https://attack.mitre.org/)
- [Sqrrl Threat Hunting Reference Guide](https://www.threathunting.net/files/framework-for-threat-hunting-whitepaper.pdf)
- [Splunk Boss of the SOC (BOTS) Dataset](https://github.com/splunk/botsv3)
- [SANS Threat Hunting Summit Resources](https://www.sans.org/cyber-security-summit/archives/)
- [Active Countermeasures - Threat Hunting](https://www.activecountermeasures.com/category/threat-hunting/)
- [Cyber Threat Hunting Book by Anomali](https://www.anomali.com/resources/whitepapers/cyber-threat-hunting)
- [ThreatHunter-Playbook on GitHub](https://github.com/OTRF/ThreatHunter-Playbook)

---

## 🔗 Hunting Hypothesis Ideas

Use these as starting points for future hunts:

1. **Credential Access:** Hunt for Kerberoasting (Event 4769 with RC4 encryption)
2. **Exfiltration:** Hunt for large outbound file transfers to cloud storage
3. **C2 Communication:** Hunt for beaconing patterns (regular interval connections)
4. **Privilege Escalation:** Hunt for SeDebugPrivilege usage outside expected processes
5. **Defense Evasion:** Hunt for security tool tampering (AV/EDR disabled)
6. **Discovery:** Hunt for mass enumeration commands (net user, net group)
7. **Persistence:** Hunt for new services created with suspicious paths
8. **Initial Access:** Hunt for suspicious email attachments executed
