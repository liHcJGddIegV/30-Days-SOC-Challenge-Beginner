# Day#38- SOC Automation with Python

---

## 🎯 Objective

To learn how to automate repetitive SOC analyst tasks using Python, including log parsing, IOC enrichment, API integration with threat intelligence platforms, and automated alert response.

---

## 🖥️ Lab Setup

### **System Requirements**
- **Operating System:** Windows or Linux
- **Python:** Version 3.8 or higher
- **Text Editor:** VS Code, PyCharm, or any code editor

### **Python Libraries to Install**
```bash
pip install requests
pip install python-whois
pip install dnspython
pip install pandas
```

### **API Keys Required (Free Tier)**
- **VirusTotal API Key:** [Sign up here](https://www.virustotal.com/gui/join-us)
- **AbuseIPDB API Key:** [Sign up here](https://www.abuseipdb.com/register)

---

## 📘 Why Automate SOC Tasks?

### **The Problem**
SOC analysts spend significant time on repetitive tasks:
- **Manually enriching IOCs** (checking VirusTotal, WHOIS, AbuseIPDB)
- **Copying data between tools** (logs → tickets → reports)
- **Parsing log files** to extract relevant information
- **Generating routine reports**
- **Performing the same investigation steps** for similar alerts

### **The Solution: Automation**
Automating repetitive tasks allows analysts to:
- ✅ **Focus on complex analysis** instead of manual data entry
- ✅ **Reduce human error** in routine processes
- ✅ **Improve MTTR** (Mean Time To Respond)
- ✅ **Scale SOC operations** without adding headcount
- ✅ **Ensure consistency** in investigation procedures

---

## 🐍 Python for SOC Analysts

### **Why Python?**
- **Easy to learn** - Beginner-friendly syntax
- **Rich libraries** - Extensive ecosystem for security tasks
- **API integration** - Simple HTTP requests with `requests` library
- **Log parsing** - Built-in string manipulation and regex
- **Automation** - Schedule scripts with cron or Task Scheduler
- **Community** - Large security community sharing tools

### **Common SOC Automation Use Cases**
1. **IOC Enrichment** - Automatically check IPs/domains/hashes against threat intel
2. **Log Parsing** - Extract relevant fields from large log files
3. **Alert Triage** - Automatically categorize and prioritize alerts
4. **Report Generation** - Create daily/weekly security reports
5. **Ticket Creation** - Auto-create tickets from SIEM alerts
6. **Phishing Analysis** - Extract URLs/attachments from emails
7. **OSINT Collection** - Gather threat intelligence from public sources

---

## 🛠️ Lab Task 1: Automate IP Reputation Check

### **Scenario**
You receive 50 suspicious IP addresses daily and need to check their reputation. Manually checking each on VirusTotal takes too long.

### **Manual Process (Before Automation):**
1. Copy IP address
2. Open VirusTotal website
3. Paste IP and search
4. Review results
5. Copy findings to spreadsheet
6. Repeat 49 more times (⏱️ ~10 minutes per IP = 8 hours!)

### **Automated Process (With Python):**
1. Run script with IP list
2. Script queries VirusTotal API for all IPs
3. Results saved to CSV (⏱️ ~2 minutes total!)

---

### **Python Script: VirusTotal IP Checker**

```python
#!/usr/bin/env python3
"""
VirusTotal IP Reputation Checker
Automates checking multiple IP addresses against VirusTotal
"""

import requests
import time
import csv

# Configuration
VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"  # Get free key from virustotal.com
VT_API_URL = "https://www.virustotal.com/api/v3/ip_addresses/"

def check_ip_reputation(ip_address):
    """
    Query VirusTotal API for IP reputation

    Args:
        ip_address (str): IP address to check

    Returns:
        dict: Reputation data or error
    """
    headers = {
        "x-apikey": VT_API_KEY
    }

    try:
        response = requests.get(f"{VT_API_URL}{ip_address}", headers=headers)

        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']

            return {
                'ip': ip_address,
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
                'reputation': data['data']['attributes'].get('reputation', 0),
                'country': data['data']['attributes'].get('country', 'Unknown')
            }
        else:
            return {'ip': ip_address, 'error': f"API Error: {response.status_code}"}

    except Exception as e:
        return {'ip': ip_address, 'error': str(e)}

def main():
    # List of suspicious IPs to check
    suspicious_ips = [
        "203.0.113.45",
        "198.51.100.78",
        "192.0.2.100",
        "185.220.101.45"
    ]

    print("[+] Starting VirusTotal IP Reputation Check...")
    print(f"[+] Checking {len(suspicious_ips)} IP addresses...\n")

    results = []

    for ip in suspicious_ips:
        print(f"[*] Checking {ip}...", end=' ')
        result = check_ip_reputation(ip)

        if 'error' not in result:
            print(f"✓ Malicious: {result['malicious']}, Suspicious: {result['suspicious']}")
            results.append(result)
        else:
            print(f"✗ {result['error']}")

        # Rate limiting (free tier: 4 requests/minute)
        time.sleep(15)

    # Save results to CSV
    if results:
        with open('ip_reputation_results.csv', 'w', newline='') as csvfile:
            fieldnames = ['ip', 'malicious', 'suspicious', 'harmless', 'reputation', 'country']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()
            for result in results:
                writer.writerow(result)

        print(f"\n[+] Results saved to ip_reputation_results.csv")

        # Print summary
        malicious_count = sum(1 for r in results if r['malicious'] > 0)
        print(f"\n[!] Summary: {malicious_count}/{len(results)} IPs flagged as malicious")

if __name__ == "__main__":
    main()
```

### **How to Use:**
1. Save script as `vt_ip_checker.py`
2. Replace `YOUR_VIRUSTOTAL_API_KEY` with your API key
3. Add your suspicious IPs to the `suspicious_ips` list
4. Run: `python3 vt_ip_checker.py`

### **Output:**
```
[+] Starting VirusTotal IP Reputation Check...
[+] Checking 4 IP addresses...

[*] Checking 203.0.113.45... ✓ Malicious: 15, Suspicious: 3
[*] Checking 198.51.100.78... ✓ Malicious: 0, Suspicious: 0
[*] Checking 192.0.2.100... ✓ Malicious: 8, Suspicious: 2
[*] Checking 185.220.101.45... ✓ Malicious: 22, Suspicious: 1

[+] Results saved to ip_reputation_results.csv

[!] Summary: 3/4 IPs flagged as malicious
```

---

## 🛠️ Lab Task 2: Automate Log Parsing

### **Scenario**
You have 10,000 lines of SSH authentication logs and need to extract all failed login attempts with source IPs and usernames.

### **Sample Log File (auth.log):**
```
Dec 29 10:15:22 ubuntu sshd[12345]: Failed password for invalid user admin from 203.0.113.45 port 54321 ssh2
Dec 29 10:15:25 ubuntu sshd[12346]: Failed password for root from 203.0.113.45 port 54322 ssh2
Dec 29 10:15:28 ubuntu sshd[12347]: Accepted password for jdoe from 192.168.1.100 port 54323 ssh2
Dec 29 10:15:30 ubuntu sshd[12348]: Failed password for invalid user test from 198.51.100.45 port 54324 ssh2
```

### **Python Script: SSH Log Parser**

```python
#!/usr/bin/env python3
"""
SSH Failed Login Parser
Extracts failed SSH authentication attempts from auth.log
"""

import re
from collections import Counter

def parse_ssh_logs(log_file):
    """
    Parse SSH auth logs and extract failed login attempts

    Args:
        log_file (str): Path to auth.log file

    Returns:
        list: List of failed login attempts with details
    """
    failed_logins = []

    # Regex pattern to match failed SSH login attempts
    pattern = r'Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)'

    with open(log_file, 'r') as f:
        for line in f:
            match = re.search(pattern, line)
            if match:
                username = match.group(1)
                src_ip = match.group(2)
                port = match.group(3)

                failed_logins.append({
                    'username': username,
                    'source_ip': src_ip,
                    'port': port,
                    'log_line': line.strip()
                })

    return failed_logins

def analyze_failed_logins(failed_logins):
    """
    Analyze failed login patterns

    Args:
        failed_logins (list): List of failed login dictionaries
    """
    print(f"\n[+] Total failed login attempts: {len(failed_logins)}")

    # Count by source IP
    ip_counter = Counter([login['source_ip'] for login in failed_logins])
    print(f"\n[!] Top 5 attacking IPs:")
    for ip, count in ip_counter.most_common(5):
        print(f"    {ip}: {count} attempts")

    # Count by username
    user_counter = Counter([login['username'] for login in failed_logins])
    print(f"\n[!] Top 5 targeted usernames:")
    for user, count in user_counter.most_common(5):
        print(f"    {user}: {count} attempts")

    # Identify brute force attacks (> 20 attempts from single IP)
    print(f"\n[!] Potential brute force attacks (>20 attempts):")
    for ip, count in ip_counter.items():
        if count > 20:
            print(f"    {ip}: {count} attempts - INVESTIGATE")

def main():
    log_file = "auth.log"  # Path to your auth.log file

    print("[+] Parsing SSH authentication logs...")
    failed_logins = parse_ssh_logs(log_file)

    if failed_logins:
        analyze_failed_logins(failed_logins)

        # Save to CSV for further analysis
        import csv
        with open('failed_ssh_logins.csv', 'w', newline='') as csvfile:
            fieldnames = ['username', 'source_ip', 'port']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for login in failed_logins:
                writer.writerow({
                    'username': login['username'],
                    'source_ip': login['source_ip'],
                    'port': login['port']
                })

        print(f"\n[+] Results saved to failed_ssh_logins.csv")
    else:
        print("[-] No failed login attempts found")

if __name__ == "__main__":
    main()
```

---

## 🛠️ Lab Task 3: Automate IOC Extraction from Threat Report

### **Scenario**
You receive a threat intelligence report with embedded IPs, domains, and file hashes. Extract all IOCs automatically.

### **Python Script: IOC Extractor**

```python
#!/usr/bin/env python3
"""
IOC Extractor
Automatically extract IPs, domains, URLs, and hashes from threat reports
"""

import re

def extract_iocs(text):
    """
    Extract various IOC types from text

    Args:
        text (str): Threat intelligence report text

    Returns:
        dict: Dictionary of extracted IOCs by type
    """
    iocs = {
        'ips': [],
        'domains': [],
        'urls': [],
        'sha256_hashes': [],
        'md5_hashes': []
    }

    # IP addresses (IPv4)
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    iocs['ips'] = list(set(re.findall(ip_pattern, text)))

    # Domains
    domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
    iocs['domains'] = list(set(re.findall(domain_pattern, text)))

    # URLs
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    iocs['urls'] = list(set(re.findall(url_pattern, text)))

    # SHA256 hashes
    sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
    iocs['sha256_hashes'] = list(set(re.findall(sha256_pattern, text)))

    # MD5 hashes
    md5_pattern = r'\b[a-fA-F0-9]{32}\b'
    iocs['md5_hashes'] = list(set(re.findall(md5_pattern, text)))

    return iocs

def main():
    # Sample threat report text
    threat_report = """
    Threat Actor: APT28

    The following indicators have been observed:

    C2 Servers:
    - 203.0.113.45
    - malicious-domain.com
    - http://evil-payload.ru/download.exe

    File Hashes:
    SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    MD5: d41d8cd98f00b204e9800998ecf8427e

    Additional infrastructure:
    - 198.51.100.78
    - data-exfil.ru
    """

    print("[+] Extracting IOCs from threat report...\n")
    iocs = extract_iocs(threat_report)

    # Display results
    for ioc_type, values in iocs.items():
        if values:
            print(f"[+] {ioc_type.upper()}:")
            for value in values:
                print(f"    - {value}")
            print()

    # Save to file for import into SIEM/TIP
    with open('extracted_iocs.txt', 'w') as f:
        f.write("=== EXTRACTED IOCS ===\n\n")
        for ioc_type, values in iocs.items():
            if values:
                f.write(f"{ioc_type.upper()}:\n")
                for value in values:
                    f.write(f"{value}\n")
                f.write("\n")

    print("[+] IOCs saved to extracted_iocs.txt")

if __name__ == "__main__":
    main()
```

---

## 📸 Submission

Submit the following:

1. **VirusTotal IP Checker:**
   - Modified script with your API key (redacted in submission)
   - Screenshot of script output for at least 5 IPs
   - Generated CSV file with results

2. **SSH Log Parser:**
   - Python script (complete and functional)
   - Sample output showing failed login analysis
   - Identification of at least one brute force attack pattern

3. **IOC Extractor:**
   - Script execution screenshot
   - Sample threat report used (text or PDF)
   - Extracted IOCs in organized format

4. **Bonus - Custom Automation:**
   - Create your own automation script for any SOC task:
     - WHOIS lookup automation
     - Hash checker (VirusTotal)
     - Domain reputation checker (AbuseIPDB)
     - Email header parser
   - Document what it does and how to use it

---

## 🎓 Learning Outcome

After completing this lab, you will:

- Understand the value of automation in SOC operations
- Write Python scripts to automate repetitive analyst tasks
- Integrate with threat intelligence APIs (VirusTotal, AbuseIPDB)
- Parse and analyze log files programmatically
- Extract IOCs from threat intelligence reports using regex
- Generate structured output (CSV, JSON) for further analysis
- Improve MTTR through automated enrichment
- Build a foundation for SOAR (Security Orchestration, Automation, Response)
- Handle API rate limiting and error handling
- Create reusable automation tools for daily SOC work

---

## 💡 Key Takeaways

✅ **Automate repetitive tasks** - Free analysts for complex analysis
✅ **APIs are powerful** - Integrate threat intel platforms for enrichment
✅ **Start small** - Automate one task at a time
✅ **Error handling matters** - APIs fail, handle gracefully
✅ **Document your scripts** - Others (and future you) will use them
✅ **Rate limiting is real** - Respect API limits to avoid bans
✅ **Version control** - Use Git to track script changes
✅ **Security** - Never hardcode API keys, use environment variables

---

## 📚 Additional Resources

- [Python for Cybersecurity](https://www.python.org/about/apps/)
- [Requests Library Documentation](https://docs.python-requests.org/)
- [VirusTotal API Documentation](https://developers.virustotal.com/reference/overview)
- [AbuseIPDB API Documentation](https://docs.abuseipdb.com/)
- [SOAR Platforms Overview](https://www.gartner.com/en/information-technology/glossary/security-orchestration-automation-response-soar)
- [Python Regex Tutorial](https://docs.python.org/3/library/re.html)
- [TheHive Project - Automation](https://github.com/TheHive-Project/Cortex-Analyzers)
- [MISP - Threat Intelligence Platform](https://www.misp-project.org/)

---

## 🚀 Advanced Automation Ideas

Once you master the basics, try automating:
1. **Automated ticket creation** from SIEM alerts (Jira/ServiceNow API)
2. **Phishing email analysis** (extract attachments, URLs, headers)
3. **Automated blocklist updates** (add malicious IPs to firewall)
4. **Daily threat intel digest** (collect IOCs from multiple sources)
5. **Automated incident timeline** generation from logs
6. **Alert enrichment pipeline** (SIEM → Python → Enriched ticket)
7. **Automated reporting** (weekly SOC metrics dashboard)
