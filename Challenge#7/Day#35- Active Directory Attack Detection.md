# Day#35- Active Directory Attack Detection

---

## 🎯 Objective

To understand common Active Directory attack techniques, learn to detect them using Windows Event Logs, and implement effective monitoring strategies to protect domain environments.

---

## 🖥️ Lab Setup

### **System Requirements**
- **Domain Controller:** Windows Server 2019/2022 with Active Directory
- **Workstation:** Windows 10/11 joined to the domain
- **SIEM:** Splunk or Wazuh (optional but recommended)
- **Logging:** Advanced Audit Policy configured

### **Tools Required**
- Windows Event Viewer
- PowerShell
- Event Log collection enabled for:
  - Security logs (Event IDs: 4768, 4769, 4776, 4624, 4625, 4720, 4732, 4672)

---

## 📘 Why Active Directory is a Prime Target

**Active Directory (AD)** is the central authentication and authorization system in most corporate Windows environments. Compromising AD gives attackers:

- **Access to all domain resources** (files, databases, applications)
- **Ability to create accounts** and escalate privileges
- **Lateral movement** across the entire domain
- **Persistence mechanisms** that survive system reboots
- **Domain-wide control** if Domain Admin is compromised

### **Attack Kill Chain in AD Environments**
```
Initial Access → Credential Theft → Lateral Movement →
Privilege Escalation → Domain Admin → Persistence → Exfiltration
```

---

## 🔐 Common Active Directory Attacks

### **1. Kerberoasting (T1558.003)**

**What it is:**
Attackers request Kerberos service tickets for accounts with Service Principal Names (SPNs), then crack them offline to obtain plaintext passwords.

**Why it works:**
- Service account passwords are often weak
- Service tickets are encrypted with the service account's password hash
- Attackers can crack these offline without triggering account lockouts

**Detection:**

| Event ID | Log Source | Description |
|----------|-----------|-------------|
| **4769** | Domain Controller Security Log | Kerberos Service Ticket Request |

**Indicators:**
- Event 4769 with:
  - Ticket Encryption Type: 0x17 (RC4-HMAC) - weak encryption
  - Service Name: NOT krbtgt or common services
  - High volume of requests from single account
  - Requests for unusual SPNs

**Splunk Query:**
```spl
index=windows EventCode=4769 Ticket_Encryption_Type=0x17
| where Service_Name!="krbtgt" AND Service_Name!="*$"
| stats count by Account_Name, Service_Name, src_ip
| where count > 10
```

---

### **2. AS-REP Roasting (T1558.004)**

**What it is:**
Attackers target accounts with "Do not require Kerberos preauthentication" enabled to obtain crackable password hashes.

**Why it works:**
- Misconfigured accounts don't require pre-authentication
- Attackers can request AS-REP responses and crack them offline

**Detection:**

| Event ID | Log Source | Description |
|----------|-----------|-------------|
| **4768** | Domain Controller Security Log | Kerberos Authentication Ticket (TGT) Request |

**Indicators:**
- Event 4768 with Pre-Authentication Type: 0 (pre-auth disabled)
- Unusual accounts requesting TGTs without pre-auth
- Requests from unfamiliar IPs

**Splunk Query:**
```spl
index=windows EventCode=4768 Pre_Authentication_Type=0
| stats count by Account_Name, src_ip
| sort -count
```

---

### **3. Pass-the-Hash (T1550.002)**

**What it is:**
Attackers use stolen NTLM password hashes to authenticate without knowing the plaintext password.

**Why it works:**
- NTLM allows authentication using just the hash
- Hashes can be extracted from memory (Mimikatz, LSASS dump)

**Detection:**

| Event ID | Log Source | Description |
|----------|-----------|-------------|
| **4624** | Target System Security Log | Successful Logon (Logon Type 3 or 9) |
| **4625** | Target System Security Log | Failed Logon |

**Indicators:**
- Logon Type 3 (Network) or 9 (NewCredentials)
- Logon Process: NtLmSsp
- Authentication from unusual source
- Same NTLM hash used across multiple systems

---

### **4. Golden Ticket (T1558.001)**

**What it is:**
Attackers with access to the krbtgt account hash can create fraudulent Kerberos Ticket Granting Tickets (TGTs) with unlimited validity.

**Why it's severe:**
- Provides domain-wide access
- Bypasses password changes
- Persists even if original compromised account is disabled

**Detection:**

| Event ID | Log Source | Description |
|----------|-----------|-------------|
| **4624** | Domain Controller | Logon with forged ticket |
| **4672** | Domain Controller | Special privileges assigned to new logon |

**Indicators:**
- Logon Type 3 with Kerberos authentication
- TGT lifetime exceeds policy (normally 10 hours, golden tickets often set to 10 years)
- Account usage after it's been disabled
- Logons from non-existent accounts

**Advanced Detection:**
Monitor for:
- Ticket requests with unusual lifetimes
- Accounts with SID history anomalies
- krbtgt password last change date (should be rotated regularly)

---

### **5. Silver Ticket (T1558.002)**

**What it is:**
Forged Kerberos service tickets (TGS) for specific services, created using a compromised service account hash.

**Scope:**
- Limited to specific services (unlike Golden Ticket which is domain-wide)
- Harder to detect because tickets are created without contacting the DC

**Detection:**
- Event 4769 (Service Ticket Request) might NOT appear for silver tickets
- Monitor for unusual service access patterns
- Anomalous access to sensitive resources

---

### **6. DCSync Attack (T1003.006)**

**What it is:**
Attackers with replication permissions use legitimate AD replication protocols to extract password hashes from the Domain Controller.

**Why it works:**
- Uses legitimate AD replication (DRSUAPI)
- Appears as normal DC-to-DC replication

**Detection:**

| Event ID | Log Source | Description |
|----------|-----------|-------------|
| **4662** | Domain Controller | Operation performed on an Active Directory object |

**Indicators:**
- Event 4662 with:
  - Object Type: DS-Replication-Get-Changes or DS-Replication-Get-Changes-All
  - Account performing replication is NOT a Domain Controller
  - Source IP is not a known DC

**Splunk Query:**
```spl
index=windows EventCode=4662
(Properties="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*" OR Properties="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*")
| where Account_Name!="*DC*" AND Account_Name!="*$"
| table _time, Account_Name, src_ip, Object_DN
```

---

### **7. Domain Enumeration (T1087.002)**

**What it is:**
Attackers enumerate domain users, groups, and computers to map the environment.

**Common Commands:**
```powershell
net user /domain
net group "Domain Admins" /domain
Get-ADUser -Filter *
Get-ADGroupMember "Domain Admins"
```

**Detection:**

| Event ID | Log Source | Description |
|----------|-----------|-------------|
| **4661** | Domain Controller | Handle to an object was requested |

**Indicators:**
- High volume of LDAP queries from a single source
- Enumeration of sensitive groups (Domain Admins, Enterprise Admins)
- Unusual accounts performing AD queries

---

## 🛠️ Lab Task 1: Detect Kerberoasting

### **Scenario**
An attacker has compromised a standard user account and is attempting to Kerberoast service accounts.

### **Simulation (On Domain Controller)**

1. **Enable Advanced Audit Policies:**
```powershell
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable
```

2. **Create a Test SPN Account:**
```powershell
New-ADUser -Name "SQLService" -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) -Enabled $true
setspn -A MSSQLSvc/sql.domain.local:1433 SQLService
```

3. **Simulate Kerberoast Attack:**
```powershell
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/sql.domain.local:1433"
```

### **Detection Task**

1. Open Event Viewer on the Domain Controller
2. Navigate to: **Security Logs**
3. Filter for **Event ID 4769**
4. Look for:
   - Service Name: MSSQLSvc/sql.domain.local
   - Ticket Encryption Type: 0x17 (RC4)
   - Account requesting the ticket

### **Questions to Answer:**
- What user requested the service ticket?
- What encryption type was used?
- Is this request legitimate or suspicious?
- How many service ticket requests did this user make in the last hour?

---

## 🛠️ Lab Task 2: Detect Pass-the-Hash

### **Scenario**
An attacker has obtained NTLM hashes and is using them to move laterally.

### **Detection Indicators**

Look for Event 4624 with these characteristics:

| Field | Suspicious Value |
|-------|------------------|
| Logon Type | 3 (Network) or 9 (NewCredentials) |
| Authentication Package | NTLM (not Kerberos) |
| Logon Process | NtLmSsp |
| Source IP | Unexpected internal IP |
| Target Account | Administrative accounts |

### **Splunk Query:**
```spl
index=windows EventCode=4624 Logon_Type=3 Authentication_Package=NTLM
| stats count, dc(dest) as unique_targets by Account_Name, src_ip
| where unique_targets > 3
| sort -unique_targets
```

**What this detects:**
- Accounts authenticating via NTLM to multiple systems
- Potential lateral movement using Pass-the-Hash

---

## 🛠️ Lab Task 3: Detect DCSync

### **Scenario**
An attacker with compromised credentials is attempting to extract all domain password hashes using DCSync.

### **Baseline First**
Identify legitimate Domain Controllers:
```powershell
Get-ADDomainController -Filter * | Select-Object Name, IPv4Address
```

### **Detection Query (Splunk):**
```spl
index=windows EventCode=4662
(Properties="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*" OR Properties="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*" OR Properties="*89e95b76-444d-4c62-991a-0facbeda640c*")
| where NOT (Account_Name="*DC*" OR Account_Name="*$")
| table _time, Account_Name, src_ip, Object_DN, Properties
| sort -_time
```

### **Investigation Steps:**
1. Check if the account performing replication is a Domain Controller
2. Verify the source IP is a known DC
3. Check if the account has legitimate replication permissions
4. Review recent privilege escalations for this account

---

## 📸 Submission

Submit the following:

1. **Kerberoasting Detection:**
   - Screenshot of Event ID 4769 showing Kerberoast attempt
   - Splunk query to detect RC4 service ticket requests
   - Analysis: True positive or false positive?

2. **Pass-the-Hash Detection:**
   - Criteria for identifying suspicious NTLM authentication
   - Splunk query to detect lateral movement via PtH
   - List of 3 indicators that would confirm PtH attack

3. **DCSync Detection:**
   - Event ID 4662 screenshot showing replication request
   - List of legitimate accounts/IPs that should perform replication
   - Splunk query to alert on unauthorized DCSync

4. **Detection Coverage Assessment:**
   - Table showing which AD attacks you can currently detect
   - Required Event IDs and log sources for each
   - Identified gaps in coverage

---

## 🎓 Learning Outcome

After completing this lab, you will:

- Understand common Active Directory attack techniques (Kerberoasting, Pass-the-Hash, DCSync, Golden/Silver Tickets)
- Map AD attacks to MITRE ATT&CK framework
- Identify critical Windows Event IDs for AD security monitoring
- Write Splunk queries to detect AD-specific attacks
- Differentiate between legitimate and malicious Kerberos activity
- Recognize indicators of credential theft and lateral movement
- Implement baseline detection for Domain Controller security
- Understand the importance of audit policy configuration
- Build detection rules for advanced persistent threats in AD environments
- Assess detection coverage gaps for enterprise authentication

---

## 💡 Key Takeaways

✅ **Active Directory is the crown jewel** - Compromising AD = compromising the entire domain
✅ **Enable advanced audit policies** - Default logging is insufficient
✅ **Monitor Kerberos traffic** - Event IDs 4768, 4769 are critical
✅ **Baseline is essential** - Know what "normal" looks like for your DCs
✅ **Service accounts are targets** - Weak SPN passwords enable Kerberoasting
✅ **NTLM is a risk** - Prefer Kerberos, block NTLM where possible
✅ **krbtgt rotation** - Change krbtgt password every 6-12 months
✅ **Least privilege** - Minimize accounts with replication rights

---

## 📚 Additional Resources

- [MITRE ATT&CK: Active Directory Techniques](https://attack.mitre.org/tactics/TA0006/)
- [Microsoft: Advanced Security Audit Policies](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings)
- [Sean Metcalf's AD Security Blog](https://adsecurity.org/)
- [Detecting Kerberoasting - SANS](https://www.sans.org/blog/detecting-kerberoasting-activity/)
- [Detecting Pass-the-Hash Attacks](https://www.microsoft.com/en-us/security/blog/2020/03/02/detecting-pass-the-hash-attacks/)
- [Mimikatz Detection Guide](https://www.varonis.com/blog/how-to-detect-mimikatz)
- [BloodHound - AD Attack Path Analysis](https://github.com/BloodHoundAD/BloodHound)
- [Purple Knight - AD Security Assessment](https://www.purple-knight.com/)

---

## 🔗 Critical Event IDs for AD Security

| Event ID | Description | Detection Use |
|----------|-------------|---------------|
| **4624** | Successful Logon | Detect Pass-the-Hash, Golden Tickets |
| **4625** | Failed Logon | Brute force, password spraying |
| **4768** | Kerberos TGT Request | AS-REP Roasting |
| **4769** | Kerberos Service Ticket Request | Kerberoasting (RC4 encryption) |
| **4776** | NTLM Authentication | Pass-the-Hash detection |
| **4662** | Operation on AD Object | DCSync detection |
| **4720** | User Account Created | Unauthorized account creation |
| **4732** | User Added to Security Group | Privilege escalation |
| **4672** | Special Privileges Assigned | Admin rights granted |
| **5136** | Directory Service Object Modified | Group Policy or ACL changes |
