# Day#39- Advanced Email Header Analysis

---

## 🎯 Objective

To master advanced email header analysis techniques, understand email authentication mechanisms (SPF, DKIM, DMARC), trace email origins, and identify sophisticated phishing and Business Email Compromise (BEC) attacks.

---

## 🖥️ Lab Setup

### **System Requirements**
- **Web Browser:** Chrome, Firefox, or Edge
- **Email Client:** Access to email headers (Outlook, Gmail, Thunderbird)

### **Tools Required**
- [MXToolbox Email Header Analyzer](https://mxtoolbox.com/EmailHeaders.aspx)
- [Google Admin Toolbox Messageheader](https://toolbox.googleapps.com/apps/messageheader/)
- [DMARC Analyzer](https://dmarcian.com/dmarc-inspector/)
- Text editor for manual analysis

### **Sample Files**
- Sample phishing email (from Day 21-22 or create test emails)
- Email in .eml or .msg format with full headers

---

## 📘 Understanding Email Headers

**Email headers** contain routing information showing the path an email took from sender to recipient. They are critical for:
- **Identifying the true sender** (spoofing detection)
- **Tracing email origin** (tracking threat actors)
- **Validating authentication** (SPF, DKIM, DMARC)
- **Detecting email tampering**
- **Investigating phishing and BEC**

### **Header vs. Envelope**

| Component | Description | Analogy |
|-----------|-------------|---------|
| **Envelope** | Actual routing information (SMTP) | Physical envelope's postmark |
| **Header** | Visible sender/recipient in email | Letter inside the envelope |

**Key Point:** The "From" header can be easily spoofed, but envelope information (Received headers) cannot.

---

## 📧 Critical Email Header Fields

### **From & Reply-To**
```
From: CEO <ceo@company.com>
Reply-To: attacker@evil.com
```
**Red Flag:** Reply-To differs from From address (common in phishing)

---

### **Return-Path**
```
Return-Path: <bounce@malicious-server.com>
```
**Purpose:** Where bounce messages are sent
**Analysis:** Should match the sending domain; mismatch indicates spoofing

---

### **Received Headers**
```
Received: from mail-server.company.com (unknown [203.0.113.45])
    by recipient-server.com with SMTP id 12345
    for <victim@company.com>; Fri, 29 Dec 2024 10:15:30 -0500
```
**Key Information:**
- **Originating server** (first "Received" from bottom)
- **Source IP address** (in brackets)
- **Timestamp** (when email was received at each hop)
- **Protocol** (SMTP, ESMTP)

**How to Read:** Read **bottom-to-top** (oldest to newest)

---

### **Authentication Results**
```
Authentication-Results: mx.google.com;
    spf=pass (google.com: domain of sender@legitimate.com designates 203.0.113.45 as permitted sender) smtp.mailfrom=sender@legitimate.com;
    dkim=pass header.i=@legitimate.com header.s=selector1 header.b=ABC123;
    dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=legitimate.com
```

**Checks:**
- **SPF:** Did email come from authorized server?
- **DKIM:** Was email cryptographically signed and unmodified?
- **DMARC:** Does it pass both SPF and DKIM alignment?

---

## 🔐 Email Authentication Mechanisms

### **1. SPF (Sender Policy Framework)**

**Purpose:** Specifies which mail servers are authorized to send email on behalf of a domain.

**How it works:**
1. Domain owner publishes SPF record in DNS
2. Receiving server checks if sender's IP is in the SPF record
3. Result: Pass, Fail, SoftFail, Neutral

**Example SPF Record:**
```
v=spf1 ip4:203.0.113.0/24 include:_spf.google.com -all
```

**Translation:**
- `v=spf1` - SPF version 1
- `ip4:203.0.113.0/24` - Authorized IP range
- `include:_spf.google.com` - Include Google's mail servers
- `-all` - Reject all other sources (strict)

**Check SPF:**
```bash
nslookup -type=txt company.com
```

**Results:**
- ✅ **PASS** - Email from authorized server
- ❌ **FAIL** - Email from unauthorized server (likely spoofed)
- ⚠️ **SOFTFAIL** - Suspicious but not rejected (~all)
- ❔ **NEUTRAL** - No SPF record or ?all

---

### **2. DKIM (DomainKeys Identified Mail)**

**Purpose:** Cryptographically signs emails to prove they haven't been tampered with.

**How it works:**
1. Sending server signs email with private key
2. Public key published in DNS
3. Receiving server verifies signature with public key

**DKIM Header:**
```
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
    d=legitimate.com; s=selector1;
    h=from:to:subject:date;
    bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;
    b=ABC123XYZ...
```

**Key Fields:**
- `d=` - Signing domain
- `s=` - Selector (identifies which key to use)
- `bh=` - Body hash
- `b=` - Signature

**Check DKIM:**
```bash
nslookup -type=txt selector1._domainkey.company.com
```

**Results:**
- ✅ **PASS** - Signature valid, email unmodified
- ❌ **FAIL** - Signature invalid, email tampered or forged
- ❔ **NONE** - No DKIM signature

---

### **3. DMARC (Domain-based Message Authentication, Reporting, and Conformance)**

**Purpose:** Instructs receiving servers what to do when SPF or DKIM fails.

**DMARC Policies:**
- `p=none` - Monitor only, don't reject
- `p=quarantine` - Send to spam/junk
- `p=reject` - Reject the email entirely

**Example DMARC Record:**
```
v=DMARC1; p=reject; rua=mailto:dmarc@company.com; pct=100; adkim=s; aspf=s
```

**Translation:**
- `p=reject` - Policy: reject failures
- `rua=` - Send aggregate reports to this address
- `pct=100` - Apply policy to 100% of emails
- `adkim=s` - Strict DKIM alignment
- `aspf=s` - Strict SPF alignment

**Check DMARC:**
```bash
nslookup -type=txt _dmarc.company.com
```

---

## 🛠️ Lab Task 1: Analyze Spoofed Email Headers

### **Scenario: CEO Impersonation (BEC Attack)**

You receive an email that appears to be from your CEO requesting an urgent wire transfer.

### **Email Headers:**
```
From: John Smith CEO <john.smith@company.com>
Reply-To: j.smith@temp-email-service.com
Return-Path: <bounce@phishing-server.ru>
To: finance@company.com
Subject: URGENT: Wire Transfer Needed

Received: from phishing-server.ru (unknown [185.220.101.45])
    by mail.company.com (Postfix) with SMTP id 12345
    for <finance@company.com>; Fri, 29 Dec 2024 09:30:00 -0500

Received: from [192.168.1.50] (unknown [203.0.113.88])
    by phishing-server.ru (Postfix) with ESMTP id 67890
    Fri, 29 Dec 2024 14:29:55 +0000

Authentication-Results: mail.company.com;
    spf=fail (company.com: domain of bounce@phishing-server.ru does not designate 185.220.101.45 as permitted sender) smtp.mailfrom=bounce@phishing-server.ru;
    dkim=none (no signature);
    dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=company.com

X-Originating-IP: 185.220.101.45
Message-ID: <abc123@phishing-server.ru>
```

### **Analysis Questions:**

1. **Identify Spoofing Indicators:**
   - What is the visible "From" address?
   - What is the "Return-Path"?
   - Do they match?

2. **Trace the True Origin:**
   - What is the originating server? (Read Received headers bottom-to-top)
   - What is the source IP address?
   - Is this IP from your company's mail infrastructure?

3. **Check Authentication:**
   - SPF result?
   - DKIM result?
   - DMARC result?

4. **Determine Legitimacy:**
   - Is this email legitimate or spoofed?
   - What specific indicators prove it's malicious?

5. **Response Plan:**
   - Should this email be blocked?
   - What actions should be taken? (block sender, warn users, update filters)

---

## 🛠️ Lab Task 2: Trace Email Through Multiple Hops

### **Understanding Email Routing**

Emails pass through multiple servers before reaching you. Each server adds a "Received" header.

### **Sample Multi-Hop Email:**
```
Received: by recipient-server.com (Postfix)
    for <user@company.com>; Sat, 30 Dec 2024 10:00:00 -0500 (EST)

Received: from gateway.company.com (gateway [10.0.1.50])
    by recipient-server.com (Postfix) with ESMTP id ABC123
    Sat, 30 Dec 2024 09:59:58 -0500

Received: from mail.google.com (mail.google.com [142.250.185.27])
    by gateway.company.com (Postfix) with ESMTP id XYZ789
    Sat, 30 Dec 2024 09:59:55 -0500

Received: by mail.google.com with SMTP id abc123
    Sat, 30 Dec 2024 06:59:50 -0800 (PST)
```

### **Task: Create an Email Timeline**

Read the headers **bottom-to-top** and create a timeline:

| Timestamp (UTC) | Server | IP Address | Action |
|-----------------|--------|------------|--------|
| 2024-12-30 14:59:50 | mail.google.com | 142.250.185.27 | Email sent from Gmail |
| 2024-12-30 14:59:55 | gateway.company.com | 10.0.1.50 | Received at company gateway |
| 2024-12-30 14:59:58 | recipient-server.com | (internal) | Delivered to mailbox server |
| 2024-12-30 15:00:00 | mailbox | - | Delivered to user@company.com |

**Analysis:**
- **Total transit time:** 10 seconds (very fast, likely legitimate)
- **Number of hops:** 4 servers
- **Suspicious delays?** No (all timestamps sequential and reasonable)

---

## 🛠️ Lab Task 3: Detect Email Spoofing Techniques

### **Common Spoofing Techniques:**

#### **1. Display Name Spoofing**
```
From: "John Smith CEO" <attacker@evil.com>
```
**Trick:** Uses legitimate display name but different email address
**Detection:** Check actual email address, not just display name

#### **2. Lookalike Domain**
```
From: ceo@comp4ny.com  (note the '4' instead of 'a')
From: ceo@company.co  (missing the 'm')
```
**Detection:** Carefully compare domain spelling

#### **3. Homograph/IDN Attack**
```
From: ceo@compаny.com  (Cyrillic 'а' instead of Latin 'a')
```
**Detection:** Use Punycode conversion to reveal xn-- encoded domains

#### **4. Reply-To Hijacking**
```
From: ceo@company.com
Reply-To: attacker@evil.com
```
**Detection:** Check if Reply-To differs from From

#### **5. Email Address Confusion**
```
From: ceo@company.com.evil.com
```
**Detection:** Check the actual domain (evil.com, not company.com)

### **Practice: Identify the Spoofing Technique**

For each example, identify which technique is used:

**Example A:**
```
From: "IT Support" <it.support@company-helpdesk.net>
```

**Example B:**
```
From: admin@company.com
Reply-To: payments@offshore-bank.ru
```

**Example C:**
```
From: "Finance Director" <attacker123@gmail.com>
```

---

## 📸 Submission

Submit the following:

1. **Spoofed Email Analysis (Lab Task 1):**
   - Complete header analysis
   - Identification of all spoofing indicators
   - SPF/DKIM/DMARC results interpretation
   - WHOIS lookup of originating IP
   - Determination: Legitimate or Malicious?

2. **Email Routing Timeline (Lab Task 2):**
   - Complete timeline table from Received headers
   - Calculated total transit time
   - Identification of any suspicious delays or routing anomalies

3. **Spoofing Technique Identification (Lab Task 3):**
   - Correctly identify techniques in Examples A, B, C
   - Provide at least 2 real-world examples of each technique
   - Recommendations for detecting each technique

4. **Real Email Analysis:**
   - Obtain a real phishing email (from spam folder or safe source)
   - Extract and analyze full headers
   - Complete analysis report including:
     - SPF/DKIM/DMARC validation
     - Source IP geolocation
     - Email routing path
     - Spoofing techniques used
     - IOCs (domains, IPs, reply-to addresses)

5. **Detection Rule Recommendation:**
   - Based on your analysis, write detection logic for a SIEM rule
   - Example: "Alert if SPF=fail AND Reply-To domain != From domain"

---

## 🎓 Learning Outcome

After completing this lab, you will:

- Master reading and interpreting complex email headers
- Understand SPF, DKIM, and DMARC authentication mechanisms
- Trace email routing paths through multiple servers
- Identify various email spoofing and impersonation techniques
- Detect Business Email Compromise (BEC) attempts
- Validate email authentication results
- Perform WHOIS and IP geolocation for email origins
- Differentiate between legitimate and forged emails
- Extract IOCs from email headers for threat intelligence
- Create detection rules based on email header analysis
- Understand the limitations of email security mechanisms

---

## 💡 Key Takeaways

✅ **Read Received headers bottom-to-top** - First received = true origin
✅ **From address can be spoofed** - Always check authentication results
✅ **SPF + DKIM + DMARC = Defense in Depth** - All three should pass
✅ **Reply-To mismatches are red flags** - Common BEC indicator
✅ **DMARC p=reject is strongest** - Rejects unauthenticated emails
✅ **Display names can mislead** - Always verify actual email address
✅ **Homograph attacks are subtle** - Use Punycode to reveal tricks
✅ **Transit time matters** - Unusual delays can indicate relaying

---

## 📚 Additional Resources

- [RFC 5321 - SMTP Protocol](https://tools.ietf.org/html/rfc5321)
- [RFC 7208 - SPF Specification](https://tools.ietf.org/html/rfc7208)
- [RFC 6376 - DKIM Specification](https://tools.ietf.org/html/rfc6376)
- [RFC 7489 - DMARC Specification](https://tools.ietf.org/html/rfc7489)
- [MXToolbox Email Header Analyzer](https://mxtoolbox.com/EmailHeaders.aspx)
- [Google Admin Toolbox](https://toolbox.googleapps.com/apps/messageheader/)
- [DMARC.org - Implementation Guide](https://dmarc.org/)
- [Anti-Phishing Working Group (APWG)](https://apwg.org/)
- [Microsoft: Email Authentication](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/email-authentication-about)

---

## 🔍 Email Header Analysis Checklist

### Initial Triage
- [ ] Extract full email headers
- [ ] Identify visible From and To addresses
- [ ] Check for Reply-To field
- [ ] Note subject line for keywords (URGENT, invoice, password reset)

### Authentication Validation
- [ ] Check SPF result (Pass/Fail/SoftFail/Neutral/None)
- [ ] Check DKIM result (Pass/Fail/None)
- [ ] Check DMARC result (Pass/Fail/None)
- [ ] Verify alignment (does From domain match SPF/DKIM domains?)

### Routing Analysis
- [ ] Read Received headers bottom-to-top
- [ ] Identify originating server/IP
- [ ] Create timeline of email hops
- [ ] Check for unusual delays or routing

### Source Investigation
- [ ] WHOIS lookup on originating IP
- [ ] Geolocation of source IP
- [ ] Check IP reputation (AbuseIPDB, VirusTotal)
- [ ] Verify if source matches claimed sender's infrastructure

### Spoofing Detection
- [ ] Compare From vs. Return-Path
- [ ] Check for display name spoofing
- [ ] Look for lookalike domains (typosquatting)
- [ ] Inspect for homograph/IDN attacks
- [ ] Verify Reply-To matches From

### Final Determination
- [ ] Legitimate or Malicious?
- [ ] Confidence level (High/Medium/Low)
- [ ] IOCs extracted (IPs, domains, email addresses)
- [ ] Recommended action (block, quarantine, allow)
