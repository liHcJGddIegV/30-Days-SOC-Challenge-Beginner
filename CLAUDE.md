# CLAUDE.md - AI Assistant Guide

## Repository Overview

This is a **30-Days SOC (Security Operations Center) Challenge for Beginners** - an educational repository containing hands-on cybersecurity labs and exercises designed to train aspiring SOC analysts.

### Repository Purpose
- Provide practical, hands-on SOC analyst training
- Cover fundamental cybersecurity topics through daily challenges
- Offer real-world scenario-based learning with sample data files
- Guide students through log analysis, packet analysis, incident response, and EDR basics

---

## Repository Structure

```
30-Days-SOC-Challenge-Beginner/
├── README.md                          # Main repository readme
├── CLAUDE.md                          # This file - AI assistant guide
│
├── 101 SOC Analyst/                   # Foundational cybersecurity content
│   └── 1. Fundamental of Cybersecurity/
│       └── Overview of Cybersecurity
│
├── Challenge#1/                       # Log Analysis (Days 1-5)
│   ├── Day#1- Introduction to Log Analysis.md
│   ├── Day#2- Log Analysis Basics: Windows Security Logs.md
│   ├── Day#3- Log Analysis Basics: Windows Powershell Logs.md
│   ├── Day#4- Log Analysis Basics: Network-Based Attacks on Linux.md
│   ├── Day#5- Log Analysis Basics: Linux Auth Logs.md
│   ├── Cheat Sheet- Linux Logs.md
│   └── basics of powershell.md
│
├── Challenge#2/                       # Wireshark/Packet Analysis (Days 6-10)
│   ├── Day#6- Introduction to Wireshark.md
│   ├── Day#7- Wireshark Basics – ICMP Protocol Analysis.md
│   ├── Day#8- Wireshark Basics – TCP Protocol Analysis.md
│   ├── Day#9- Wireshark Basics – HTTP Protocol Analysis.md
│   └── Day#10- Wireshark Basics – TLS Protocol Analysis.md
│
├── Challenge#3/                       # Incident Response (Days 11-15)
│   ├── Day#11- Introduction to Incident Response.md
│   ├── Day#12- Incident Response Basics: Suspicious Bash Script Execution.md
│   ├── Day#13- Incident Response Basics- Malicious Cron Jobs.md
│   ├── Day#14- Incident Response Basics: Suspicious PowerShell Activity.md
│   └── Day#15- Incident Response Basics: Linux Suspicious Process.md
│
├── Challenge#4/                       # Splunk (Days 16-20 + Optional)
│   ├── Day#16-Setting up Splunk.md
│   ├── Day#17- Splunk Basics: Ingesting Linux Logs.md
│   ├── Day#18-Splunk Basics: SSH Log Analysis.md
│   ├── Day#19-Splunk Basics: HTTP Log Analysis.md
│   ├── Day#20- Splunk Basics: Connection Log Analysis.md
│   ├── Day#20-- Splunk Basics: Investigating Unauthorized Access.md
│   ├── Optional-1- Splunk Basics: Investing SSH Brute Force attack.md
│   └── Optional-2- Splunk Basics: Investigating Unusual User Creation.md
│
├── Challenge#5/                       # Advanced Topics (Days 21-25)
│   ├── Day#21- Introduction to Phishing Analysis.md
│   ├── Day#22- Phishing Analysis: Suspicious Lookalike email.md
│   ├── Day#23- Threat Intelligence basics.md
│   ├── Day#24- Introduction to Malware Analysis.md
│   └── Day#25- Introduction to Digital Forensics.md
│
├── Challenge#6/                       # EDR/Wazuh (Days 26-30)
│   ├── Day#26- Setting up Wazuh.md
│   ├── Day#27- EDR Basics: FIM using Wazuh.md
│   ├── Day#28- EDR Basics: Detecting SSH Brute Force attack.md
│   ├── Day#29: EDR Basics: Detecting Suspicious Network Traffic.md
│   └── Day#30- EDR Basics: Vulnerability detection using Wazuh.md
│
└── [Sample Data Files]                # Practice data for exercises
    ├── Protocol_Analysis_pcap.pcapng  # Network traffic capture (15.9 MB)
    ├── BRADESCO LIVELO.eml            # Sample phishing email
    ├── linux_auth_logs.json           # Linux authentication logs
    ├── ssh_logs.json                  # SSH connection logs
    ├── http_logs.json                 # HTTP traffic logs
    ├── dns_logs.json                  # DNS query logs
    ├── zeek_conn_logs.json            # Zeek network connection logs
    ├── Linux_UnAuthorized_Auditd_logs.json  # Audit logs
    └── Sample_PCAP_File               # Additional PCAP samples
```

---

## Content Organization

### Challenge Structure
The repository is organized into **6 main challenges**, each focusing on specific SOC analyst skills:

1. **Challenge #1: Log Analysis** (Days 1-5)
   - Windows Event Viewer, PowerShell logs, Security logs
   - Linux auth.log, syslog analysis
   - Focus on detecting unauthorized access and suspicious activities

2. **Challenge #2: Wireshark & Packet Analysis** (Days 6-10)
   - Protocol analysis (ICMP, TCP, HTTP, TLS)
   - Network traffic investigation
   - PCAP file analysis

3. **Challenge #3: Incident Response** (Days 11-15)
   - IR fundamentals and methodology
   - Detecting suspicious scripts, cron jobs, processes
   - Windows and Linux incident scenarios

4. **Challenge #4: Splunk** (Days 16-20)
   - SIEM setup and configuration
   - Log ingestion and analysis
   - Creating queries and investigating security events
   - Includes optional advanced exercises

5. **Challenge #5: Advanced Security Topics** (Days 21-25)
   - Phishing analysis
   - Threat intelligence
   - Malware analysis basics
   - Digital forensics introduction

6. **Challenge #6: EDR with Wazuh** (Days 26-30)
   - EDR setup and configuration
   - File Integrity Monitoring (FIM)
   - Detecting attacks (SSH brute force, suspicious traffic)
   - Vulnerability detection

---

## File Naming Conventions

### Markdown Files
- **Format:** `Day#{number}- {Topic Title}.md`
- **Examples:**
  - `Day#1- Introduction to Log Analysis.md`
  - `Day#29: EDR Basics: Detecting Suspicious Network Traffic.md`
- **Note:** Some files use `:` instead of `-` after "Day#X" (minor inconsistency)

### Special Files
- `Cheat Sheet- {Topic}.md` - Reference materials
- `basics of {topic}.md` - Foundational guides
- `Optional-{number}- {Title}.md` - Supplementary exercises

### Data Files
- JSON files: Use snake_case (e.g., `linux_auth_logs.json`)
- PCAP files: Descriptive names with proper extensions
- EML files: Uppercase format for sample emails

---

## Documentation Standards

### Markdown Structure
Each lab document follows a consistent structure:

```markdown
# Day#{N}: {Title}

---

## 🎯 Objective
Clear statement of learning goals

---

## 🖥️ Lab Setup
System requirements and prerequisites

---

## 📘 What is {Concept}?
Educational content explaining the topic

---

## 🛠️ Lab Task: {Task Title}
Step-by-step hands-on exercise

### Step 1: {Action}
Detailed instructions with code blocks

### Step 2: {Action}
...

---

## 📸 Submission
What students should submit (usually screenshots)

---

## 🎓 Learning Outcome / Conclusion
Summary of skills gained
```

### Common Elements
- **Emojis:** Used consistently for visual organization (🎯, 🖥️, 📘, 🛠️, 📸, 🎓)
- **Code Blocks:** Properly formatted with language indicators
- **Video Tutorials:** Many include YouTube video embeds with thumbnail images
- **Tables:** Used for structured information (e.g., vulnerability types, configurations)
- **Numbered Lists:** Step-by-step instructions
- **Bullet Points:** For concepts, tools, and key points

---

## Development Workflows

### Git Branch Strategy
- **Main Branch:** Production content (usually `main` or `master`)
- **Feature Branches:** Use pattern `claude/{description}-{session-id}`
  - Example: `claude/add-claude-documentation-73EgF`
- **CRITICAL:** Always push to Claude-specific branches (`claude/*`) to avoid 403 errors

### Git Operations Best Practices
1. **Always check current branch** before making changes
2. **Use descriptive commit messages** following existing patterns:
   - "Update Day#{N}: {Topic}"
   - "Add files via upload"
   - "Create Day#{N}- {Topic}"
3. **Push with upstream tracking:** `git push -u origin <branch-name>`
4. **Retry on network failures:** Up to 4 times with exponential backoff

### Commit Message Patterns
Based on git history analysis:
```
Update Day#{N}: {Topic Title}
Create Day#{N}- {Topic Title}
Add files via upload
Rename {old} to {new}
```

---

## Key Conventions for AI Assistants

### When Adding New Content

#### 1. Day Numbering
- Follow sequential numbering within each challenge
- Use format: `Day#{number}-` or `Day#{number}:`
- Check existing files to maintain consistency

#### 2. Documentation Format
- **Always include:** Objective, Lab Setup, Educational Content, Hands-on Task, Submission, Learning Outcome
- **Use emojis** for section headers (matching existing style)
- **Include code blocks** with proper syntax highlighting
- **Add video tutorials** when available (YouTube embeds)

#### 3. File Placement
- Place daily challenges in appropriate Challenge# directory
- Keep cheat sheets and reference materials with their related challenge
- Store sample data files in repository root

#### 4. Technical Accuracy
- **Verify commands** before including them (especially Linux/Windows commands)
- **Test file paths** in instructions
- **Validate log formats** and sample outputs
- **Check tool versions** and compatibility

### When Editing Existing Content

#### 1. Preserve Structure
- Maintain existing emoji usage
- Keep section ordering consistent
- Don't remove video embeds or links unless broken

#### 2. Update Carefully
- Read entire file before making changes
- Ensure updates match the difficulty level (beginner-friendly)
- Test any new commands or configurations
- Update related files if necessary (e.g., cheat sheets)

#### 3. Consistency Checks
- Match formatting of similar documents
- Use same terminology as existing content
- Keep file naming patterns consistent

### Security Considerations

This is an **educational repository** for authorized security training:
- ✅ **Allowed:** Educational content, defensive security, lab scenarios, CTF-style challenges
- ✅ **Allowed:** Sample malware analysis (with clear warnings and educational context)
- ✅ **Allowed:** Vulnerability scanning in controlled lab environments
- ❌ **Not Allowed:** Actual malware code without educational context
- ❌ **Not Allowed:** Techniques for malicious evasion or real-world attacks

### Sample Data Files

When working with or referencing sample data:
- **PCAP files:** Use for network analysis exercises (Wireshark, Zeek)
- **JSON logs:** Splunk ingestion and analysis exercises
- **EML files:** Phishing analysis scenarios
- **Always mention file location** when referenced in documentation
- **Include download links** when files are hosted externally

---

## Common Tasks for AI Assistants

### Adding a New Day's Content
1. Identify the correct Challenge# directory
2. Use proper file naming: `Day#{N}- {Topic}.md`
3. Follow the standard markdown structure
4. Include all required sections (Objective, Setup, Task, Submission, Outcome)
5. Add appropriate emojis and formatting
6. Update README.md if necessary
7. Commit with message: `Create Day#{N}- {Topic}`

### Updating Existing Documentation
1. Read the entire file first
2. Identify what needs updating
3. Preserve existing structure and style
4. Test any command changes
5. Commit with message: `Update Day#{N}: {Topic}`

### Adding Sample Data Files
1. Place in repository root (unless instructed otherwise)
2. Use descriptive, snake_case naming for JSON files
3. Update relevant lab documentation to reference the new file
4. Include file purpose in documentation
5. Commit with descriptive message

### Creating Cheat Sheets or References
1. Place in the relevant Challenge# directory
2. Use format: `Cheat Sheet- {Topic}.md`
3. Make it concise and reference-friendly
4. Use tables and code blocks for clarity
5. Link from relevant day documents

---

## Tools and Technologies Referenced

### Analysis Tools
- **Wireshark:** Network protocol analyzer
- **Splunk:** SIEM platform
- **Wazuh:** Open-source EDR/SIEM
- **ELK Stack:** Elasticsearch, Logstash, Kibana
- **Graylog:** Log management

### Operating Systems
- **Windows 10/11, Windows Server 2019/2022**
- **Linux:** Ubuntu, CentOS
- Focus on both Windows and Linux log sources

### Log Sources
- Windows Event Viewer (Security, System, Application, PowerShell)
- Linux logs (/var/log/auth.log, syslog, audit.log)
- Network logs (PCAP, Zeek, DNS)
- Application logs (Apache, SSH, HTTP)

### Protocols Covered
- ICMP, TCP, HTTP, HTTPS/TLS, SSH, DNS, FTP

---

## Quality Standards

### Documentation Quality
- **Clarity:** Instructions should be beginner-friendly
- **Completeness:** All steps should be included
- **Accuracy:** Commands and configurations must be tested
- **Consistency:** Follow established patterns

### Technical Accuracy
- Verify all commands work as documented
- Ensure log examples are realistic
- Check that file paths are correct
- Validate tool installation instructions

### Educational Value
- Each lab should teach specific, measurable skills
- Include "why" explanations, not just "how"
- Provide context for SOC analyst work
- Include real-world applicability

---

## Maintenance Guidelines

### Regular Reviews
- Check for broken YouTube links
- Update tool versions when necessary
- Verify download links for sample files
- Ensure all commands still work with current OS versions

### Content Updates
- Keep security concepts current
- Update CVE examples in vulnerability detection
- Refresh threat intelligence sources
- Modernize outdated screenshots or examples

### Issue Handling
- Document any known issues in the specific day's file
- Provide workarounds when possible
- Update setup instructions if prerequisites change

---

## Quick Reference for AI Assistants

### Before Making Changes
- [ ] Read relevant existing files
- [ ] Understand the challenge context
- [ ] Check file naming conventions
- [ ] Verify current git branch

### When Creating Content
- [ ] Follow markdown structure template
- [ ] Include all required sections
- [ ] Use appropriate emojis
- [ ] Add code blocks with syntax highlighting
- [ ] Include clear learning objectives
- [ ] Specify submission requirements

### Before Committing
- [ ] Verify all commands are correct
- [ ] Check file paths are accurate
- [ ] Ensure formatting is consistent
- [ ] Test any new instructions if possible
- [ ] Use proper commit message format

### When Pushing
- [ ] Confirm on correct branch (claude/*)
- [ ] Use: `git push -u origin <branch-name>`
- [ ] Verify push succeeded
- [ ] Create PR if requested

---

## Additional Resources

### External References
- YouTube tutorials are embedded in many lessons
- GitHub repository for sample PCAP files
- Tool documentation (Wireshark, Splunk, Wazuh)
- OWASP Top 10 for security vulnerabilities
- NVD (National Vulnerability Database) for CVEs

### Learning Progression
The challenge follows a logical progression:
1. **Foundation:** Log analysis basics (Challenge #1)
2. **Network:** Packet analysis with Wireshark (Challenge #2)
3. **Response:** Incident handling (Challenge #3)
4. **SIEM:** Centralized logging with Splunk (Challenge #4)
5. **Advanced:** Phishing, malware, forensics (Challenge #5)
6. **EDR:** Endpoint detection and response (Challenge #6)

---

## Version Information

- **Repository:** 30-Days-SOC-Challenge-Beginner
- **Last Updated:** 2025-12-29
- **Content Days:** 30 main days + optional exercises
- **Target Audience:** Beginner SOC analysts
- **Format:** Self-paced, hands-on labs

---

## Notes for Claude Code

### Interaction Style
- Be concise and technical
- Assume the user has basic cybersecurity knowledge
- Provide command-line solutions when appropriate
- Explain security concepts clearly

### When Uncertain
- Read multiple existing day files for patterns
- Check git history for recent changes
- Verify information against cybersecurity best practices
- Ask user for clarification on ambiguous requirements

### Best Practices
- Always test commands before suggesting them
- Maintain the educational, beginner-friendly tone
- Preserve existing documentation structure
- Keep security accuracy paramount
- Follow the established style guide strictly

---

*This documentation is maintained to help AI assistants effectively contribute to the 30-Days SOC Challenge repository while maintaining quality, consistency, and educational value.*
