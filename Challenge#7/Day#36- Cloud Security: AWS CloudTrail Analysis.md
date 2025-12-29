# Day#36- Cloud Security: AWS CloudTrail Analysis

---

## 🎯 Objective

To understand AWS CloudTrail logging, learn how to analyze cloud security events, and detect common cloud-based threats in AWS environments.

---

## 🖥️ Lab Setup

### **System Requirements**
- **AWS Account:** Free tier account (or sandbox environment)
- **Web Browser:** Chrome, Firefox, or Edge
- **Optional:** AWS CLI installed locally

### **AWS Services Used**
- **CloudTrail:** Audit logging for AWS API calls
- **CloudWatch:** Log aggregation and monitoring
- **S3:** CloudTrail log storage
- **IAM:** Identity and Access Management

### **Cost Note**
Most of this lab can be completed within AWS Free Tier limits. CloudTrail provides one free trail.

---

## 📘 What is AWS CloudTrail?

**AWS CloudTrail** is a service that enables governance, compliance, and auditing of your AWS account by logging all API calls made to AWS services.

### **What CloudTrail Captures**
- **Who:** IAM user or role that made the request
- **When:** Timestamp of the request
- **What:** Which AWS service and action (e.g., CreateBucket, TerminateInstances)
- **Where:** Source IP address and region
- **Result:** Success or failure
- **How:** Request parameters and response elements

### **CloudTrail Event Types**

| Event Type | Description | Examples |
|------------|-------------|----------|
| **Management Events** | Control plane operations | Create EC2, Delete S3 bucket, Modify IAM policy |
| **Data Events** | Data plane operations | S3 object access, Lambda function invocations |
| **Insight Events** | Unusual activity detection | Spike in API calls, error rate increases |

---

## ☁️ Common Cloud Security Threats

### **1. Compromised Credentials**
Attackers use stolen AWS access keys to:
- Launch cryptocurrency miners
- Exfiltrate S3 bucket data
- Create backdoor IAM accounts

### **2. Privilege Escalation**
Attackers exploit overly permissive IAM policies to:
- Attach administrator policies to their account
- Create new access keys for persistence

### **3. Data Exfiltration**
Attackers:
- Make S3 buckets public
- Copy data to external accounts
- Create snapshots and share them

### **4. Resource Abuse**
Attackers:
- Launch expensive EC2 instances for crypto mining
- Create resources in unusual regions

### **5. Persistence Mechanisms**
Attackers:
- Create IAM users/roles for backdoor access
- Modify security groups to allow future access
- Create access keys for service accounts

---

## 🔍 Critical CloudTrail Events to Monitor

### **IAM-Related Events (Privilege & Access)**

| Event Name | Risk Level | Description |
|------------|-----------|-------------|
| **CreateAccessKey** | 🔴 High | New API access key created |
| **CreateUser** | 🔴 High | New IAM user created |
| **AttachUserPolicy** | 🔴 High | Policy attached to user (potential privilege escalation) |
| **PutUserPolicy** | 🔴 High | Inline policy added to user |
| **CreateRole** | 🟡 Medium | New IAM role created |
| **AssumeRole** | 🟡 Medium | Role assumed (track unusual role usage) |
| **ConsoleLogin** | 🟢 Low | User logged into AWS Console |
| **DeleteUser** | 🔴 High | IAM user deleted (covering tracks) |

### **S3 Events (Data Protection)**

| Event Name | Risk Level | Description |
|------------|-----------|-------------|
| **PutBucketPublicAccessBlock** | 🔴 High | Public access settings modified |
| **PutBucketPolicy** | 🔴 High | Bucket policy changed |
| **DeleteBucket** | 🔴 High | S3 bucket deleted |
| **GetObject** | 🟡 Medium | Object downloaded (enable data events) |
| **PutObject** | 🟢 Low | Object uploaded |

### **EC2 Events (Resource Abuse)**

| Event Name | Risk Level | Description |
|------------|-----------|-------------|
| **RunInstances** | 🟡 Medium | New EC2 instance launched |
| **TerminateInstances** | 🟡 Medium | EC2 instance terminated |
| **CreateSecurityGroup** | 🟡 Medium | New security group created |
| **AuthorizeSecurityGroupIngress** | 🔴 High | Firewall rule allowing inbound traffic |

### **Account-Level Events**

| Event Name | Risk Level | Description |
|------------|-----------|-------------|
| **DisableRegion** | 🔴 High | AWS region disabled |
| **DeleteTrail** | 🔴 High | CloudTrail logging disabled (anti-forensics) |
| **StopLogging** | 🔴 High | CloudTrail trail stopped |
| **UpdateTrail** | 🟡 Medium | CloudTrail configuration changed |

---

## 🛠️ Lab Task 1: Enable and Configure CloudTrail

### **Step 1: Create a CloudTrail Trail**

1. Log into **AWS Console**
2. Navigate to **CloudTrail** service
3. Click **Create trail**
4. Configure:
   - **Trail name:** `SOC-Security-Trail`
   - **Storage location:** Create new S3 bucket
   - **Log file validation:** ✅ Enabled (prevents tampering)
   - **Management events:** ✅ Read/Write
   - **Data events:** ✅ Enable for critical S3 buckets

5. Click **Create trail**

### **Step 2: Verify Logging is Active**

```bash
aws cloudtrail get-trail-status --name SOC-Security-Trail
```

Expected output:
```json
{
    "IsLogging": true,
    "LatestDeliveryTime": "2024-12-29T10:30:00Z"
}
```

---

## 🛠️ Lab Task 2: Analyze CloudTrail Logs for Suspicious Activity

### **Scenario 1: Detect Compromised Access Keys**

**Indicators of Compromised Credentials:**
- API calls from unexpected geographic locations
- API calls from unfamiliar IP addresses
- High volume of API errors (unauthorized attempts)
- Access at unusual times (e.g., 3 AM for a 9-5 employee)

### **CloudTrail Query (Console)**

1. Go to **CloudTrail → Event history**
2. Filter by:
   - **Event name:** CreateAccessKey
   - **Time range:** Last 7 days
3. Review events for:
   - Who created the key?
   - When was it created?
   - Source IP address

### **Using AWS CLI to Query Logs:**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey \
  --max-results 10
```

### **Analysis Questions:**
- Was this access key creation expected?
- Is the source IP from your organization's range?
- Has this user created multiple keys recently?
- Were there failed API calls immediately after?

---

### **Scenario 2: Detect Privilege Escalation**

**Attack Pattern:**
Attacker with limited IAM permissions attempts to escalate privileges by:
1. Attaching the `AdministratorAccess` policy to their user
2. Creating a new IAM user with admin rights
3. Modifying their own inline policy

### **CloudTrail Events to Investigate:**

Look for these event names in sequence:
- `AttachUserPolicy` (especially if policy = AdministratorAccess)
- `PutUserPolicy` (inline policy modification)
- `CreateUser` + `AttachUserPolicy` (creating backdoor admin)

### **Detection Query:**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AttachUserPolicy \
  --start-time 2024-12-29T00:00:00 \
  --end-time 2024-12-29T23:59:59
```

### **Investigation Steps:**
1. Identify the user who performed the action
2. Check if they have authorization to modify IAM policies
3. Review what policy was attached (is it AdministratorAccess?)
4. Check for subsequent suspicious activity from that user

---

### **Scenario 3: Detect S3 Bucket Exposure**

**Attack Pattern:**
Attacker makes an S3 bucket public to exfiltrate data.

### **CloudTrail Events:**

| Event Name | What It Means |
|------------|---------------|
| `PutBucketAcl` | Bucket ACL modified (potentially made public) |
| `PutBucketPolicy` | Bucket policy changed (could allow public access) |
| `DeleteBucketPublicAccessBlock` | Public access block removed |

### **Detection Query:**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutBucketAcl
```

### **Analysis:**
For each event, check:
- Which bucket was modified?
- What user made the change?
- What is the new ACL/policy? (public-read?)
- Was there a GetObject spike after the change? (data exfiltration)

---

### **Scenario 4: Detect Cryptocurrency Mining**

**Attack Pattern:**
Attacker launches large EC2 instances in unusual regions to mine cryptocurrency.

### **Indicators:**
- RunInstances in regions you don't normally use
- Large instance types (e.g., c5.24xlarge, p3.16xlarge)
- Multiple instances launched simultaneously
- Instance launched from unfamiliar IP address

### **Detection Query:**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=RunInstances \
  --max-results 20
```

### **Red Flags:**
- ❌ Instance launched in ap-southeast-1 (but your org only uses us-east-1)
- ❌ Instance type: c5.24xlarge (compute-optimized, expensive)
- ❌ Source IP: 203.0.113.45 (unfamiliar external IP)
- ❌ Launch time: 2:00 AM (outside business hours)

---

## 🛠️ Lab Task 3: Create CloudWatch Alarms for Security Events

### **Step 1: Create Metric Filter for Root User Activity**

Root user logins should be rare and monitored closely.

1. Go to **CloudWatch → Logs → Log groups**
2. Select your CloudTrail log group
3. Click **Create metric filter**
4. Filter pattern:
```
{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }
```
5. Name: `RootUserActivity`
6. Create alarm:
   - Threshold: >= 1 occurrence
   - Notification: Send SNS email alert

### **Step 2: Alert on CloudTrail Disabled**

Attackers often disable logging to cover their tracks.

Filter pattern:
```
{ ($.eventName = StopLogging) || ($.eventName = DeleteTrail) || ($.eventName = UpdateTrail) }
```

### **Step 3: Alert on IAM Policy Changes**

Filter pattern:
```
{ ($.eventName = PutUserPolicy) || ($.eventName = PutGroupPolicy) || ($.eventName = PutRolePolicy) || ($.eventName = AttachUserPolicy) || ($.eventName = AttachGroupPolicy) || ($.eventName = AttachRolePolicy) }
```

---

## 📸 Submission

Submit the following:

1. **CloudTrail Configuration:**
   - Screenshot showing CloudTrail trail is enabled and logging
   - S3 bucket location where logs are stored
   - Confirmation that log file validation is enabled

2. **Event Analysis - Scenario 1 (Compromised Credentials):**
   - Screenshot of a CreateAccessKey event from CloudTrail
   - Analysis: Who created it? When? Source IP?
   - Assessment: Legitimate or suspicious?

3. **Event Analysis - Scenario 2 (Privilege Escalation):**
   - CloudTrail query results for AttachUserPolicy events
   - List of policies that were attached
   - Identify if any are overly permissive (AdministratorAccess, PowerUserAccess)

4. **Event Analysis - Scenario 3 (S3 Exposure):**
   - Query results for PutBucketAcl or PutBucketPolicy
   - Analysis of which buckets were modified
   - Determination if any became publicly accessible

5. **CloudWatch Alarm Configuration:**
   - Screenshot of at least 2 CloudWatch alarms created
   - Metric filter patterns used
   - SNS notification configured

---

## 🎓 Learning Outcome

After completing this lab, you will:

- Understand the role of AWS CloudTrail in cloud security monitoring
- Enable and configure CloudTrail for comprehensive logging
- Analyze CloudTrail events to detect suspicious activity
- Identify indicators of compromised AWS credentials
- Detect privilege escalation attempts in IAM
- Monitor for S3 bucket exposure and data exfiltration
- Recognize cryptocurrency mining and resource abuse patterns
- Create CloudWatch alarms for critical security events
- Understand the importance of log file validation and tamper detection
- Apply security monitoring principles to cloud environments
- Differentiate between management, data, and insight events

---

## 💡 Key Takeaways

✅ **CloudTrail is essential** - Every AWS API call should be logged
✅ **Enable log file validation** - Prevents attackers from tampering with logs
✅ **Monitor root user activity** - Root should rarely be used
✅ **IAM policy changes are high risk** - Alert on privilege modifications
✅ **Geographic anomalies matter** - API calls from unexpected regions are suspicious
✅ **Failed API calls indicate probing** - High error rates suggest reconnaissance
✅ **CloudTrail can be disabled** - Monitor for StopLogging and DeleteTrail events
✅ **Integrate with SIEM** - Forward CloudTrail logs to Splunk/Wazuh for correlation

---

## 📚 Additional Resources

- [AWS CloudTrail Documentation](https://docs.aws.amazon.com/cloudtrail/)
- [AWS Security Best Practices](https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html)
- [MITRE ATT&CK for Cloud (IaaS)](https://attack.mitre.org/matrices/enterprise/cloud/)
- [AWS CloudTrail Log Event Reference](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html)
- [AWS Security Hub](https://aws.amazon.com/security-hub/)
- [AWS GuardDuty - Threat Detection](https://aws.amazon.com/guardduty/)
- [CloudTrail Insights](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-insights-events-with-cloudtrail.html)
- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)

---

## 🔗 CloudTrail Event Cheat Sheet

### High-Priority Events for SOC Monitoring

**Account Compromise:**
- `ConsoleLogin` (failed attempts)
- `GetSessionToken` (temporary credentials requested)
- `CreateAccessKey`
- `UpdateAccessKey`

**Privilege Escalation:**
- `AttachUserPolicy`
- `AttachRolePolicy`
- `PutUserPolicy`
- `CreatePolicyVersion`

**Persistence:**
- `CreateUser`
- `CreateRole`
- `CreateLoginProfile`

**Defense Evasion:**
- `DeleteTrail`
- `StopLogging`
- `PutEventSelectors`
- `DeleteFlowLogs`

**Data Exfiltration:**
- `PutBucketAcl`
- `PutBucketPolicy`
- `CreateSnapshot` (EBS)
- `CreateDBSnapshot` (RDS)

**Resource Abuse:**
- `RunInstances`
- `CreateFunction` (Lambda)
- `CreateCluster` (ECS/EKS)

---

## 🧪 Bonus Exercise

### Hunt for Unusual API Activity

Write a CloudTrail query to find:
1. API calls from IPs outside your country
2. API calls made by IAM users during non-business hours
3. High volume of API errors from a single user (potential reconnaissance)
4. S3 GetObject requests for buckets containing "confidential" or "sensitive"

**Hint:** Use `aws cloudtrail lookup-events` with JSON output and process with `jq` or Python for advanced analysis.
