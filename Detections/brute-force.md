# Detection: Brute-Force Attempt

## Overview

Detects multiple failed logins within a certian time frame and broke up into 3 severtity catagories.

---

## Detection Logic

1. detects 5 login attempts within 5 minutes (low severity)
2. detects 10 login attempts within 5 minutes (Medium severity)
3. detects 20 login attempts within 5 minutes (High severity)




---

## Rule Type

Threshold

---
## Mitre

Tactic: Credential Access
Technique: T1110 Brute Force

---

## Query

```text
event.action : "cowrie.login.failed"
Results aggregated by source.ip >= 25
```
---
## Investigation Guide

Identify source IP and confirm alert threshold

Pivot on source.ip in Discover:
source.ip: "{{context.source.ip}}"

Check for successful authentication:
eventid: cowrie.login.success AND source.ip: "{{context.source.ip}}"

Review login attempts and usernames:
eventid: cowrie.login.failed AND source.ip: "{{context.source.ip}}"

If successful login is found, review command execution:
eventid: cowrie.command.input AND source.ip: "{{context.source.ip}}"

Determine if activity indicates compromise or scanning behavior

---
## Work in Progress

need to tune the Detection logic to supress the lower severity alerts and only show the highest severity that applies to reduce noise of multiple alerts per brute force attempt
