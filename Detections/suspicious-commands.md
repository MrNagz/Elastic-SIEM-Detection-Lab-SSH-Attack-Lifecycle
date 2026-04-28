# Detection: <Name>

## Overview

This Rule Detects commands that are most likely being used for malicious purposes

---

## Detection Logic

This detection uses a query to see if wget or curl or chmod are run on the machine

---

## Rule Type

- Custom Query 

---
## Mitre

Tactic: Command and Control

Technique: T1105 – Ingress Tool Transfer

Tactic: Execution

Technique: T1059 – Command and Scripting Interpreter

---

## Query

```text
eventid: cowrie.command.input AND cowrie.command: (*wget* OR *curl* OR *chmod*)
```
---
## Investigation Guide
1. Identify source IP and executed command

2. Pivot on source.ip:
  source.ip: "{{context.source.ip}}"

3. Review full command history:
  eventid: cowrie.command.input AND source.ip: "{{context.source.ip}}"

4. Check for prior brute force activity:
  eventid: cowrie.login.failed AND source.ip: "{{context.source.ip}}"

5. Determine if commands indicate payload download or execution

6. Assess whether activity represents automated malware or manual interaction
