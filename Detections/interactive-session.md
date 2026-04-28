# Detection: <Name>

## Overview
This Detection alerts a session that looks like a human exploring the machine


---

## Detection Logic

This detection looks for a few commands that are used by humans to navigate around a machine, hopefully seperating bots running scripts and gain intel on how humans use exploits

---

## Rule Type

- Threshold

---
## Mitre

Tactic: Discovery

Technique: T1082 – System Information Discovery

Technique: T1083 – File and Directory Discovery

Technique: T1033 – Account Discovery

---

## Query

```text
event.action: "cowrie.command.input" AND
(
  cowrie.command: *ls* OR
  cowrie.command: *pwd* OR
  cowrie.command: *whoami* OR
  cowrie.command: *cat* OR
  cowrie.command: *cd*
)
Results aggregated by source.ip >= 5
```
---
## Investigation Guide

1. Identify source IP associated with command activity

2. Pivot on source.ip:
   source.ip: "{{context.source.ip}}"

3. Review full command history:
  event.action: "cowrie.command.input" AND source.ip: "{{context.source.ip}}"

4. Identify command patterns:

  - System discovery (ls, pwd, whoami)
  - File inspection (cat)
  - Directory movement (cd)
  
5. Determine if behavior indicates interactive exploration

6. Correlate with prior alerts:

  - Brute force activity
  - Successful login
  - Suspicious command execution
    
7. Assess risk based on level of interaction and command diversity
