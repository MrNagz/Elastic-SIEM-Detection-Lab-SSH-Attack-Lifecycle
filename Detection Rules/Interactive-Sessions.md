# Detection: <Name>

## Overview
This Detection alers a session that looks like a human exploring the machine


---

## Detection Logic

This detection looks for a few commands that are used by humans to navigate around a machine, hopefully seperating bots running scripts and gain intel on how humans use exploits

---

## Rule Type

- Threshold

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
