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

- 

---

## Query

```text
event.action : "cowrie.login.failed"
Results aggregated by source.ip >= 25
```
---
## Work in Progress

need to tune the Detection logic to supress the lower severity alerts and only show the highest severity that applies to reduce noise of multiple alerts per brute force attempt
