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

## Query

```text
eventid: cowrie.command.input AND cowrie.command: (*wget* OR *curl* OR *chmod*)
