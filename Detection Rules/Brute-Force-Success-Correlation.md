# Detection: Brute Force Followed by Successful Login

## Overview

Detects successful authentication after multiple failed attempts from the same IP.

---

## Detection Logic

A sequence of failed logins followed by a successful login indicates a likely compromise.

---

## Rule Type

EQL Correlation Rule

---

## Query

sequence by source.ip with maxspan=2m
  [any where event.action == "cowrie.login.failed"]
  ...
  [any where event.action == "cowrie.login.success"]

---

## Fields Used

- source.ip
- event.action
- user.name

---

## Severity

High

---

## MITRE ATT&CK Mapping

- Tactic: Credential Access
- Technique: T1110

---

## Testing Methodology

Generated failed logins using sshpass, followed by a successful login.

---

## Example Alert

![Correlation](../screenshots/correlation.png)

---

## Investigation Guide

1. Identify source IP  
2. Confirm failed login pattern  
3. Confirm successful login  
4. Review commands executed  

---

## Limitations

- Requires properly tuned time window
- May miss low-and-slow attacks

---

## Improvements

- Add session tracking
- Combine with command detection
