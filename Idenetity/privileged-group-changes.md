## Privileged Group Changes Detection

**Log Source:** Microsoft Sentinel — Windows Security Events  
**EventID:** 4732  
**MITRE ATT&CK:** T1098 — Account Manipulation  
**Purpose:** Detect users being added to privileged groups indicating 
possible privilege escalation or insider threat  

---

### Query

```kql
SecurityEvent
| where EventID == 4732
| where TimeGenerated > ago(1h)
| project TimeGenerated, Account, MemberName, TargetUserName, Computer
| order by TimeGenerated desc
```

---

### What to Look For

- **Unknown account added to Domain Admins** → High priority
- **After hours activity** → Higher suspicion
- **Service account added to privileged group** → Investigate
- **Multiple additions in short time** → Possible compromise

---

### Verdict Triggers

| Condition | Action |
|---|---|
| Unauthorised user added to admin group | Escalate immediately |
| Change done by IT during maintenance | Likely B-TP |
| Service account added unexpectedly | Investigate |
| After hours + no change ticket | Escalate |

---

### Notes

- Always verify if a change request or ticket exists
- Cross-reference with EventID 4728 (global group) and 4756 (universal group)
- Check who performed the action — Account field shows the actor
