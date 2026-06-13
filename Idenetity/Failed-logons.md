## Failed Logon Detection

**Log Source:** Microsoft Sentinel — Windows Security Events  
**EventID:** 4625  
**MITRE ATT&CK:** T1110 — Brute Force  
**Purpose:** Detect repeated failed logon attempts indicating brute force 
or password spray attacks  

---

### Query

```kql
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(1h)
| summarize FailedAttempts = count() by Account, IpAddress, Computer, 
WorkstationName
| where FailedAttempts > 5
| order by FailedAttempts desc
```

---

### What to Look For

- **Same account, multiple IPs** → Password spray attack
- **Same IP, multiple accounts** → Brute force attack
- **After hours timing** → Higher suspicion
- **Followed by EventID 4624** → Successful logon after failures = 
compromise likely

---

### Verdict Triggers

| Condition | Action |
|---|---|
| >5 failures, same account, 1 hour | Investigate |
| >10 failures + successful 4624 after | Escalate immediately |
| Known IP / service account | Likely false positive |
| External IP + admin account targeted | High priority |

---

### Notes

- Cross-reference with EventID 4624 to check if attack succeeded
- Check if account was locked (EventID 4740)
- Validate IP against threat intel (AbuseIPDB, Sentinel watchlists)
