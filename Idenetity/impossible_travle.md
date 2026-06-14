## Impossible Travel Detection

**Log Source:** Microsoft Sentinel — Entra ID Sign-in Logs  
**Table:** SigninLogs  
**MITRE ATT&CK:** T1078 — Valid Accounts  
**Purpose:** Detect a user logging in from two geographically distant 
locations within a short time window — indicating stolen credentials  

---

### Query

```kql
SigninLogs
| where ResultType == 0
| where TimeGenerated > ago(1h)
| summarize Locations = make_set(Location), IPs = make_set(IPAddress), 
LoginCount = count() by UserPrincipalName, bin(TimeGenerated, 1h)
| where array_length(Locations) > 1
| order by LoginCount desc
```

---

### What to Look For

- **Same user, 2 different countries within 1 hour** → Impossible travel
- **VPN or proxy IP** → Could explain location jump, verify first
- **New device or unfamiliar OS** → Higher suspicion
- **Followed by sensitive actions** → Escalate immediately

---

### Verdict Triggers

| Condition | Action |
|---|---|
| 2 countries, under 1 hour, no VPN | Escalate |
| Known VPN IP involved | Likely false positive |
| Sensitive resource accessed after | High priority |
| User confirms travel | Close as B-TP |

---

### Notes

- Always confirm with user or manager before closing
- Check if user has VPN or travel history
- Cross-reference with Entra ID risk detections
- This alert is built into Entra ID Protection natively — 
compare findings
