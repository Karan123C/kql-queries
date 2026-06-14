## Guest User Invitation Detection

**Log Source:** Microsoft Sentinel — Entra ID Audit Logs  
**Table:** AuditLogs  
**MITRE ATT&CK:** T1136 — Create Account  
**Purpose:** Detect external guest users being invited into the tenant 
which could indicate insider threat or misconfiguration  

---

### Query

```kql
AuditLogs
| where OperationName == "Invite external user"
| where TimeGenerated > ago(1d)
| extend InvitedBy = tostring(InitiatedBy.user.userPrincipalName)
| extend InvitedUser = tostring(TargetResources[0].userPrincipalName)
| project TimeGenerated, InvitedBy, InvitedUser, Result
| order by TimeGenerated desc
```

---

### What to Look For

- **Unknown user sending invitations** → Investigate
- **Bulk invitations in short time** → High suspicion
- **Invited user from suspicious domain** → Escalate
- **Invitation sent after hours** → Higher suspicion

---

### Verdict Triggers

| Condition | Action |
|---|---|
| Authorised IT/HR sending invite | Likely B-TP |
| Unknown sender + suspicious domain | Escalate |
| Bulk invites with no business reason | Escalate immediately |
| Invited user gains sensitive access | High priority |

---

### Notes

- Verify with sender if invitation was intentional
- Check invited domain against known threat intel
- Cross-reference with Entra ID access reviews
- Guest users should follow least privilege principle
