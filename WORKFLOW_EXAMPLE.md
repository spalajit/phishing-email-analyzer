# Email Analyzer - Complete Workflow Example

This document shows the complete workflow with **user confirmation** at every step.

## Running the Analyzer

```bash
python email_analyzer.py analyze --file samples/sample_phishing.eml
```

## Detailed Workflow

### Step 1: Email Parsing and Summary

The tool parses the email and displays all extracted information:

```
======================================================================
EMAIL ANALYSIS SUMMARY
======================================================================

Subject: Urgent: Verify Your Account Immediately
From: IT Security Team <phisher@evil-domain.com>
  └─ Email: phisher@evil-domain.com
  └─ Domain: evil-domain.com
Date: Thu, 17 Oct 2024 10:00:00 -0400

URLs Found (2):
  - https://secure-verification-portal.evil-domain.com/verify?token=xyz123abc
  - http://account-security-check.malicious-site.com/login

URL Domains:
  - secure-verification-portal.evil-domain.com
  - account-security-check.malicious-site.com

Embedded Emails:
  - support@evil-domain.com
======================================================================
```

### Step 2: Check Point - Email Queries

The tool queries Check Point for related emails:

```
=== Check Point Analysis ===

[1/3] Searching for emails with same subject...
      Found 3 email(s) with subject: 'Urgent: Verify Your Account Immediately'
      Recent matches:
        - 2024-10-17 10:05:00 | From: phisher@evil-domain.com | To: john.doe@company.com
        - 2024-10-17 10:03:00 | From: phisher@evil-domain.com | To: jane.smith@company.com
        - 2024-10-17 10:00:00 | From: phisher@evil-domain.com | To: victim@company.com

[2/3] Searching for emails from same sender...
      Found 5 email(s) from: phisher@evil-domain.com
      Recent matches:
        - 2024-10-17 10:05:00 | Subject: Urgent: Verify Your Account Immediately
        - 2024-10-17 10:03:00 | Subject: Urgent: Verify Your Account Immediately
        - 2024-10-17 10:00:00 | Subject: Urgent: Verify Your Account Immediately
        - 2024-10-16 14:30:00 | Subject: Action Required: Account Verification
        - 2024-10-15 09:15:00 | Subject: Security Alert

[3/3] Searching for emails sent TO sender (possible victims)...
      Found 2 email(s) sent to: phisher@evil-domain.com
      ⚠ WARNING: Users may have replied to this phishing email!
      Possible victims:
        - 2024-10-17 10:10:00 | From: john.doe@company.com
        - 2024-10-17 10:07:00 | From: jane.smith@company.com
```

### Step 3: Proposed Actions - Individual Confirmation

Now the tool asks for confirmation on **each action individually**:

```
======================================================================
PROPOSED ACTIONS - PLEASE REVIEW
======================================================================

[Action 1] Quarantine 3 email(s) with subject: 'Urgent: Verify Your Account Immediately'
  Proceed with quarantine? (y/n): y
  Enter quarantine reason: Phishing campaign targeting multiple users

[Action 2] Block sender email: phisher@evil-domain.com
  Proceed with email block? (y/n): y
  Enter block comment: Phishing sender - fake IT security alert

[Action 3] Block entire domain: evil-domain.com
  Proceed with domain block? (y/n): y
  Enter domain block comment: Known phishing infrastructure
```

**You can skip any action by typing 'n':**

```
[Action 1] Quarantine 3 email(s) with subject: 'Urgent: Verify Your Account Immediately'
  Proceed with quarantine? (y/n): n
  Skipped quarantine

[Action 2] Block sender email: phisher@evil-domain.com
  Proceed with email block? (y/n): y
  Enter block comment: Phishing sender
```

### Step 4: Final Confirmation

Before executing anything, you get a **final summary and confirmation**:

```
======================================================================
FINAL CONFIRMATION
======================================================================

You are about to perform 3 action(s):
  1. Quarantine 3 email(s)
  2. Block email: phisher@evil-domain.com
  3. Block domain: evil-domain.com

Execute all actions? (yes/no): yes
```

**Type 'no' to cancel everything:**

```
Execute all actions? (yes/no): no

Actions cancelled by user.
```

### Step 5: Action Execution

Only after you type "yes", the tool executes the actions:

```
======================================================================
EXECUTING ACTIONS
======================================================================

Quarantining emails with subject 'Urgent: Verify Your Account Immediately'...
✓ Quarantined 3 email(s)

Blocking sender email 'phisher@evil-domain.com'...
✓ Created sender block rule: Block_phisher@evil-domain.com_20241017_145623

Blocking domain 'evil-domain.com'...
✓ Created domain block rule: Block_Domain_evil-domain.com_20241017_145625

Publishing Check Point configuration...
✓ Configuration published successfully
```

### Step 6: Netskope - URL Blocking

Next, the tool handles URL blocking in Netskope:

```
=== Netskope URL Blocking ===

Extracted URLs (2):
  1. https://secure-verification-portal.evil-domain.com/verify?token=xyz123abc
  2. http://account-security-check.malicious-site.com/login

URL Editing:
  - Press ENTER to block all URLs
  - Type 'edit' to modify the list
  - Type 'skip' to skip URL blocking

Your choice: edit
```

**Option 1: Accept all URLs (press ENTER)**
```
Your choice:

Final URL list (2):
  - https://secure-verification-portal.evil-domain.com/verify?token=xyz123abc
  - http://account-security-check.malicious-site.com/login
```

**Option 2: Edit the list**
```
Your choice: edit

For each URL, type 'y' to include, 'n' to skip, or enter a modified URL:
  https://secure-verification-portal.evil-domain.com/verify?token=xyz123abc [y/n/modified]: y
  http://account-security-check.malicious-site.com/login [y/n/modified]: https://account-security-check.malicious-site.com

Add additional URLs (one per line, empty line to finish):
  https://evil-domain.com


Final URL list (3):
  - https://secure-verification-portal.evil-domain.com/verify?token=xyz123abc
  - https://account-security-check.malicious-site.com
  - https://evil-domain.com
```

**Option 3: Skip URL blocking**
```
Your choice: skip
Skipping URL blocking
```

### Step 7: Netskope Confirmation

Before blocking URLs, you get a final confirmation:

```
======================================================================
NETSKOPE BLOCK CONFIRMATION
======================================================================
You are about to block 3 URL(s) in Netskope list: 'Phishing_URLs_Blocklist'

Proceed with URL blocking? (yes/no): yes

Blocking URLs in Netskope list: 'Phishing_URLs_Blocklist'...
✓ Successfully blocked 3 URL(s) in Netskope
  List: Phishing_URLs_Blocklist
  List ID: abc123
```

**Type 'no' to cancel:**
```
Proceed with URL blocking? (yes/no): no

URL blocking cancelled by user.
```

### Step 8: Report Generation

Finally, a JSON report is saved:

```
✓ Analysis report saved: reports/email_analysis_20241017_145630.json
```

## Summary of Confirmations

The tool requires confirmation at **3 key points**:

1. **Individual action confirmation** (for each Check Point action):
   - Quarantine emails? (y/n)
   - Block sender email? (y/n)
   - Block sender domain? (y/n)

2. **Final Check Point confirmation** (before executing any actions):
   - Execute all actions? (yes/no)

3. **Netskope confirmation** (before blocking URLs):
   - Proceed with URL blocking? (yes/no)

## Quick Decision Guide

### Quarantine Emails
- **YES if**: Multiple users received the same phishing email
- **NO if**: Only one user received it (already isolated)

### Block Sender Email
- **YES if**: Confirmed phishing/malicious sender
- **NO if**: Suspicious but not confirmed (investigate first)

### Block Domain
- **YES if**: Domain is clearly malicious/disposable
- **NO if**: Domain might be legitimate but compromised (e.g., gmail.com, yahoo.com)

### Block URLs
- **YES for**: Phishing sites, credential harvesting pages
- **Edit first**: If URLs need wildcard expansion (e.g., block whole domain)
- **NO if**: URLs are from legitimate sites (might be false positive)

## Example: Conservative Response

```
[Action 1] Quarantine 3 email(s)
  Proceed? (y/n): y    ← Quarantine to prevent further spread

[Action 2] Block sender email
  Proceed? (y/n): y    ← Block confirmed phishing sender

[Action 3] Block entire domain
  Proceed? (y/n): n    ← Don't block domain (might be too broad)
  Skipped domain block

Execute all actions? (yes/no): yes

[URLs]
Your choice: edit
  - evil-site.com/verify [y/n/modified]: y
  - gmail.com [y/n/modified]: n    ← Don't block legitimate service

Proceed with URL blocking? (yes/no): yes
```

## Safety Features

1. **No automatic execution** - Every action requires explicit confirmation
2. **Granular control** - Approve/reject each action individually
3. **URL editing** - Review and modify URLs before blocking
4. **Final review** - See all actions before committing
5. **Easy cancellation** - Type 'no' or 'n' to skip any step

---

**Remember**: You have full control at every step. When in doubt, choose 'no' and investigate further.
