# Email Analyzer and Threat Response Tool

Automated tool to analyze reported phishing emails and create block rules in Check Point and Netskope.

## Why this exists

Phishing triage is repetitive and time-sensitive: pull the sender, subject, and
URLs out of a reported email; check whether anyone else received the same
message or replied to it; then get block rules in place before more people
click. Doing that by hand across two separate admin consoles is slow and easy
to get inconsistent. This tool parses the reported email once, runs the
correlation queries automatically, and turns the analyst's decisions into
block rules and a blocklist update — with a confirmation step before anything
is actually changed.

## Features

### Email Analysis
- **Parse email files** (.eml format) or raw email text
- **Extract key information**:
  - Sender email address and domain
  - Subject line
  - All URLs and domains
  - Recipients
  - Embedded email addresses
  - Attachments

### Check Point Integration
- **Query email history** (last 14 days):
  - Emails with same subject line
  - Emails from same sender
  - Emails sent TO the sender (potential victim responses)
- **Create block rules**:
  - Block sender email address (with custom comment)
  - Block entire sender domain (optional, with custom comment)
- **Publish changes** automatically

### Netskope Integration
- **Extract URLs** from phishing emails
- **Interactive URL editing**:
  - Review extracted URLs
  - Add or remove URLs
  - Modify URLs before blocking
- **Create URL blocklist**:
  - Adds URLs to existing list or creates new one
  - Centralized management of phishing URLs

## Installation

### Prerequisites
- Python 3.8 or higher
- Access to Check Point Management API
- Access to Netskope API (with URL list management permissions)

### Setup

1. **Install dependencies**:
   ```bash
   cd EmailAnalyzer
   pip install -r requirements.txt
   ```

2. **Configure the tool**:
   Edit `config.yaml` and add your credentials:

   ```yaml
   checkpoint:
     enabled: true
     base_url: "https://your-checkpoint-server"
     username: "admin"
     password: "your_password"

   netskope:
     enabled: true
     tenant: "yourcompany"
     api_token: "your_api_token"
     blocklist_name: "Phishing_URLs_Blocklist"
   ```

3. **Create directories** (if not exist):
   ```bash
   mkdir logs reports samples
   ```

## Usage

### Test Connections
```bash
python email_analyzer.py test
```

### Analyze a Phishing Email

**From .eml file**:
```bash
python email_analyzer.py analyze --file samples/phishing_email.eml
```

**From raw email text**:
```bash
python email_analyzer.py analyze --text "From: phisher@evil.com..."
```

### Workflow

When you analyze an email, the tool will:

1. **Parse and display** email details:
   - Sender information
   - Subject and recipients
   - Extracted URLs
   - Attachments

2. **Check Point queries** (if enabled):
   - Search for emails with same subject
   - Search for emails from same sender
   - Search for replies to the sender (victims)
   - Display results

3. **Create Check Point block rules**:
   - Prompt for comment on sender email block
   - Ask if you want to block the domain
   - Prompt for domain block comment
   - Create rules and publish

4. **Netskope URL blocking** (if enabled):
   - Display extracted URLs
   - Allow you to:
     - Accept all URLs as-is
     - Edit the list (add/remove/modify)
     - Skip URL blocking
   - Add URLs to blocklist

5. **Generate report**:
   - Save analysis results to JSON file
   - Saved in `reports/email_analysis_YYYYMMDD_HHMMSS.json`

## Example Workflow

```bash
$ python email_analyzer.py analyze --file phishing.eml

======================================================================
EMAIL ANALYSIS SUMMARY
======================================================================

Subject: Urgent: Verify Your Account
From: "Security Team" <phisher@evil-domain.com>
  └─ Email: phisher@evil-domain.com
  └─ Domain: evil-domain.com
Date: Thu, 17 Oct 2024 10:00:00 -0400

URLs Found (2):
  - https://evil-site.com/verify?token=xyz
  - http://malicious-login.com/account

=== Check Point Analysis ===

[1/3] Searching for emails with same subject...
      Found 3 email(s) with subject: 'Urgent: Verify Your Account'

[2/3] Searching for emails from same sender...
      Found 5 email(s) from: phisher@evil-domain.com

[3/3] Searching for emails sent TO sender (possible victims)...
      Found 2 email(s) sent to: phisher@evil-domain.com
      ⚠ WARNING: Users may have replied to this phishing email!

--- Creating Block Rules ---

Block sender email: phisher@evil-domain.com
Enter comment for blocking 'phisher@evil-domain.com': Phishing campaign - fake security alert
✓ Created sender block rule: Block_phisher@evil-domain.com_20241017_140523

Block sender domain: evil-domain.com
Also block entire domain 'evil-domain.com'? (y/n): y
Enter comment for blocking domain 'evil-domain.com': Known phishing domain
✓ Created domain block rule: Block_Domain_evil-domain.com_20241017_140530

Publishing Check Point configuration...
✓ Configuration published successfully

=== Netskope URL Blocking ===

Extracted URLs (2):
  1. https://evil-site.com/verify?token=xyz
  2. http://malicious-login.com/account

URL Editing:
  - Press ENTER to block all URLs
  - Type 'edit' to modify the list
  - Type 'skip' to skip URL blocking

Your choice: edit

For each URL, type 'y' to include, 'n' to skip, or enter a modified URL:
  https://evil-site.com/verify?token=xyz [y/n/modified]: y
  http://malicious-login.com/account [y/n/modified]: y

Add additional URLs (one per line, empty line to finish):
  https://evil-site.com/


Final URL list (3):
  - https://evil-site.com/verify?token=xyz
  - http://malicious-login.com/account
  - https://evil-site.com/

Blocking URLs in Netskope list: 'Phishing_URLs_Blocklist'...
✓ Successfully blocked 3 URL(s) in Netskope
  List: Phishing_URLs_Blocklist

✓ Analysis report saved: reports/email_analysis_20241017_140535.json

=== Analysis Complete ===
```

## Configuration Options

### Check Point

```yaml
checkpoint:
  enabled: true                          # Enable/disable Check Point integration
  base_url: "https://checkpoint-server"  # Management server URL
  username: "admin"                      # Admin username
  password: "password"                   # Admin password
  api_key: "YOUR_API_KEY"               # Alternative: API key authentication
  lookback_days: 14                      # Days to search email history
```

### Netskope

```yaml
netskope:
  enabled: true                          # Enable/disable Netskope integration
  tenant: "yourcompany"                  # Netskope tenant name
  api_token: "YOUR_API_TOKEN"           # API token with URL list permissions
  blocklist_name: "Phishing_URLs_Blocklist"  # Name of URL list to use/create
```

## File Formats

### Input: .eml Files

Save reported emails as `.eml` files (standard email format). Most email clients support this:

- **Outlook**: File → Save As → Outlook Message Format (.msg) or use "Export"
- **Gmail**: Open email → More (⋮) → Download message
- **Thunderbird**: File → Save As → File

### Output: Analysis Reports

Reports are saved as JSON in `reports/` directory:

```json
{
  "sender": "Phisher <phisher@evil.com>",
  "sender_email": "phisher@evil.com",
  "sender_domain": "evil.com",
  "subject": "Urgent: Verify Your Account",
  "urls": ["https://evil-site.com/verify"],
  "url_domains": ["evil-site.com"],
  "analysis": {
    "timestamp": "2024-10-17T14:05:35",
    "analyst": "Security Team"
  }
}
```

## API Requirements

### Check Point
- **Product**: Check Point Management API (R80.x+)
- **Required permissions**:
  - Read email logs
  - Create anti-spam rules
  - Publish configuration
- **Authentication**: Username/password or API key

### Netskope
- **Product**: Netskope Security Cloud
- **Required permissions**:
  - URL list management (read/write)
  - Policy management (if creating rules)
- **Authentication**: API token

## Troubleshooting

### Check Point Connection Issues
- Verify Management server URL is correct
- Check username/password or API key
- Ensure API access is enabled on the server
- Check network connectivity and firewall rules

### Netskope Connection Issues
- Verify tenant name is correct (not full URL)
- Check API token has URL list permissions
- Test token with: `https://{tenant}.goskope.com/api/v2/policy/urllist`

### Email Parsing Issues
- Ensure .eml file is valid format
- Try opening in an email client first
- Check file encoding (should be UTF-8 or ASCII)

## Logs

All operations are logged to `logs/email_analyzer.log`:
```bash
tail -f logs/email_analyzer.log
```

## Security Considerations

1. **Protect config.yaml** - Contains API credentials
2. **Review URLs before blocking** - Avoid false positives
3. **Check for victims** - Monitor replies to phishing emails
4. **Verify sender domain** - Don't block legitimate domains
5. **Archive email samples** - Keep original .eml files for reference

## Advanced Usage

### Batch Processing

Create a script to process multiple emails:

```bash
#!/bin/bash
for file in samples/*.eml; do
  echo "Processing: $file"
  python email_analyzer.py analyze --file "$file"
  echo "---"
done
```

### Integration with Email Gateway

Forward reported phishing emails automatically:
1. Create a mailbox (e.g., phishing@company.com)
2. Use mail server rules to save emails as .eml
3. Run analyzer on new files
4. Automate with cron or scheduled task

## Support

For issues or questions:
- Check logs in `logs/email_analyzer.log`
- Review API documentation for Check Point and Netskope
- Verify API credentials and permissions

## License

MIT

---

**Version**: 1.0
