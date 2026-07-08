# Email Analyzer - Quick Setup Guide

## Installation

### 1. Install Python Dependencies
```bash
cd EmailAnalyzer
pip install -r requirements.txt
```

### 2. Configure Your Credentials

Edit `config.yaml` and replace with your actual credentials:

#### Check Point Configuration
```yaml
checkpoint:
  enabled: true
  base_url: "https://your-checkpoint-mgmt-server"
  username: "admin"
  password: "your_checkpoint_password"
```

**OR** if using API key:
```yaml
checkpoint:
  enabled: true
  base_url: "https://your-checkpoint-mgmt-server"
  api_key: "your_checkpoint_api_key"
```

#### Netskope Configuration
```yaml
netskope:
  enabled: true
  tenant: "yourcompany"  # Just the tenant name, not full URL
  api_token: "your_netskope_api_token"
  blocklist_name: "Phishing_URLs_Blocklist"
```

### 3. Test Connections
```bash
python email_analyzer.py test
```

Expected output:
```
✓ Check Point: Connected
✓ Netskope: Connected
```

### 4. Test with Sample Email
```bash
python email_analyzer.py analyze --file samples/sample_phishing.eml
```

## Getting API Credentials

### Check Point Management API

**Option 1: Username/Password**
- Use your existing admin credentials
- URL format: `https://<mgmt-server-ip>`

**Option 2: API Key (Recommended)**
1. Log into Check Point SmartConsole
2. Go to: Manage & Settings → Blades → Management API
3. Click "Advanced Settings"
4. Generate new API key
5. Copy the API key to config.yaml

**Required Permissions:**
- Email logs: Read
- Anti-Spam rules: Create, Modify
- Configuration: Publish

### Netskope API Token

1. Log into Netskope tenant as admin
2. Go to: Settings → Tools → REST API v2
3. Click "New Token"
4. Select scopes:
   - `/api/v2/policy/urllist` (read, write)
   - `/api/v2/policy/rules` (read, write)
5. Generate and copy token
6. Tenant name is the subdomain (e.g., `yourcompany` from `yourcompany.goskope.com`)

## Usage Examples

### Analyze a Phishing Email
```bash
# From .eml file (recommended)
python email_analyzer.py analyze --file /path/to/phishing_email.eml

# From raw text
python email_analyzer.py analyze --text "From: phisher@evil.com..."
```

### Interactive Workflow

The tool will:
1. Parse and display email details
2. Query Check Point for related emails (same subject, sender, replies)
3. Prompt you for block rule comments
4. Ask if you want to block the domain
5. Display extracted URLs
6. Let you edit URL list
7. Block URLs in Netskope
8. Generate JSON report

## Saving Emails as .eml Files

### Outlook
1. Open the email
2. File → Save As
3. Choose format: "Outlook Message Format (*.msg)" or export as .eml

### Gmail
1. Open the email
2. Click More (⋮)
3. Click "Download message"
4. File downloads as .eml

### Thunderbird
1. Right-click the email
2. "Save As" → Choose location
3. File saves as .eml

## Troubleshooting

### "Check Point: Connection failed"
- Verify base_url is correct (https://<server>)
- Check username/password or API key
- Ensure Management API is enabled
- Check firewall allows connection

### "Netskope: Connection failed"
- Verify tenant name is correct (not full URL)
- Check API token is valid
- Test manually: `curl -H "Netskope-API-Token: YOUR_TOKEN" https://YOUR_TENANT.goskope.com/api/v2/policy/urllist`

### Email parsing errors
- Ensure file is valid .eml format
- Try opening in email client first
- Check file isn't corrupted

## Advanced Configuration

### Disable a Service
```yaml
checkpoint:
  enabled: false  # Skips Check Point integration

netskope:
  enabled: false  # Skips Netskope integration
```

### Custom Blocklist Name
```yaml
netskope:
  blocklist_name: "My_Custom_Phishing_List"
```

### Adjust Email Search Timeframe
```yaml
checkpoint:
  lookback_days: 30  # Search last 30 days instead of 14
```

## File Locations

- **Config**: `config.yaml`
- **Logs**: `logs/email_analyzer.log`
- **Reports**: `reports/email_analysis_*.json`
- **Samples**: `samples/*.eml`

## Security Notes

1. **Protect config.yaml** - Contains sensitive API credentials
2. **Review before blocking** - Always verify URLs/domains before creating rules
3. **Check for victims** - Look for replies to phishing emails
4. **Keep samples** - Archive .eml files for evidence
5. **Restrict access** - Only authorized security personnel

## Next Steps

1. Test with the sample email
2. Process a real reported phishing email
3. Verify block rules are created correctly
4. Set up automated workflow (optional)

## Support

Check logs for detailed error messages:
```bash
tail -f logs/email_analyzer.log
```

---

**Quick Reference:**
- Test: `python email_analyzer.py test`
- Analyze: `python email_analyzer.py analyze --file <path>`
- Logs: `logs/email_analyzer.log`
- Reports: `reports/`
