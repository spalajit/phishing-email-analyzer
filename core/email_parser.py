"""
Email Parser Module
Extracts key information from email files (.eml, .msg) or raw email text
"""

import re
import email
from email import policy
from email.parser import BytesParser
from typing import List, Dict, Optional, Tuple
import logging

logger = logging.getLogger(__name__)


class EmailParser:
    """Parse and extract information from email messages"""

    def __init__(self):
        """Initialize email parser"""
        self.url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        )
        self.email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')

    def parse_eml_file(self, file_path: str) -> Dict:
        """
        Parse .eml file and extract information

        Args:
            file_path: Path to .eml file

        Returns:
            Dictionary with extracted information
        """
        try:
            with open(file_path, 'rb') as f:
                msg = BytesParser(policy=policy.default).parse(f)

            return self._extract_from_message(msg)

        except Exception as e:
            logger.error(f"Error parsing EML file: {e}")
            raise

    def parse_raw_email(self, email_text: str) -> Dict:
        """
        Parse raw email text and extract information

        Args:
            email_text: Raw email text (including headers)

        Returns:
            Dictionary with extracted information
        """
        try:
            msg = email.message_from_string(email_text, policy=policy.default)
            return self._extract_from_message(msg)

        except Exception as e:
            logger.error(f"Error parsing raw email: {e}")
            raise

    def _extract_from_message(self, msg) -> Dict:
        """
        Extract key information from email message object

        Args:
            msg: email.message.Message object

        Returns:
            Dictionary with extracted data
        """
        # Extract headers
        sender = self._extract_sender(msg)
        recipients = self._extract_recipients(msg)
        subject = msg.get('Subject', '').strip()
        date = msg.get('Date', '').strip()
        message_id = msg.get('Message-ID', '').strip()

        # Extract body
        body = self._extract_body(msg)

        # Extract URLs from body and headers
        urls = self._extract_urls(body, msg)

        # Extract email addresses from body (for forwarded emails)
        embedded_emails = self._extract_emails_from_body(body)

        # Extract attachments info
        attachments = self._extract_attachments(msg)

        result = {
            'sender': sender,
            'sender_email': self._extract_email_address(sender),
            'sender_domain': self._extract_domain(sender),
            'recipients': recipients,
            'subject': subject,
            'date': date,
            'message_id': message_id,
            'body': body,
            'body_preview': body[:500] if body else '',
            'urls': urls,
            'unique_urls': list(set(urls)),
            'url_domains': list(set(self._extract_domain(url) for url in urls)),
            'embedded_emails': embedded_emails,
            'attachments': attachments,
            'has_attachments': len(attachments) > 0
        }

        logger.info(f"Parsed email: Subject='{subject}', Sender={sender}, URLs={len(urls)}")
        return result

    def _extract_sender(self, msg) -> str:
        """Extract sender from email"""
        from_header = msg.get('From', '')
        return str(from_header).strip()

    def _extract_recipients(self, msg) -> List[str]:
        """Extract all recipients (To, Cc, Bcc)"""
        recipients = []

        for header in ['To', 'Cc', 'Bcc']:
            value = msg.get(header, '')
            if value:
                # Split by comma and clean up
                addrs = [addr.strip() for addr in str(value).split(',')]
                recipients.extend(addrs)

        return recipients

    def _extract_body(self, msg) -> str:
        """Extract email body (plain text or HTML)"""
        body = ''

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get('Content-Disposition', ''))

                # Skip attachments
                if 'attachment' in content_disposition:
                    continue

                # Get text/plain first, fall back to text/html
                if content_type == 'text/plain':
                    try:
                        body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                        break
                    except:
                        pass
                elif content_type == 'text/html' and not body:
                    try:
                        body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    except:
                        pass
        else:
            # Not multipart - get payload directly
            try:
                body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
            except:
                body = str(msg.get_payload())

        return body.strip()

    def _extract_urls(self, body: str, msg) -> List[str]:
        """Extract all URLs from email body and headers"""
        urls = []

        # Extract from body
        if body:
            urls.extend(self.url_pattern.findall(body))

        # Also check common headers that might contain URLs
        for header in ['List-Unsubscribe', 'List-Subscribe']:
            value = msg.get(header, '')
            if value:
                urls.extend(self.url_pattern.findall(str(value)))

        return urls

    def _extract_emails_from_body(self, body: str) -> List[str]:
        """Extract email addresses from body (useful for forwarded emails)"""
        if not body:
            return []

        emails = self.email_pattern.findall(body)
        return list(set(emails))

    def _extract_attachments(self, msg) -> List[Dict]:
        """Extract attachment information"""
        attachments = []

        if msg.is_multipart():
            for part in msg.walk():
                content_disposition = str(part.get('Content-Disposition', ''))

                if 'attachment' in content_disposition:
                    filename = part.get_filename()
                    content_type = part.get_content_type()

                    attachments.append({
                        'filename': filename or 'unknown',
                        'content_type': content_type,
                        'size': len(part.get_payload(decode=True) or b'')
                    })

        return attachments

    def _extract_email_address(self, from_header: str) -> str:
        """
        Extract just the email address from a From header
        Example: "John Doe <john@example.com>" -> "john@example.com"
        """
        match = self.email_pattern.search(from_header)
        return match.group(0) if match else from_header.strip()

    def _extract_domain(self, email_or_url: str) -> str:
        """
        Extract domain from email address or URL
        Examples:
            john@example.com -> example.com
            https://evil.com/path -> evil.com
        """
        if not email_or_url:
            return ''

        # Check if it's a URL
        if email_or_url.startswith('http'):
            try:
                from urllib.parse import urlparse
                parsed = urlparse(email_or_url)
                return parsed.netloc
            except:
                return ''

        # Check if it's an email
        if '@' in email_or_url:
            # Extract email first if it has display name
            email_addr = self._extract_email_address(email_or_url)
            parts = email_addr.split('@')
            return parts[1] if len(parts) > 1 else ''

        return ''

    def extract_display_name(self, from_header: str) -> str:
        """
        Extract display name from From header
        Example: "John Doe <john@example.com>" -> "John Doe"
        """
        if '<' in from_header:
            return from_header.split('<')[0].strip().strip('"')
        return ''


# Example usage
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)

    parser = EmailParser()

    # Example: Parse a sample email
    sample_email = """From: Phisher <phisher@evil.com>
To: victim@company.com
Subject: Urgent: Verify Your Account
Date: Thu, 17 Oct 2024 10:00:00 -0400
Message-ID: <abc123@evil.com>

Dear User,

Your account will be suspended unless you verify immediately:
Click here: https://evil-site.com/verify?token=xyz123

Also visit: http://another-bad-site.com/login

Thanks,
Support Team
support@evil.com
"""

    result = parser.parse_raw_email(sample_email)

    print("\n=== Email Analysis ===")
    print(f"Sender: {result['sender']}")
    print(f"Sender Email: {result['sender_email']}")
    print(f"Sender Domain: {result['sender_domain']}")
    print(f"Subject: {result['subject']}")
    print(f"URLs Found: {len(result['urls'])}")
    for url in result['unique_urls']:
        print(f"  - {url}")
    print(f"URL Domains: {result['url_domains']}")
    print(f"Embedded Emails: {result['embedded_emails']}")
