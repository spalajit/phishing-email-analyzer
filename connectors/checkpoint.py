"""
Check Point Email Security Connector
Queries email logs and creates block rules
"""

import requests
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import json

logger = logging.getLogger(__name__)


class CheckPointConnector:
    """Connector for Check Point Email Security API"""

    def __init__(self, config: Dict):
        """
        Initialize Check Point connector

        Args:
            config: Configuration dictionary with API credentials
        """
        self.base_url = config.get('base_url', '').rstrip('/')
        self.api_key = config.get('api_key')
        self.username = config.get('username')
        self.password = config.get('password')

        # Session management
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })

        # Authentication method depends on Check Point product
        # This example uses API key, but could also use username/password
        if self.api_key:
            self.session.headers.update({
                'X-API-Key': self.api_key
            })

        self.session_id = None

    def login(self) -> bool:
        """
        Login to Check Point API (if using session-based auth)

        Returns:
            True if login successful
        """
        try:
            # Check Point Management API login
            if self.username and self.password:
                payload = {
                    'user': self.username,
                    'password': self.password
                }

                response = self.session.post(
                    f'{self.base_url}/web_api/login',
                    json=payload
                )
                response.raise_for_status()

                data = response.json()
                self.session_id = data.get('sid')

                # Update headers with session ID
                self.session.headers.update({
                    'X-chkp-sid': self.session_id
                })

                logger.info("Check Point login successful")
                return True

            return True  # API key mode doesn't need login

        except Exception as e:
            logger.error(f"Check Point login failed: {e}")
            return False

    def logout(self):
        """Logout from Check Point API"""
        try:
            if self.session_id:
                self.session.post(
                    f'{self.base_url}/web_api/logout',
                    json={}
                )
                logger.info("Check Point logout successful")
        except Exception as e:
            logger.warning(f"Check Point logout failed: {e}")

    def test_connection(self) -> bool:
        """
        Test API connection

        Returns:
            True if connection successful
        """
        try:
            # Attempt login if needed
            if self.username and self.password:
                return self.login()

            # Otherwise test a simple API call
            response = self.session.get(f'{self.base_url}/web_api/show-session')
            return response.status_code == 200

        except Exception as e:
            logger.error(f"Check Point connection test failed: {e}")
            return False

    def search_emails_by_subject(
        self,
        subject: str,
        days_back: int = 14
    ) -> List[Dict]:
        """
        Search for emails with the same subject line

        Args:
            subject: Subject line to search for
            days_back: Number of days to look back

        Returns:
            List of matching emails
        """
        try:
            start_date = datetime.now() - timedelta(days=days_back)

            # Check Point email log query
            # NOTE: Actual API endpoint depends on Check Point product
            # (Harmony Email, Anti-Spam & Email Security, etc.)
            payload = {
                'time-frame': {
                    'from': start_date.isoformat(),
                    'to': datetime.now().isoformat()
                },
                'filter': {
                    'subject': subject
                },
                'limit': 1000
            }

            response = self.session.post(
                f'{self.base_url}/api/v1/email/search',
                json=payload
            )
            response.raise_for_status()

            data = response.json()
            emails = data.get('results', [])

            logger.info(f"Found {len(emails)} emails with subject '{subject}' in last {days_back} days")
            return emails

        except Exception as e:
            logger.error(f"Error searching emails by subject: {e}")
            return []

    def search_emails_by_sender(
        self,
        sender_email: str,
        days_back: int = 14
    ) -> List[Dict]:
        """
        Search for emails from the same sender

        Args:
            sender_email: Sender email address
            days_back: Number of days to look back

        Returns:
            List of matching emails
        """
        try:
            start_date = datetime.now() - timedelta(days=days_back)

            payload = {
                'time-frame': {
                    'from': start_date.isoformat(),
                    'to': datetime.now().isoformat()
                },
                'filter': {
                    'from': sender_email
                },
                'limit': 1000
            }

            response = self.session.post(
                f'{self.base_url}/api/v1/email/search',
                json=payload
            )
            response.raise_for_status()

            data = response.json()
            emails = data.get('results', [])

            logger.info(f"Found {len(emails)} emails from '{sender_email}' in last {days_back} days")
            return emails

        except Exception as e:
            logger.error(f"Error searching emails by sender: {e}")
            return []

    def search_emails_to_sender(
        self,
        sender_email: str,
        days_back: int = 14
    ) -> List[Dict]:
        """
        Search for emails sent TO the sender (replies to phisher)

        Args:
            sender_email: Email address to search in recipients
            days_back: Number of days to look back

        Returns:
            List of matching emails
        """
        try:
            start_date = datetime.now() - timedelta(days=days_back)

            payload = {
                'time-frame': {
                    'from': start_date.isoformat(),
                    'to': datetime.now().isoformat()
                },
                'filter': {
                    'to': sender_email
                },
                'limit': 1000
            }

            response = self.session.post(
                f'{self.base_url}/api/v1/email/search',
                json=payload
            )
            response.raise_for_status()

            data = response.json()
            emails = data.get('results', [])

            logger.info(f"Found {len(emails)} emails sent TO '{sender_email}' in last {days_back} days")
            return emails

        except Exception as e:
            logger.error(f"Error searching emails to sender: {e}")
            return []

    def create_sender_block_rule(
        self,
        sender_email: str,
        sender_domain: str,
        comment: str,
        rule_name: Optional[str] = None
    ) -> Dict:
        """
        Create a block rule for sender email address

        Args:
            sender_email: Email address to block
            sender_domain: Domain to optionally block
            comment: Comment/reason for blocking
            rule_name: Optional rule name

        Returns:
            Dictionary with rule creation result
        """
        try:
            if not rule_name:
                rule_name = f"Block_{sender_email}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

            # Check Point Anti-Spam rule creation
            payload = {
                'name': rule_name,
                'type': 'sender-block',
                'sender': {
                    'email': sender_email,
                    'domain': sender_domain
                },
                'action': 'block',
                'comments': comment,
                'enabled': True
            }

            response = self.session.post(
                f'{self.base_url}/web_api/add-anti-spam-rule',
                json=payload
            )
            response.raise_for_status()

            result = response.json()

            logger.info(f"Created sender block rule: {rule_name}")
            return {
                'success': True,
                'rule_name': rule_name,
                'rule_id': result.get('uid'),
                'sender_email': sender_email,
                'comment': comment
            }

        except Exception as e:
            logger.error(f"Error creating sender block rule: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def create_domain_block_rule(
        self,
        domain: str,
        comment: str,
        rule_name: Optional[str] = None
    ) -> Dict:
        """
        Create a block rule for entire domain

        Args:
            domain: Domain to block
            comment: Comment/reason for blocking
            rule_name: Optional rule name

        Returns:
            Dictionary with rule creation result
        """
        try:
            if not rule_name:
                rule_name = f"Block_Domain_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

            payload = {
                'name': rule_name,
                'type': 'domain-block',
                'domain': domain,
                'action': 'block',
                'comments': comment,
                'enabled': True
            }

            response = self.session.post(
                f'{self.base_url}/web_api/add-anti-spam-rule',
                json=payload
            )
            response.raise_for_status()

            result = response.json()

            logger.info(f"Created domain block rule: {rule_name}")
            return {
                'success': True,
                'rule_name': rule_name,
                'rule_id': result.get('uid'),
                'domain': domain,
                'comment': comment
            }

        except Exception as e:
            logger.error(f"Error creating domain block rule: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def quarantine_emails_by_subject(
        self,
        subject: str,
        days_back: int = 14,
        comment: Optional[str] = None
    ) -> Dict:
        """
        Quarantine all emails with matching subject line

        Args:
            subject: Subject line to match
            days_back: Number of days to look back
            comment: Optional comment/reason

        Returns:
            Dictionary with quarantine result
        """
        try:
            # First, search for matching emails
            emails = self.search_emails_by_subject(subject, days_back)

            if not emails:
                logger.info(f"No emails found to quarantine with subject: '{subject}'")
                return {
                    'success': True,
                    'emails_found': 0,
                    'emails_quarantined': 0,
                    'message': 'No matching emails found'
                }

            # Get email IDs or message IDs
            email_ids = [email.get('id') or email.get('message_id') for email in emails]
            email_ids = [eid for eid in email_ids if eid]  # Filter out None values

            if not email_ids:
                logger.warning("Found emails but couldn't extract IDs for quarantine")
                return {
                    'success': False,
                    'error': 'Could not extract email IDs'
                }

            # Quarantine emails
            # API endpoint varies by Check Point product
            payload = {
                'email_ids': email_ids,
                'action': 'quarantine',
                'reason': comment or f"Phishing - subject match: {subject}",
                'timestamp': datetime.now().isoformat()
            }

            response = self.session.post(
                f'{self.base_url}/api/v1/email/quarantine',
                json=payload
            )
            response.raise_for_status()

            result = response.json()
            quarantined_count = result.get('quarantined_count', len(email_ids))

            logger.info(f"Quarantined {quarantined_count} email(s) with subject '{subject}'")
            return {
                'success': True,
                'emails_found': len(emails),
                'emails_quarantined': quarantined_count,
                'email_ids': email_ids,
                'subject': subject
            }

        except Exception as e:
            logger.error(f"Error quarantining emails: {e}")
            return {
                'success': False,
                'error': str(e),
                'emails_found': len(emails) if 'emails' in locals() else 0
            }

    def quarantine_emails_by_ids(
        self,
        email_ids: List[str],
        reason: Optional[str] = None
    ) -> Dict:
        """
        Quarantine specific emails by their IDs

        Args:
            email_ids: List of email IDs to quarantine
            reason: Optional reason for quarantine

        Returns:
            Dictionary with quarantine result
        """
        try:
            payload = {
                'email_ids': email_ids,
                'action': 'quarantine',
                'reason': reason or 'Phishing email - manual quarantine',
                'timestamp': datetime.now().isoformat()
            }

            response = self.session.post(
                f'{self.base_url}/api/v1/email/quarantine',
                json=payload
            )
            response.raise_for_status()

            result = response.json()
            quarantined_count = result.get('quarantined_count', len(email_ids))

            logger.info(f"Quarantined {quarantined_count} email(s) by ID")
            return {
                'success': True,
                'emails_quarantined': quarantined_count,
                'email_ids': email_ids
            }

        except Exception as e:
            logger.error(f"Error quarantining emails by ID: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def publish_changes(self) -> bool:
        """
        Publish configuration changes (required for Check Point)

        Returns:
            True if publish successful
        """
        try:
            response = self.session.post(
                f'{self.base_url}/web_api/publish',
                json={}
            )
            response.raise_for_status()

            logger.info("Published Check Point configuration changes")
            return True

        except Exception as e:
            logger.error(f"Error publishing changes: {e}")
            return False


# Example usage
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)

    config = {
        'base_url': 'https://your-checkpoint-server',
        'username': 'admin',
        'password': 'your_password'
    }

    connector = CheckPointConnector(config)

    if connector.test_connection():
        print("✓ Connected to Check Point")

        # Search examples
        emails = connector.search_emails_by_sender('phisher@evil.com', days_back=14)
        print(f"Found {len(emails)} emails from phisher")

        # Create block rule
        result = connector.create_sender_block_rule(
            sender_email='phisher@evil.com',
            sender_domain='evil.com',
            comment='Reported phishing email - blocking sender'
        )
        print(f"Block rule created: {result}")

        # Publish changes
        connector.publish_changes()
        connector.logout()
    else:
        print("✗ Connection failed")
