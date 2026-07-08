#!/usr/bin/env python3
"""
Email Analyzer and Threat Response Tool
Analyzes reported phishing emails and creates block rules in Check Point and Netskope
"""

import argparse
import sys
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict
import yaml
import json

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/email_analyzer.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class EmailAnalyzerCLI:
    """Main CLI application for email analysis and threat response"""

    def __init__(self, config_path='config.yaml'):
        """Initialize CLI with configuration"""
        self.config_path = config_path
        self.config = self.load_config()

        # Ensure directories exist
        Path('logs').mkdir(exist_ok=True)
        Path('reports').mkdir(exist_ok=True)
        Path('samples').mkdir(exist_ok=True)

    def load_config(self):
        """Load configuration from YAML"""
        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
            logger.info(f"Loaded configuration from {self.config_path}")
            return config
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            sys.exit(1)

    def analyze_email(self, email_path: str = None, email_text: str = None):
        """
        Analyze a reported phishing email and take response actions

        Args:
            email_path: Path to .eml file
            email_text: Raw email text
        """
        from core.email_parser import EmailParser

        logger.info("=== Starting Email Analysis ===")

        # Parse email
        parser = EmailParser()

        if email_path:
            logger.info(f"Parsing email file: {email_path}")
            email_data = parser.parse_eml_file(email_path)
        elif email_text:
            logger.info("Parsing raw email text")
            email_data = parser.parse_raw_email(email_text)
        else:
            logger.error("No email provided")
            return False

        # Display extracted information
        self._display_email_summary(email_data)

        # Perform Check Point queries and actions
        if self.config.get('checkpoint', {}).get('enabled', False):
            logger.info("\n=== Check Point Analysis ===")
            self._checkpoint_analysis(email_data)
        else:
            logger.info("Check Point integration disabled")

        # Perform Netskope URL blocking
        if self.config.get('netskope', {}).get('enabled', False):
            logger.info("\n=== Netskope URL Blocking ===")
            self._netskope_blocking(email_data)
        else:
            logger.info("Netskope integration disabled")

        # Generate report
        self._generate_report(email_data)

        logger.info("=== Analysis Complete ===")
        return True

    def _display_email_summary(self, email_data: Dict):
        """Display extracted email information"""
        print(f"\n{'='*70}")
        print(f"EMAIL ANALYSIS SUMMARY")
        print(f"{'='*70}\n")

        print(f"Subject: {email_data['subject']}")
        print(f"From: {email_data['sender']}")
        print(f"  └─ Email: {email_data['sender_email']}")
        print(f"  └─ Domain: {email_data['sender_domain']}")
        print(f"Date: {email_data['date']}")
        print(f"Message-ID: {email_data['message_id']}\n")

        print(f"Recipients ({len(email_data['recipients'])}):")
        for recipient in email_data['recipients'][:5]:
            print(f"  - {recipient}")
        if len(email_data['recipients']) > 5:
            print(f"  ... and {len(email_data['recipients']) - 5} more\n")

        print(f"URLs Found ({len(email_data['urls'])}):")
        for url in email_data['unique_urls']:
            print(f"  - {url}")

        if email_data['url_domains']:
            print(f"\nURL Domains:")
            for domain in email_data['url_domains']:
                print(f"  - {domain}")

        if email_data['embedded_emails']:
            print(f"\nEmbedded Email Addresses:")
            for email_addr in email_data['embedded_emails']:
                print(f"  - {email_addr}")

        if email_data['attachments']:
            print(f"\nAttachments ({len(email_data['attachments'])}):")
            for att in email_data['attachments']:
                print(f"  - {att['filename']} ({att['content_type']}, {att['size']} bytes)")

        print(f"\nBody Preview:")
        print(f"{email_data['body_preview']}")
        print(f"\n{'='*70}\n")

    def _checkpoint_analysis(self, email_data: Dict):
        """Perform Check Point queries and create block rules"""
        from connectors.checkpoint import CheckPointConnector

        try:
            connector = CheckPointConnector(self.config['checkpoint'])

            if not connector.test_connection():
                logger.error("Failed to connect to Check Point")
                return

            sender_email = email_data['sender_email']
            sender_domain = email_data['sender_domain']
            subject = email_data['subject']

            # Query 1: Emails with same subject
            print(f"\n[1/3] Searching for emails with same subject...")
            same_subject = connector.search_emails_by_subject(subject, days_back=14)
            print(f"      Found {len(same_subject)} email(s) with subject: '{subject}'")

            if same_subject:
                print(f"      Recent matches:")
                for email in same_subject[:5]:
                    print(f"        - {email.get('date')} | From: {email.get('from')} | To: {email.get('to')}")
                if len(same_subject) > 5:
                    print(f"        ... and {len(same_subject) - 5} more")

            # Query 2: Emails from same sender
            print(f"\n[2/3] Searching for emails from same sender...")
            from_sender = connector.search_emails_by_sender(sender_email, days_back=14)
            print(f"      Found {len(from_sender)} email(s) from: {sender_email}")

            if from_sender:
                print(f"      Recent matches:")
                for email in from_sender[:5]:
                    print(f"        - {email.get('date')} | Subject: {email.get('subject')}")
                if len(from_sender) > 5:
                    print(f"        ... and {len(from_sender) - 5} more")

            # Query 3: Emails sent TO sender (replies)
            print(f"\n[3/3] Searching for emails sent TO sender (possible victims)...")
            to_sender = connector.search_emails_to_sender(sender_email, days_back=14)
            print(f"      Found {len(to_sender)} email(s) sent to: {sender_email}")

            if to_sender:
                print(f"      ⚠ WARNING: Users may have replied to this phishing email!")
                print(f"      Possible victims:")
                for email in to_sender[:5]:
                    print(f"        - {email.get('date')} | From: {email.get('from')}")
                if len(to_sender) > 5:
                    print(f"        ... and {len(to_sender) - 5} more")

            # === ACTION CONFIRMATION SECTION ===
            print(f"\n{'='*70}")
            print(f"PROPOSED ACTIONS - PLEASE REVIEW")
            print(f"{'='*70}\n")

            actions_to_take = []

            # 1. Quarantine emails with same subject
            if same_subject:
                print(f"[Action 1] Quarantine {len(same_subject)} email(s) with subject: '{subject}'")
                quarantine_confirm = input(f"  Proceed with quarantine? (y/n): ").strip().lower()
                if quarantine_confirm == 'y':
                    quarantine_comment = input(f"  Enter quarantine reason: ").strip()
                    if not quarantine_comment:
                        quarantine_comment = f"Phishing - subject match: {subject}"
                    actions_to_take.append(('quarantine', {
                        'subject': subject,
                        'comment': quarantine_comment,
                        'count': len(same_subject)
                    }))
                else:
                    print(f"  Skipped quarantine")

            # 2. Block sender email
            print(f"\n[Action 2] Block sender email: {sender_email}")
            block_email_confirm = input(f"  Proceed with email block? (y/n): ").strip().lower()
            if block_email_confirm == 'y':
                email_comment = input(f"  Enter block comment: ").strip()
                if not email_comment:
                    email_comment = f"Phishing email reported on {datetime.now().strftime('%Y-%m-%d')}"
                actions_to_take.append(('block_email', {
                    'email': sender_email,
                    'domain': sender_domain,
                    'comment': email_comment
                }))
            else:
                print(f"  Skipped email block")

            # 3. Block sender domain
            print(f"\n[Action 3] Block entire domain: {sender_domain}")
            block_domain_confirm = input(f"  Proceed with domain block? (y/n): ").strip().lower()
            if block_domain_confirm == 'y':
                domain_comment = input(f"  Enter domain block comment: ").strip()
                if not domain_comment:
                    domain_comment = f"Phishing domain - reported on {datetime.now().strftime('%Y-%m-%d')}"
                actions_to_take.append(('block_domain', {
                    'domain': sender_domain,
                    'comment': domain_comment
                }))
            else:
                print(f"  Skipped domain block")

            # Final confirmation
            if not actions_to_take:
                print(f"\nNo actions selected. Exiting Check Point workflow.")
                connector.logout()
                return

            print(f"\n{'='*70}")
            print(f"FINAL CONFIRMATION")
            print(f"{'='*70}")
            print(f"\nYou are about to perform {len(actions_to_take)} action(s):")
            for i, (action_type, action_data) in enumerate(actions_to_take, 1):
                if action_type == 'quarantine':
                    print(f"  {i}. Quarantine {action_data['count']} email(s)")
                elif action_type == 'block_email':
                    print(f"  {i}. Block email: {action_data['email']}")
                elif action_type == 'block_domain':
                    print(f"  {i}. Block domain: {action_data['domain']}")

            final_confirm = input(f"\nExecute all actions? (yes/no): ").strip().lower()
            if final_confirm != 'yes':
                print(f"\nActions cancelled by user.")
                connector.logout()
                return

            # Execute approved actions
            print(f"\n{'='*70}")
            print(f"EXECUTING ACTIONS")
            print(f"{'='*70}\n")

            results = []

            for action_type, action_data in actions_to_take:
                if action_type == 'quarantine':
                    print(f"Quarantining emails with subject '{action_data['subject']}'...")
                    result = connector.quarantine_emails_by_subject(
                        subject=action_data['subject'],
                        days_back=14,
                        comment=action_data['comment']
                    )
                    if result.get('success'):
                        print(f"✓ Quarantined {result['emails_quarantined']} email(s)")
                    else:
                        print(f"✗ Quarantine failed: {result.get('error')}")
                    results.append(result)

                elif action_type == 'block_email':
                    print(f"Blocking sender email '{action_data['email']}'...")
                    result = connector.create_sender_block_rule(
                        sender_email=action_data['email'],
                        sender_domain=action_data['domain'],
                        comment=action_data['comment']
                    )
                    if result.get('success'):
                        print(f"✓ Created sender block rule: {result['rule_name']}")
                    else:
                        print(f"✗ Block rule failed: {result.get('error')}")
                    results.append(result)

                elif action_type == 'block_domain':
                    print(f"Blocking domain '{action_data['domain']}'...")
                    result = connector.create_domain_block_rule(
                        domain=action_data['domain'],
                        comment=action_data['comment']
                    )
                    if result.get('success'):
                        print(f"✓ Created domain block rule: {result['rule_name']}")
                    else:
                        print(f"✗ Domain block failed: {result.get('error')}")
                    results.append(result)

            # Publish changes if any rules were created
            if any(r.get('success') for r in results):
                print(f"\nPublishing Check Point configuration...")
                if connector.publish_changes():
                    print(f"✓ Configuration published successfully")
                else:
                    print(f"✗ Failed to publish configuration")

            connector.logout()

        except Exception as e:
            logger.error(f"Error in Check Point analysis: {e}")

    def _netskope_blocking(self, email_data: Dict):
        """Block URLs in Netskope"""
        from connectors.netskope import NetskopeConnector

        try:
            connector = NetskopeConnector(self.config['netskope'])

            if not connector.test_connection():
                logger.error("Failed to connect to Netskope")
                return

            urls = email_data['unique_urls']

            if not urls:
                print("No URLs found in email - skipping Netskope blocking")
                return

            print(f"\nExtracted URLs ({len(urls)}):")
            for i, url in enumerate(urls, 1):
                print(f"  {i}. {url}")

            # Allow user to edit URL list
            print(f"\nURL Editing:")
            print(f"  - Press ENTER to block all URLs")
            print(f"  - Type 'edit' to modify the list")
            print(f"  - Type 'skip' to skip URL blocking")

            user_choice = input(f"\nYour choice: ").strip().lower()

            if user_choice == 'skip':
                print("Skipping URL blocking")
                return

            if user_choice == 'edit':
                # Interactive editing
                final_urls = []
                print(f"\nFor each URL, type 'y' to include, 'n' to skip, or enter a modified URL:")

                for url in urls:
                    response = input(f"  {url} [y/n/modified]: ").strip()

                    if response.lower() == 'y':
                        final_urls.append(url)
                    elif response.lower() == 'n':
                        continue
                    else:
                        # User provided modified URL
                        if response:
                            final_urls.append(response)

                # Allow adding new URLs
                print(f"\nAdd additional URLs (one per line, empty line to finish):")
                while True:
                    new_url = input("  ").strip()
                    if not new_url:
                        break
                    final_urls.append(new_url)

                urls = final_urls

            if not urls:
                print("No URLs selected for blocking")
                return

            print(f"\nFinal URL list ({len(urls)}):")
            for url in urls:
                print(f"  - {url}")

            # Confirm before blocking
            list_name = self.config.get('netskope', {}).get('blocklist_name', 'Phishing_URLs_Blocklist')
            print(f"\n{'='*70}")
            print(f"NETSKOPE BLOCK CONFIRMATION")
            print(f"{'='*70}")
            print(f"You are about to block {len(urls)} URL(s) in Netskope list: '{list_name}'")

            final_confirm = input(f"\nProceed with URL blocking? (yes/no): ").strip().lower()
            if final_confirm != 'yes':
                print(f"\nURL blocking cancelled by user.")
                return

            # Block URLs
            print(f"\nBlocking URLs in Netskope list: '{list_name}'...")

            result = connector.block_urls_simple(urls, list_name)

            if result.get('success'):
                print(f"✓ Successfully blocked {len(urls)} URL(s) in Netskope")
                print(f"  List: {list_name}")
                if result.get('list_id'):
                    print(f"  List ID: {result['list_id']}")
            else:
                print(f"✗ Failed to block URLs: {result.get('error')}")

        except Exception as e:
            logger.error(f"Error in Netskope blocking: {e}")

    def _generate_report(self, email_data: Dict):
        """Generate analysis report"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            report_file = f"reports/email_analysis_{timestamp}.json"

            # Add analysis metadata
            email_data['analysis'] = {
                'timestamp': datetime.now().isoformat(),
                'analyst': self.config.get('general', {}).get('analyst_name', 'Unknown')
            }

            with open(report_file, 'w') as f:
                json.dump(email_data, f, indent=2)

            logger.info(f"Report saved: {report_file}")
            print(f"\n✓ Analysis report saved: {report_file}")

        except Exception as e:
            logger.error(f"Error generating report: {e}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Email Analyzer and Threat Response Tool')
    parser.add_argument('--config', default='config.yaml', help='Configuration file path')

    subparsers = parser.add_subparsers(dest='command', help='Command to execute')

    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze a phishing email')
    analyze_parser.add_argument('--file', help='Path to .eml file')
    analyze_parser.add_argument('--text', help='Raw email text')

    # Test command
    test_parser = subparsers.add_parser('test', help='Test API connections')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Initialize CLI
    cli = EmailAnalyzerCLI(args.config)

    # Execute command
    try:
        if args.command == 'analyze':
            if not args.file and not args.text:
                print("Error: Must provide --file or --text")
                sys.exit(1)

            cli.analyze_email(email_path=args.file, email_text=args.text)

        elif args.command == 'test':
            print("Testing API connections...\n")

            # Test Check Point
            if cli.config.get('checkpoint', {}).get('enabled'):
                from connectors.checkpoint import CheckPointConnector
                cp = CheckPointConnector(cli.config['checkpoint'])
                if cp.test_connection():
                    print("✓ Check Point: Connected")
                else:
                    print("✗ Check Point: Connection failed")

            # Test Netskope
            if cli.config.get('netskope', {}).get('enabled'):
                from connectors.netskope import NetskopeConnector
                ns = NetskopeConnector(cli.config['netskope'])
                if ns.test_connection():
                    print("✓ Netskope: Connected")
                else:
                    print("✗ Netskope: Connection failed")

    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
