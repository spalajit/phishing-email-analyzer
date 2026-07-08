"""
Netskope Connector for URL Blocking
Creates URL block rules in Netskope security policy
"""

import requests
import logging
from typing import List, Dict, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class NetskopeConnector:
    """Connector for Netskope API - URL List Management"""

    def __init__(self, config: Dict):
        """
        Initialize Netskope connector

        Args:
            config: Configuration dictionary
        """
        self.tenant = config.get('tenant')  # e.g., 'yourcompany'
        self.api_token = config.get('api_token')
        self.base_url = f"https://{self.tenant}.goskope.com"

        self.session = requests.Session()
        self.session.headers.update({
            'Netskope-API-Token': self.api_token,
            'Content-Type': 'application/json'
        })

    def test_connection(self) -> bool:
        """
        Test API connection

        Returns:
            True if connection successful
        """
        try:
            # Test with a simple API call
            response = self.session.get(
                f'{self.base_url}/api/v2/policy/urllist',
                params={'limit': 1}
            )
            response.raise_for_status()

            logger.info("Netskope connection test successful")
            return True

        except Exception as e:
            logger.error(f"Netskope connection test failed: {e}")
            return False

    def get_url_lists(self) -> List[Dict]:
        """
        Get all URL lists

        Returns:
            List of URL lists
        """
        try:
            response = self.session.get(
                f'{self.base_url}/api/v2/policy/urllist'
            )
            response.raise_for_status()

            data = response.json()
            url_lists = data.get('data', {}).get('url_lists', [])

            logger.info(f"Retrieved {len(url_lists)} URL lists from Netskope")
            return url_lists

        except Exception as e:
            logger.error(f"Error getting URL lists: {e}")
            return []

    def get_url_list_by_name(self, list_name: str) -> Optional[Dict]:
        """
        Get a specific URL list by name

        Args:
            list_name: Name of the URL list

        Returns:
            URL list dictionary or None if not found
        """
        try:
            url_lists = self.get_url_lists()

            for url_list in url_lists:
                if url_list.get('name') == list_name:
                    logger.info(f"Found URL list: {list_name}")
                    return url_list

            logger.warning(f"URL list not found: {list_name}")
            return None

        except Exception as e:
            logger.error(f"Error getting URL list by name: {e}")
            return None

    def create_url_list(
        self,
        list_name: str,
        urls: List[str],
        list_type: str = 'exact',
        description: Optional[str] = None
    ) -> Dict:
        """
        Create a new URL list

        Args:
            list_name: Name of the URL list
            urls: List of URLs to block
            list_type: Type of list ('exact', 'regex', 'category')
            description: Optional description

        Returns:
            Dictionary with creation result
        """
        try:
            payload = {
                'name': list_name,
                'data': {
                    'urls': urls,
                    'type': list_type
                }
            }

            if description:
                payload['data']['description'] = description

            response = self.session.post(
                f'{self.base_url}/api/v2/policy/urllist',
                json=payload
            )
            response.raise_for_status()

            result = response.json()

            logger.info(f"Created URL list: {list_name} with {len(urls)} URLs")
            return {
                'success': True,
                'list_name': list_name,
                'list_id': result.get('data', {}).get('id'),
                'url_count': len(urls)
            }

        except Exception as e:
            logger.error(f"Error creating URL list: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def update_url_list(
        self,
        list_id: str,
        urls: List[str],
        append: bool = True
    ) -> Dict:
        """
        Update an existing URL list

        Args:
            list_id: ID of the URL list
            urls: List of URLs to add/replace
            append: If True, append to existing URLs; if False, replace

        Returns:
            Dictionary with update result
        """
        try:
            payload = {
                'id': list_id,
                'data': {
                    'urls': urls,
                    'append': append
                }
            }

            response = self.session.put(
                f'{self.base_url}/api/v2/policy/urllist/{list_id}',
                json=payload
            )
            response.raise_for_status()

            logger.info(f"Updated URL list {list_id}: {'appended' if append else 'replaced'} {len(urls)} URLs")
            return {
                'success': True,
                'list_id': list_id,
                'url_count': len(urls),
                'operation': 'append' if append else 'replace'
            }

        except Exception as e:
            logger.error(f"Error updating URL list: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def add_urls_to_list(
        self,
        list_name: str,
        urls: List[str]
    ) -> Dict:
        """
        Add URLs to an existing list or create new list if it doesn't exist

        Args:
            list_name: Name of the URL list
            urls: List of URLs to add

        Returns:
            Dictionary with operation result
        """
        try:
            # Check if list exists
            existing_list = self.get_url_list_by_name(list_name)

            if existing_list:
                # Append to existing list
                list_id = existing_list.get('id')
                return self.update_url_list(list_id, urls, append=True)
            else:
                # Create new list
                return self.create_url_list(list_name, urls)

        except Exception as e:
            logger.error(f"Error adding URLs to list: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def create_phishing_block_rule(
        self,
        urls: List[str],
        rule_name: Optional[str] = None,
        comment: Optional[str] = None
    ) -> Dict:
        """
        Create a URL blocking rule for phishing URLs

        Args:
            urls: List of URLs to block
            rule_name: Optional rule name
            comment: Optional comment/reason

        Returns:
            Dictionary with rule creation result
        """
        try:
            # Generate rule name if not provided
            if not rule_name:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                rule_name = f"Phishing_Block_{timestamp}"

            # Create or update URL list
            url_list_name = f"{rule_name}_URLs"
            url_list_result = self.add_urls_to_list(url_list_name, urls)

            if not url_list_result.get('success'):
                return url_list_result

            # Create blocking policy rule
            # Note: This assumes you want to add to the existing Real-time Protection policy
            payload = {
                'name': rule_name,
                'action': 'block',
                'url_list': url_list_name,
                'description': comment or f"Phishing URLs blocked on {datetime.now().strftime('%Y-%m-%d')}",
                'enabled': True
            }

            response = self.session.post(
                f'{self.base_url}/api/v2/policy/rules',
                json=payload
            )
            response.raise_for_status()

            result = response.json()

            logger.info(f"Created phishing block rule: {rule_name}")
            return {
                'success': True,
                'rule_name': rule_name,
                'rule_id': result.get('data', {}).get('id'),
                'url_list_name': url_list_name,
                'url_count': len(urls),
                'comment': comment
            }

        except Exception as e:
            logger.error(f"Error creating phishing block rule: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def block_urls_simple(
        self,
        urls: List[str],
        list_name: str = 'Phishing_URLs_Blocklist'
    ) -> Dict:
        """
        Simple method to block URLs by adding them to a blocklist

        Args:
            urls: List of URLs to block
            list_name: Name of the blocklist (will be created if doesn't exist)

        Returns:
            Dictionary with operation result
        """
        try:
            logger.info(f"Blocking {len(urls)} URLs in Netskope list '{list_name}'")

            result = self.add_urls_to_list(list_name, urls)

            if result.get('success'):
                logger.info(f"Successfully added {len(urls)} URLs to blocklist")

            return result

        except Exception as e:
            logger.error(f"Error blocking URLs: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def get_url_categories(self, urls: List[str]) -> Dict[str, str]:
        """
        Get Netskope's category classification for URLs

        Args:
            urls: List of URLs to classify

        Returns:
            Dictionary mapping URL to category
        """
        try:
            payload = {
                'urls': urls
            }

            response = self.session.post(
                f'{self.base_url}/api/v2/policy/urlcat/lookup',
                json=payload
            )
            response.raise_for_status()

            data = response.json()
            categories = data.get('data', {})

            logger.info(f"Retrieved categories for {len(urls)} URLs")
            return categories

        except Exception as e:
            logger.error(f"Error getting URL categories: {e}")
            return {}


# Example usage
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)

    config = {
        'tenant': 'yourcompany',
        'api_token': 'your_api_token_here'
    }

    connector = NetskopeConnector(config)

    if connector.test_connection():
        print("✓ Connected to Netskope")

        # Block phishing URLs
        phishing_urls = [
            'https://evil-site.com/verify',
            'https://phishing-example.com/login',
            'http://malicious-domain.com/update'
        ]

        result = connector.block_urls_simple(phishing_urls)
        print(f"Block result: {result}")

        # Get URL lists
        lists = connector.get_url_lists()
        print(f"Found {len(lists)} URL lists")

    else:
        print("✗ Connection failed")
