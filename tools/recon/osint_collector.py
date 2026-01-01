#!/usr/bin/env python3
"""
OSINTCollector - Collects Open Source Intelligence from various sources
"""
import logging
import re
import requests
from typing import Dict, List
import socket

logger = logging.getLogger(__name__)

class OSINTCollector:
    """
    A class for collecting Open Source Intelligence from publicly available sources.
    Collects information like WHOIS data, IP addresses, email patterns, and more.
    """
    def __init__(self, config: Dict):
        """
        Initializes the OSINTCollector.

        Args:
            config (Dict): The configuration dictionary for the framework.
        """
        self.config = config
        logger.info("OSINTCollector initialized")

    def collect(self, target: str) -> Dict:
        """
        Collects OSINT data for a given target.

        Args:
            target (str): The target (e.g., domain name, company name).

        Returns:
            Dict: A dictionary containing OSINT findings.
        """
        logger.info(f"Starting OSINT collection for {target}")

        results = {
            "target": target,
            "ip_addresses": self._get_ip_addresses(target),
            "email_patterns": self._find_email_patterns(target),
            "technologies": self._detect_technologies(target),
            "social_media": self._find_social_media(target),
            "metadata": "OSINT collection completed"
        }

        logger.info(f"OSINT collection completed for {target}")
        return results

    def _get_ip_addresses(self, target: str) -> List[str]:
        """Resolve target domain to IP addresses"""
        try:
            # Remove protocol if present
            domain = target.replace('http://', '').replace('https://', '').split('/')[0]
            ip_list = socket.gethostbyname_ex(domain)[2]
            logger.info(f"Resolved {domain} to IPs: {ip_list}")
            return ip_list
        except socket.gaierror as e:
            logger.warning(f"Could not resolve {target}: {e}")
            return []
        except Exception as e:
            logger.error(f"Error resolving IP for {target}: {e}")
            return []

    def _find_email_patterns(self, target: str) -> List[str]:
        """Find common email patterns for the target domain"""
        try:
            domain = target.replace('http://', '').replace('https://', '').split('/')[0]
            # Common email patterns
            patterns = [
                f"info@{domain}",
                f"contact@{domain}",
                f"admin@{domain}",
                f"support@{domain}",
                f"security@{domain}"
            ]
            logger.info(f"Generated {len(patterns)} common email patterns for {domain}")
            return patterns
        except Exception as e:
            logger.error(f"Error generating email patterns: {e}")
            return []

    def _detect_technologies(self, target: str) -> Dict:
        """Detect web technologies used by the target"""
        try:
            if not target.startswith('http'):
                target = f"http://{target}"

            response = requests.get(target, timeout=10, allow_redirects=True)
            headers = response.headers

            technologies = {
                "server": headers.get('Server', 'Unknown'),
                "powered_by": headers.get('X-Powered-By', 'Unknown'),
                "framework": self._detect_framework(response.text, headers),
                "status_code": response.status_code
            }

            logger.info(f"Detected technologies for {target}: {technologies}")
            return technologies
        except requests.RequestException as e:
            logger.warning(f"Could not detect technologies for {target}: {e}")
            return {"error": str(e)}
        except Exception as e:
            logger.error(f"Error detecting technologies: {e}")
            return {"error": str(e)}

    def _detect_framework(self, html_content: str, headers: Dict) -> str:
        """Detect web framework from HTML and headers"""
        frameworks = {
            'WordPress': ['wp-content', 'wp-includes'],
            'Drupal': ['drupal.js', 'sites/default'],
            'Joomla': ['joomla', 'option=com_'],
            'Django': ['csrfmiddlewaretoken'],
            'Laravel': ['laravel', '_token'],
            'React': ['react', '__REACT'],
            'Angular': ['ng-version', 'angular'],
            'Vue': ['vue', '__VUE__']
        }

        for framework, indicators in frameworks.items():
            for indicator in indicators:
                if indicator.lower() in html_content.lower():
                    return framework

        return "Unknown"

    def _find_social_media(self, target: str) -> Dict:
        """Find potential social media accounts for the target"""
        try:
            domain = target.replace('http://', '').replace('https://', '').split('/')[0]
            company_name = domain.split('.')[0]

            social_media = {
                "twitter": f"https://twitter.com/{company_name}",
                "linkedin": f"https://linkedin.com/company/{company_name}",
                "github": f"https://github.com/{company_name}",
                "facebook": f"https://facebook.com/{company_name}"
            }

            logger.info(f"Generated social media URLs for {company_name}")
            return social_media
        except Exception as e:
            logger.error(f"Error generating social media links: {e}")
            return {}
