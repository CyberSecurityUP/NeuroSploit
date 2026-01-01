#!/usr/bin/env python3
"""
SubdomainFinder - Discovers subdomains using multiple techniques
"""
import logging
import requests
import socket
from typing import Dict, List, Set
import re

logger = logging.getLogger(__name__)

class SubdomainFinder:
    """
    A class for finding subdomains of a given domain.
    Uses Certificate Transparency logs, DNS brute-forcing, and common patterns.
    """
    def __init__(self, config: Dict):
        """
        Initializes the SubdomainFinder.

        Args:
            config (Dict): The configuration dictionary for the framework.
        """
        self.config = config
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'webdisk', 'ns', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'test',
            'dev', 'staging', 'api', 'admin', 'portal', 'beta', 'demo', 'vpn',
            'blog', 'shop', 'store', 'forum', 'support', 'm', 'mobile', 'cdn',
            'static', 'assets', 'img', 'images', 'git', 'jenkins', 'jira'
        ]
        logger.info("SubdomainFinder initialized")

    def find(self, target: str) -> List[str]:
        """
        Finds subdomains for a given domain using multiple techniques.

        Args:
            target (str): The domain name to search subdomains for.

        Returns:
            List[str]: A list of found subdomains.
        """
        logger.info(f"Starting subdomain enumeration for {target}")

        # Remove protocol if present
        domain = target.replace('http://', '').replace('https://', '').split('/')[0]

        found_subdomains: Set[str] = set()

        # Method 1: Certificate Transparency logs
        ct_subdomains = self._check_crtsh(domain)
        found_subdomains.update(ct_subdomains)

        # Method 2: Common subdomain brute-forcing
        brute_subdomains = self._brute_force_common(domain)
        found_subdomains.update(brute_subdomains)

        result = sorted(list(found_subdomains))
        logger.info(f"Found {len(result)} subdomains for {domain}")
        return result

    def _check_crtsh(self, domain: str) -> List[str]:
        """
        Query Certificate Transparency logs via crt.sh
        """
        subdomains = []
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            logger.info(f"Querying crt.sh for {domain}")

            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                data = response.json()

                for entry in data:
                    name_value = entry.get('name_value', '')
                    # Split by newlines (crt.sh returns multiple names per entry sometimes)
                    names = name_value.split('\n')
                    for name in names:
                        name = name.strip().lower()
                        # Remove wildcards
                        name = name.replace('*.', '')
                        # Only include valid subdomains for this domain
                        if name.endswith(domain) and name != domain:
                            subdomains.append(name)

                logger.info(f"Found {len(subdomains)} subdomains from crt.sh")
            else:
                logger.warning(f"crt.sh returned status code {response.status_code}")

        except requests.RequestException as e:
            logger.warning(f"Error querying crt.sh: {e}")
        except Exception as e:
            logger.error(f"Unexpected error in crt.sh query: {e}")

        return list(set(subdomains))  # Remove duplicates

    def _brute_force_common(self, domain: str) -> List[str]:
        """
        Brute-force common subdomain names
        """
        found = []
        logger.info(f"Brute-forcing common subdomains for {domain}")

        for subdomain in self.common_subdomains:
            full_domain = f"{subdomain}.{domain}"
            if self._check_subdomain_exists(full_domain):
                found.append(full_domain)
                logger.debug(f"Found subdomain: {full_domain}")

        logger.info(f"Found {len(found)} subdomains via brute-force")
        return found

    def _check_subdomain_exists(self, subdomain: str) -> bool:
        """
        Check if a subdomain exists by attempting to resolve it
        """
        try:
            socket.gethostbyname(subdomain)
            return True
        except socket.gaierror:
            return False
        except Exception as e:
            logger.debug(f"Error checking {subdomain}: {e}")
            return False
