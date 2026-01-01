#!/usr/bin/env python3
"""
DNSEnumerator - Enumerates DNS records for target domains
"""
import logging
import socket
import subprocess
from typing import Dict, List
import re

logger = logging.getLogger(__name__)

class DNSEnumerator:
    """
    A class for enumerating DNS records.
    Queries various DNS record types including A, AAAA, MX, NS, TXT, CNAME, and SOA.
    """
    def __init__(self, config: Dict):
        """
        Initializes the DNSEnumerator.

        Args:
            config (Dict): The configuration dictionary for the framework.
        """
        self.config = config
        logger.info("DNSEnumerator initialized")

    def enumerate(self, target: str) -> Dict:
        """
        Enumerates DNS records for a given domain.

        Args:
            target (str): The domain name to enumerate.

        Returns:
            Dict: A dictionary containing DNS records.
        """
        logger.info(f"Starting DNS enumeration for {target}")

        # Remove protocol if present
        domain = target.replace('http://', '').replace('https://', '').split('/')[0]

        records = {
            "target": domain,
            "records": {
                "A": self._get_a_records(domain),
                "AAAA": self._get_aaaa_records(domain),
                "MX": self._get_mx_records(domain),
                "NS": self._get_ns_records(domain),
                "TXT": self._get_txt_records(domain),
                "CNAME": self._get_cname_records(domain)
            },
            "notes": "DNS enumeration completed"
        }

        logger.info(f"DNS enumeration completed for {domain}")
        return records

    def _get_a_records(self, domain: str) -> List[str]:
        """Get A records (IPv4 addresses)"""
        try:
            records = socket.gethostbyname_ex(domain)[2]
            logger.info(f"Found {len(records)} A records for {domain}")
            return records
        except socket.gaierror as e:
            logger.warning(f"Could not resolve A records for {domain}: {e}")
            return []
        except Exception as e:
            logger.error(f"Error getting A records: {e}")
            return []

    def _get_aaaa_records(self, domain: str) -> List[str]:
        """Get AAAA records (IPv6 addresses)"""
        try:
            records = socket.getaddrinfo(domain, None, socket.AF_INET6)
            ipv6_addrs = list(set([record[4][0] for record in records]))
            logger.info(f"Found {len(ipv6_addrs)} AAAA records for {domain}")
            return ipv6_addrs
        except socket.gaierror:
            logger.debug(f"No AAAA records found for {domain}")
            return []
        except Exception as e:
            logger.error(f"Error getting AAAA records: {e}")
            return []

    def _get_mx_records(self, domain: str) -> List[str]:
        """Get MX records using nslookup/dig fallback"""
        return self._query_dns_tool(domain, "MX")

    def _get_ns_records(self, domain: str) -> List[str]:
        """Get NS records using nslookup/dig fallback"""
        return self._query_dns_tool(domain, "NS")

    def _get_txt_records(self, domain: str) -> List[str]:
        """Get TXT records using nslookup/dig fallback"""
        return self._query_dns_tool(domain, "TXT")

    def _get_cname_records(self, domain: str) -> List[str]:
        """Get CNAME records using nslookup/dig fallback"""
        try:
            result = socket.getfqdn(domain)
            if result != domain:
                logger.info(f"Found CNAME for {domain}: {result}")
                return [result]
            return []
        except Exception as e:
            logger.debug(f"No CNAME records found for {domain}")
            return []

    def _query_dns_tool(self, domain: str, record_type: str) -> List[str]:
        """
        Query DNS using nslookup (fallback method when dnspython not available)
        """
        try:
            # Try using nslookup
            cmd = ['nslookup', '-type=' + record_type, domain]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
                shell=False
            )

            if result.returncode == 0:
                records = self._parse_nslookup_output(result.stdout, record_type)
                logger.info(f"Found {len(records)} {record_type} records for {domain}")
                return records
            else:
                logger.debug(f"nslookup failed for {record_type} records")
                return []

        except FileNotFoundError:
            logger.warning("nslookup not found. DNS enumeration limited to A/AAAA records.")
            return []
        except subprocess.TimeoutExpired:
            logger.warning(f"DNS query timeout for {record_type} records")
            return []
        except Exception as e:
            logger.error(f"Error querying {record_type} records: {e}")
            return []

    def _parse_nslookup_output(self, output: str, record_type: str) -> List[str]:
        """Parse nslookup output to extract DNS records"""
        records = []

        if record_type == "MX":
            # MX records format: "mail exchanger = 10 mail.example.com"
            pattern = r'mail exchanger = \d+ (.+)'
            matches = re.findall(pattern, output)
            records = [match.strip().rstrip('.') for match in matches]

        elif record_type == "NS":
            # NS records format: "nameserver = ns1.example.com"
            pattern = r'nameserver = (.+)'
            matches = re.findall(pattern, output)
            records = [match.strip().rstrip('.') for match in matches]

        elif record_type == "TXT":
            # TXT records format: "text = "v=spf1 ...""
            pattern = r'text = "([^"]+)"'
            matches = re.findall(pattern, output)
            records = matches

        return records
