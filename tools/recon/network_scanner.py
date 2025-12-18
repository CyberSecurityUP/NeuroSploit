#!/usr/bin/env python3
"""
NetworkScanner - A tool for scanning networks to find open ports.
"""
import socket
import logging
from typing import Dict, List

logger = logging.getLogger(__name__)

class NetworkScanner:
    """
    A class to scan for open ports on a target machine.
    """
    def __init__(self, config: Dict):
        """
        Initializes the NetworkScanner.
        
        Args:
            config (Dict): The configuration dictionary for the framework.
        """
        self.config = config
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
            993, 995, 1723, 3306, 3389, 5900, 8080
        ]

    def scan(self, target: str) -> Dict:
        """
        Scans a target for open ports.

        Args:
            target (str): The IP address or hostname to scan.

        Returns:
            Dict: A dictionary containing the list of open ports found.
        """
        logger.info(f"Starting network scan on {target}")
        open_ports = []
        
        try:
            target_ip = socket.gethostbyname(target)
            logger.info(f"Resolved {target} to {target_ip}")

            for port in self.common_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socket.setdefaulttimeout(1)
                
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    logger.info(f"Port {port} is open on {target}")
                    open_ports.append(port)
                sock.close()

        except socket.gaierror:
            logger.error(f"Hostname could not be resolved: {target}")
            return {"error": "Hostname could not be resolved."}
        except socket.error:
            logger.error(f"Could not connect to server: {target}")
            return {"error": "Could not connect to server."}

        logger.info(f"Network scan finished. Found {len(open_ports)} open ports.")
        return {"target": target, "open_ports": open_ports}

