#!/usr/bin/env python3
"""
SSH Lateral Movement - Techniques for lateral movement via SSH
"""
import logging
from typing import Dict, List
import socket

logger = logging.getLogger(__name__)

class SSHLateral:
    """
    SSH-based lateral movement techniques including
    key-based authentication, password spraying, and tunneling.
    """
    def __init__(self, config: Dict):
        """
        Initializes SSHLateral movement module.

        Args:
            config (Dict): Configuration dictionary
        """
        self.config = config
        logger.info("SSHLateral module initialized")

    def check_ssh_access(self, target: str, port: int = 22) -> bool:
        """
        Check if SSH is accessible on target.

        Args:
            target (str): Target IP or hostname
            port (int): SSH port (default 22)

        Returns:
            bool: True if SSH is accessible
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((target, port))
            sock.close()

            if result == 0:
                logger.info(f"SSH port {port} is open on {target}")
                return True
            else:
                logger.info(f"SSH port {port} is closed on {target}")
                return False
        except Exception as e:
            logger.error(f"Error checking SSH access: {e}")
            return False

    def enumerate_ssh_keys(self, target: str, username: str) -> Dict:
        """
        Enumerate potential SSH key locations.

        Args:
            target (str): Target IP or hostname
            username (str): Target username

        Returns:
            Dict: SSH key enumeration results
        """
        logger.info(f"Enumerating SSH keys for {username}@{target}")

        common_key_paths = [
            f"/home/{username}/.ssh/id_rsa",
            f"/home/{username}/.ssh/id_ed25519",
            f"/home/{username}/.ssh/id_ecdsa",
            f"/root/.ssh/id_rsa",
            f"/root/.ssh/authorized_keys"
        ]

        results = {
            "target": target,
            "username": username,
            "common_paths": common_key_paths,
            "notes": "Key extraction requires existing access to target system"
        }

        return results

    def create_ssh_tunnel(self, target: str, local_port: int, remote_host: str, remote_port: int) -> Dict:
        """
        Create SSH tunnel for pivoting.

        Args:
            target (str): SSH server to tunnel through
            local_port (int): Local port to bind
            remote_host (str): Remote host to reach
            remote_port (int): Remote port to reach

        Returns:
            Dict: Tunnel creation results
        """
        logger.info(f"Creating SSH tunnel: localhost:{local_port} -> {target} -> {remote_host}:{remote_port}")

        results = {
            "tunnel_type": "ssh_forward",
            "local_port": local_port,
            "remote_host": remote_host,
            "remote_port": remote_port,
            "notes": "SSH tunneling requires paramiko or external ssh command"
        }

        logger.warning("SSH tunneling requires paramiko library or ssh binary")
        return results
