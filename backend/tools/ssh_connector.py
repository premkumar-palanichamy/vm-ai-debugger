"""
SSH Connector — establishes SSH sessions to Linux VMs.
All Linux tools use this connector to run remote commands.
"""
import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class SSHConnector:
    """
    Manages an SSH connection to a Linux VM using paramiko.

    Usage:
        with SSHConnector() as conn:
            result = conn.run("systemctl status nginx")
    """

    def __init__(
        self,
        host: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        ssh_key: Optional[str] = None,
        port: Optional[int] = None,
    ):
        self.host = host or os.getenv("VM_LINUX_HOST", "")
        self.username = username or os.getenv("VM_LINUX_USER", "ubuntu")
        self.password = password or os.getenv("VM_LINUX_PASSWORD", "")
        self.ssh_key = ssh_key or os.getenv("VM_LINUX_SSH_KEY", "")
        self.port = port or int(os.getenv("VM_LINUX_PORT", "22"))
        self._client = None

    def connect(self):
        """Establish SSH connection."""
        try:
            import paramiko
            self._client = paramiko.SSHClient()
            self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            connect_kwargs = {
                "hostname": self.host,
                "port": self.port,
                "username": self.username,
                "timeout": 15,
            }

            # Prefer SSH key over password
            if self.ssh_key:
                key_path = os.path.expanduser(self.ssh_key)
                connect_kwargs["key_filename"] = key_path
            elif self.password:
                connect_kwargs["password"] = self.password

            self._client.connect(**connect_kwargs)
            logger.info("SSH connected to %s:%s", self.host, self.port)
            return self

        except ImportError:
            raise RuntimeError("paramiko not installed. Run: pip install paramiko")
        except Exception as e:
            logger.error("SSH connection failed to %s: %s", self.host, e)
            raise

    def run(self, command: str, timeout: int = 30) -> dict:
        """
        Run a shell command on the remote Linux VM.
        Returns dict with stdout, stderr, exit_code.
        """
        if not self._client:
            raise RuntimeError("Not connected. Call connect() first.")
        try:
            stdin, stdout, stderr = self._client.exec_command(command, timeout=timeout)
            exit_code = stdout.channel.recv_exit_status()
            return {
                "stdout": stdout.read().decode("utf-8", errors="replace").strip(),
                "stderr": stderr.read().decode("utf-8", errors="replace").strip(),
                "exit_code": exit_code,
                "success": exit_code == 0,
            }
        except Exception as e:
            logger.error("SSH command failed: %s", e)
            return {
                "stdout": "",
                "stderr": str(e),
                "exit_code": -1,
                "success": False,
            }

    def disconnect(self):
        if self._client:
            self._client.close()
            self._client = None
        logger.info("SSH disconnected from %s", self.host)

    def __enter__(self):
        return self.connect()

    def __exit__(self, *args):
        self.disconnect()


def is_linux_configured() -> bool:
    """Check if Linux VM connection is configured in .env."""
    return bool(os.getenv("VM_LINUX_HOST", "").strip())


def get_ssh_connection() -> Optional[SSHConnector]:
    """Get a connected SSH session or None if not configured."""
    if not is_linux_configured():
        return None
    try:
        conn = SSHConnector()
        conn.connect()
        return conn
    except Exception as e:
        logger.warning("Could not connect to Linux VM: %s", e)
        return None
