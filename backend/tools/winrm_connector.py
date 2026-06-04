"""
WinRM Connector — establishes PowerShell remoting sessions to Windows VMs.
All other Windows tools use this connector to run remote commands.
"""
import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class WinRMConnector:
    """
    Manages a WinRM connection to a Windows VM.
    Uses pywinrm under the hood.

    Usage:
        with WinRMConnector() as conn:
            result = conn.run("Get-Service")
    """

    def __init__(
        self,
        host: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        port: Optional[int] = None,
        use_ssl: Optional[bool] = None,
    ):
        self.host = host or os.getenv("VM_WINDOWS_HOST", "")
        self.username = username or os.getenv("VM_WINDOWS_USER", "Administrator")
        self.password = password or os.getenv("VM_WINDOWS_PASSWORD", "")
        self.port = port or int(os.getenv("VM_WINDOWS_PORT", "5985"))
        self.use_ssl = use_ssl if use_ssl is not None else os.getenv("VM_WINDOWS_USE_SSL", "false").lower() == "true"
        self._session = None

    def connect(self):
        """Establish WinRM session."""
        try:
            import winrm
            protocol = "https" if self.use_ssl else "http"
            self._session = winrm.Session(
                target=f"{protocol}://{self.host}:{self.port}/wsman",
                auth=(self.username, self.password),
                transport="ntlm",
                server_cert_validation="ignore" if self.use_ssl else "ignore",
            )
            logger.info("WinRM connected to %s:%s", self.host, self.port)
            return self
        except ImportError:
            raise RuntimeError("pywinrm not installed. Run: pip install pywinrm")
        except Exception as e:
            logger.error("WinRM connection failed to %s: %s", self.host, e)
            raise

    def run(self, powershell_command: str) -> dict:
        """
        Run a PowerShell command on the remote Windows VM.
        Returns dict with stdout, stderr, status_code.
        """
        if not self._session:
            raise RuntimeError("Not connected. Call connect() first.")
        try:
            result = self._session.run_ps(powershell_command)
            return {
                "stdout": result.std_out.decode("utf-8", errors="replace").strip(),
                "stderr": result.std_err.decode("utf-8", errors="replace").strip(),
                "status_code": result.status_code,
                "success": result.status_code == 0,
            }
        except Exception as e:
            logger.error("WinRM command failed: %s", e)
            return {
                "stdout": "",
                "stderr": str(e),
                "status_code": -1,
                "success": False,
            }

    def run_cmd(self, command: str) -> dict:
        """Run a CMD command (not PowerShell)."""
        if not self._session:
            raise RuntimeError("Not connected. Call connect() first.")
        try:
            result = self._session.run_cmd(command)
            return {
                "stdout": result.std_out.decode("utf-8", errors="replace").strip(),
                "stderr": result.std_err.decode("utf-8", errors="replace").strip(),
                "status_code": result.status_code,
                "success": result.status_code == 0,
            }
        except Exception as e:
            return {"stdout": "", "stderr": str(e), "status_code": -1, "success": False}

    def disconnect(self):
        self._session = None
        logger.info("WinRM disconnected from %s", self.host)

    def __enter__(self):
        return self.connect()

    def __exit__(self, *args):
        self.disconnect()


def is_windows_configured() -> bool:
    """Check if Windows VM connection is configured in .env."""
    return bool(os.getenv("VM_WINDOWS_HOST", "").strip())


def get_winrm_connection() -> Optional[WinRMConnector]:
    """Get a connected WinRM session or None if not configured."""
    if not is_windows_configured():
        return None
    try:
        conn = WinRMConnector()
        conn.connect()
        return conn
    except Exception as e:
        logger.warning("Could not connect to Windows VM: %s", e)
        return None
