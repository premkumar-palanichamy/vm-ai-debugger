"""
Network Inspector — checks port accessibility, SSL certificates,
DNS resolution, and firewall rules on VMs.
"""
import os
import socket
import ssl
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


def check_port(host: str, port: int, timeout: int = 5) -> dict:
    """Check if a TCP port is open and reachable."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return {
            "host": host,
            "port": port,
            "open": result == 0,
            "error": None,
        }
    except Exception as e:
        return {"host": host, "port": port, "open": False, "error": str(e)}


def check_ssl_cert(host: str, port: int = 443) -> dict:
    """Check SSL certificate expiry and validity."""
    issues = []
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(10)
            s.connect((host, port))
            cert = s.getpeercert()

        expiry_str = cert["notAfter"]
        expiry = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (expiry - datetime.now(timezone.utc)).days
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))

        if days_left < 0:
            issues.append(f"SSL_CERT_EXPIRED:{host}")
        elif days_left < 30:
            issues.append(f"SSL_CERT_EXPIRING_SOON:{days_left}d_left:{host}")

        return {
            "host": host,
            "port": port,
            "valid": days_left > 0,
            "days_until_expiry": days_left,
            "expiry": expiry.isoformat(),
            "subject": subject.get("commonName", ""),
            "issuer": issuer.get("organizationName", ""),
            "detected_issues": issues,
        }
    except ssl.SSLCertVerificationError as e:
        return {"host": host, "port": port, "valid": False, "error": f"SSL_VERIFICATION_FAILED:{str(e)}", "detected_issues": [f"SSL_CERT_INVALID:{host}"]}
    except Exception as e:
        return {"host": host, "port": port, "valid": False, "error": str(e), "detected_issues": [f"SSL_CHECK_FAILED:{host}:{str(e)[:100]}"]}


def check_dns(hostname: str) -> dict:
    """Check DNS resolution for a hostname."""
    try:
        ip = socket.gethostbyname(hostname)
        return {"hostname": hostname, "resolved": True, "ip": ip}
    except socket.gaierror as e:
        return {"hostname": hostname, "resolved": False, "error": str(e), "detected_issues": [f"DNS_RESOLUTION_FAILED:{hostname}"]}


def inspect_vm_network(
    host: str,
    check_ports: Optional[list] = None,
    check_ssl: bool = True,
) -> dict:
    """
    Full network inspection for a VM.
    Checks common ports: 80, 443, 3306 (MySQL), 5985 (WinRM), 22 (SSH).
    """
    issues = []
    result = {}

    default_ports = check_ports or [80, 443, 3306, 5985, 22, 1433]

    # Port checks
    port_results = []
    for port in default_ports:
        check = check_port(host, port)
        port_results.append(check)
        port_name = {80: "HTTP", 443: "HTTPS", 3306: "MySQL",
                     5985: "WinRM", 22: "SSH", 1433: "MSSQL"}.get(port, str(port))
        if not check["open"] and port in [80, 443]:
            issues.append(f"PORT_CLOSED:{port_name}:{port}")
    result["port_checks"] = port_results

    # SSL check
    if check_ssl:
        ssl_result = check_ssl_cert(host, 443)
        result["ssl_certificate"] = ssl_result
        issues.extend(ssl_result.get("detected_issues", []))

    # DNS check
    dns_result = check_dns(host)
    result["dns"] = dns_result
    if not dns_result["resolved"]:
        issues.extend(dns_result.get("detected_issues", []))

    result["detected_issues"] = issues
    return result


def inspect_network_via_winrm(conn, target_host: str = "") -> dict:
    """Check network connectivity and firewall rules from inside the Windows VM."""
    issues = []
    result = {}

    # Active TCP connections
    netstat = conn.run("""
        Get-NetTCPConnection -State Listen |
        Where-Object { $_.LocalPort -in @(80,443,3306,8080,5985,1433) } |
        ForEach-Object { "$($_.LocalPort)|$($_.State)|$($_.OwningProcess)" }
    """)
    listening_ports = []
    if netstat["success"] and netstat["stdout"]:
        for line in netstat["stdout"].splitlines():
            parts = line.split("|")
            if len(parts) >= 2:
                listening_ports.append({"port": parts[0], "state": parts[1], "pid": parts[2] if len(parts) > 2 else ""})
    result["listening_ports"] = listening_ports

    # Firewall status
    fw = conn.run("""
        $profiles = Get-NetFirewallProfile
        $profiles | ForEach-Object { "$($_.Name)|$($_.Enabled)" }
    """)
    if fw["success"] and fw["stdout"]:
        result["firewall_profiles"] = fw["stdout"].splitlines()
        if "True" in fw["stdout"]:
            result["firewall_enabled"] = True

    # Test outbound connectivity
    if target_host:
        ping = conn.run(f"Test-Connection -ComputerName {target_host} -Count 2 -Quiet")
        result["ping_target"] = {
            "host": target_host,
            "reachable": "True" in ping["stdout"] if ping["success"] else False,
        }
        if not result["ping_target"]["reachable"]:
            issues.append(f"CANNOT_REACH:{target_host}")

    result["detected_issues"] = issues
    return result
