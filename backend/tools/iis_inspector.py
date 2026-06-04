"""
IIS Inspector — inspects IIS app pools, sites, and bindings on Windows VMs.
Detects stopped app pools, wrong CLR versions, failed sites.
"""
import logging
from backend.tools.winrm_connector import WinRMConnector

logger = logging.getLogger(__name__)


def inspect_iis(conn: WinRMConnector) -> dict:
    """Full IIS inspection — app pools, sites, bindings."""
    result = {}
    issues = []

    # Check IIS / W3SVC service
    svc = conn.run("""
        $svc = Get-Service W3SVC -ErrorAction SilentlyContinue
        if ($svc) { Write-Output "$($svc.Status)" } else { Write-Output "NOT_INSTALLED" }
    """)
    iis_status = svc["stdout"].strip() if svc["success"] else "UNKNOWN"
    result["iis_service_status"] = iis_status
    if iis_status not in ("Running",):
        issues.append(f"IIS_SERVICE_{iis_status.upper()}")

    # App pools
    pools = conn.run("""
        Import-Module WebAdministration -ErrorAction SilentlyContinue
        Get-WebConfiguration system.applicationHost/applicationPools/add |
        ForEach-Object {
            $state = (Get-WebAppPoolState $_.name).Value
            "$($_.name)|$state|$($_.processModel.userName)|$($_.managedRuntimeVersion)|$($_.managedPipelineMode)"
        }
    """)
    app_pools = []
    if pools["success"] and pools["stdout"]:
        for line in pools["stdout"].splitlines():
            line = line.strip()
            if not line or "|" not in line:
                continue
            parts = line.split("|")
            if len(parts) >= 4:
                state = parts[1]
                pool = {
                    "name": parts[0],
                    "state": state,
                    "identity": parts[2] if len(parts) > 2 else "",
                    "clr_version": parts[3] if len(parts) > 3 else "",
                    "pipeline_mode": parts[4] if len(parts) > 4 else "",
                }
                if state != "Started":
                    issues.append(f"APP_POOL_STOPPED:{parts[0]}:{state}")
                app_pools.append(pool)
    result["app_pools"] = app_pools

    # Sites
    sites = conn.run("""
        Import-Module WebAdministration -ErrorAction SilentlyContinue
        Get-Website | ForEach-Object {
            $state = $_.State
            $bindings = ($_.Bindings.Collection | ForEach-Object { $_.bindingInformation }) -join ';'
            "$($_.Name)|$state|$($_.PhysicalPath)|$($_.ApplicationPool)|$bindings"
        }
    """)
    iis_sites = []
    if sites["success"] and sites["stdout"]:
        for line in sites["stdout"].splitlines():
            line = line.strip()
            if not line or "|" not in line:
                continue
            parts = line.split("|")
            if len(parts) >= 4:
                state = parts[1]
                site = {
                    "name": parts[0],
                    "state": state,
                    "physical_path": parts[2],
                    "app_pool": parts[3],
                    "bindings": parts[4].split(";") if len(parts) > 4 else [],
                }
                if state != "Started":
                    issues.append(f"SITE_STOPPED:{parts[0]}:{state}")
                iis_sites.append(site)
    result["sites"] = iis_sites

    # Recent IIS errors from event log
    errors = conn.run("""
        Get-EventLog -LogName System -Source "Microsoft-Windows-IIS*" -Newest 10 -EntryType Error,Warning -ErrorAction SilentlyContinue |
        ForEach-Object { "$($_.TimeGenerated)|$($_.EntryType)|$($_.Message.Substring(0,[Math]::Min(200,$_.Message.Length)))" }
    """)
    if errors["success"] and errors["stdout"]:
        result["recent_iis_errors"] = errors["stdout"].splitlines()[:10]
        if errors["stdout"].strip():
            issues.append(f"IIS_ERRORS_IN_EVENT_LOG:{len(errors['stdout'].splitlines())}_errors")

    result["detected_issues"] = issues
    return result
