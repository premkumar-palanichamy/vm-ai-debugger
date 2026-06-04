"""
Windows Event Log Inspector — reads Event Viewer for errors, crashes,
application failures, and security issues from Windows VMs.
"""
import logging
from backend.tools.winrm_connector import WinRMConnector

logger = logging.getLogger(__name__)


def inspect_windows_events(conn: WinRMConnector, hours: int = 24) -> dict:
    """
    Read Windows Event Logs for recent errors and warnings.
    Checks: Application, System, and Security logs.
    """
    issues = []
    result = {}

    # Application log errors (most important for .NET apps)
    app_errors = conn.run(f"""
        $since = (Get-Date).AddHours(-{hours})
        Get-EventLog -LogName Application -EntryType Error,Warning -After $since -Newest 20 -ErrorAction SilentlyContinue |
        ForEach-Object {{
            "$($_.TimeGenerated)|$($_.EntryType)|$($_.Source)|$($_.EventID)|$($_.Message.Substring(0,[Math]::Min(300,$_.Message.Length)).Replace('`n',' '))"
        }}
    """)
    app_event_list = []
    if app_errors["success"] and app_errors["stdout"]:
        for line in app_errors["stdout"].splitlines():
            if "|" not in line:
                continue
            parts = line.split("|", 4)
            if len(parts) >= 4:
                entry = {
                    "time": parts[0],
                    "type": parts[1],
                    "source": parts[2],
                    "event_id": parts[3],
                    "message": parts[4] if len(parts) > 4 else "",
                }
                app_event_list.append(entry)
                # Flag specific .NET issues
                msg = entry["message"].lower()
                if "unhandled exception" in msg or "application error" in msg:
                    issues.append(f"DOTNET_UNHANDLED_EXCEPTION:{entry['source']}:{entry['time']}")
                if "cannot start" in msg or "failed to start" in msg:
                    issues.append(f"APP_FAILED_TO_START:{entry['source']}")
                if "out of memory" in msg:
                    issues.append(f"OUT_OF_MEMORY:{entry['source']}")
    result["application_events"] = app_event_list

    # System log errors
    sys_errors = conn.run(f"""
        $since = (Get-Date).AddHours(-{hours})
        Get-EventLog -LogName System -EntryType Error,Warning -After $since -Newest 10 -ErrorAction SilentlyContinue |
        ForEach-Object {{
            "$($_.TimeGenerated)|$($_.EntryType)|$($_.Source)|$($_.EventID)|$($_.Message.Substring(0,[Math]::Min(200,$_.Message.Length)).Replace('`n',' '))"
        }}
    """)
    sys_event_list = []
    if sys_errors["success"] and sys_errors["stdout"]:
        for line in sys_errors["stdout"].splitlines():
            if "|" not in line:
                continue
            parts = line.split("|", 4)
            if len(parts) >= 4:
                entry = {
                    "time": parts[0],
                    "type": parts[1],
                    "source": parts[2],
                    "event_id": parts[3],
                    "message": parts[4] if len(parts) > 4 else "",
                }
                sys_event_list.append(entry)
                msg = entry["message"].lower()
                if "disk" in msg and ("error" in msg or "fail" in msg):
                    issues.append(f"DISK_ERROR:{entry['message'][:100]}")
                if "service" in msg and "failed" in msg:
                    issues.append(f"SERVICE_FAILED:{entry['source']}")
    result["system_events"] = sys_event_list

    # .NET specific — check for crash dumps
    crash_dumps = conn.run("""
        $paths = @(
            "$env:LOCALAPPDATA\\CrashDumps",
            "C:\\Windows\\Minidump",
            "C:\\Windows\\MEMORY.DMP"
        )
        $found = @()
        foreach ($p in $paths) {
            if (Test-Path $p) {
                $files = Get-ChildItem $p -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 3
                foreach ($f in $files) {
                    $found += "$($f.LastWriteTime)|$($f.Name)|$([math]::Round($f.Length/1MB,1))MB"
                }
            }
        }
        $found
    """)
    if crash_dumps["success"] and crash_dumps["stdout"].strip():
        result["crash_dumps"] = crash_dumps["stdout"].splitlines()
        issues.append(f"CRASH_DUMPS_FOUND:{len(crash_dumps['stdout'].splitlines())}_dumps")
    else:
        result["crash_dumps"] = []

    # Windows services status — check critical services
    services = conn.run("""
        $critical = @('W3SVC','WAS','MSSQLSERVER','MySQL','MySQL80','MSMQ')
        $critical | ForEach-Object {
            $svc = Get-Service $_ -ErrorAction SilentlyContinue
            if ($svc) {
                "$($svc.Name)|$($svc.Status)|$($svc.StartType)"
            }
        }
    """)
    svc_list = []
    if services["success"] and services["stdout"]:
        for line in services["stdout"].splitlines():
            if "|" not in line:
                continue
            parts = line.split("|")
            if len(parts) >= 2:
                svc = {"name": parts[0], "status": parts[1], "start_type": parts[2] if len(parts) > 2 else ""}
                svc_list.append(svc)
                if parts[1].strip() != "Running":
                    issues.append(f"SERVICE_NOT_RUNNING:{parts[0]}:{parts[1]}")
    result["critical_services"] = svc_list

    result["detected_issues"] = issues
    return result
