"""
System Inspector — CPU, memory, disk, uptime for Windows and Linux VMs.
"""
import logging
from backend.tools.winrm_connector import WinRMConnector
from backend.tools.ssh_connector import SSHConnector

logger = logging.getLogger(__name__)


def inspect_windows_system(conn: WinRMConnector) -> dict:
    """Collect CPU, memory, disk, uptime from a Windows VM."""
    issues = []
    result = {}

    # CPU usage
    cpu = conn.run("""
        $cpu = (Get-WmiObject Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
        Write-Output $cpu
    """)
    cpu_pct = float(cpu["stdout"]) if cpu["success"] and cpu["stdout"] else None
    result["cpu_percent"] = cpu_pct
    if cpu_pct and cpu_pct > 90:
        issues.append(f"HIGH_CPU:{cpu_pct}%")

    # Memory usage
    mem = conn.run("""
        $os = Get-WmiObject Win32_OperatingSystem
        $total = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
        $free = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
        $used_pct = [math]::Round((($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize) * 100, 1)
        Write-Output "$total,$free,$used_pct"
    """)
    if mem["success"] and mem["stdout"]:
        parts = mem["stdout"].split(",")
        if len(parts) == 3:
            result["memory"] = {
                "total_gb": parts[0],
                "free_gb": parts[1],
                "used_percent": float(parts[2]),
            }
            if float(parts[2]) > 90:
                issues.append(f"HIGH_MEMORY:{parts[2]}%")

    # Disk usage
    disk = conn.run("""
        Get-WmiObject Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
            $free_pct = [math]::Round(($_.FreeSpace / $_.Size) * 100, 1)
            $used_pct = 100 - $free_pct
            "$($_.DeviceID),$([math]::Round($_.Size/1GB,1)),$([math]::Round($_.FreeSpace/1GB,1)),$used_pct"
        }
    """)
    disks = []
    if disk["success"] and disk["stdout"]:
        for line in disk["stdout"].splitlines():
            parts = line.strip().split(",")
            if len(parts) == 4:
                used_pct = float(parts[3])
                disks.append({
                    "drive": parts[0],
                    "total_gb": parts[1],
                    "free_gb": parts[2],
                    "used_percent": used_pct,
                })
                if used_pct > 90:
                    issues.append(f"DISK_FULL:{parts[0]}:{used_pct}%")
    result["disks"] = disks

    # Uptime
    uptime = conn.run("""
        $uptime = (Get-Date) - (gcim Win32_OperatingSystem).LastBootUpTime
        Write-Output "$([math]::Round($uptime.TotalHours, 1)) hours"
    """)
    result["uptime"] = uptime["stdout"] if uptime["success"] else "unknown"

    # Top CPU processes
    top_proc = conn.run("""
        Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 |
        ForEach-Object { "$($_.Name),$([math]::Round($_.CPU,1)),$([math]::Round($_.WorkingSet64/1MB,1))MB" }
    """)
    if top_proc["success"] and top_proc["stdout"]:
        result["top_processes"] = top_proc["stdout"].splitlines()

    # Pending reboot check
    reboot = conn.run("""
        $reboot = Test-Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending"
        Write-Output $reboot
    """)
    if reboot["success"] and "True" in reboot["stdout"]:
        issues.append("PENDING_REBOOT")
        result["pending_reboot"] = True
    else:
        result["pending_reboot"] = False

    result["detected_issues"] = issues
    return result


def inspect_linux_system(conn: SSHConnector) -> dict:
    """Collect CPU, memory, disk, uptime from a Linux VM."""
    issues = []
    result = {}

    # CPU usage (1 second average)
    cpu = conn.run("top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | cut -d'%' -f1")
    if cpu["success"] and cpu["stdout"]:
        try:
            cpu_pct = float(cpu["stdout"].strip())
            result["cpu_percent"] = cpu_pct
            if cpu_pct > 90:
                issues.append(f"HIGH_CPU:{cpu_pct}%")
        except ValueError:
            pass

    # Memory
    mem = conn.run("free -m | awk 'NR==2{printf \"%s,%s,%s\", $2,$3,$4}'")
    if mem["success"] and mem["stdout"]:
        parts = mem["stdout"].split(",")
        if len(parts) == 3:
            total, used, free = int(parts[0]), int(parts[1]), int(parts[2])
            used_pct = round((used / total) * 100, 1) if total > 0 else 0
            result["memory"] = {
                "total_mb": total,
                "used_mb": used,
                "free_mb": free,
                "used_percent": used_pct,
            }
            if used_pct > 90:
                issues.append(f"HIGH_MEMORY:{used_pct}%")

    # Disk
    disk = conn.run("df -h | grep '^/dev' | awk '{print $1,$2,$4,$5}'")
    disks = []
    if disk["success"] and disk["stdout"]:
        for line in disk["stdout"].splitlines():
            parts = line.split()
            if len(parts) == 4:
                used_pct = int(parts[3].replace("%", ""))
                disks.append({
                    "mount": parts[0],
                    "total": parts[1],
                    "available": parts[2],
                    "used_percent": used_pct,
                })
                if used_pct > 90:
                    issues.append(f"DISK_FULL:{parts[0]}:{used_pct}%")
    result["disks"] = disks

    # Uptime
    uptime = conn.run("uptime -p")
    result["uptime"] = uptime["stdout"] if uptime["success"] else "unknown"

    # Top processes
    top = conn.run("ps aux --sort=-%cpu | head -6 | tail -5 | awk '{print $11,$3,$4}'")
    if top["success"] and top["stdout"]:
        result["top_processes"] = top["stdout"].splitlines()

    # OOM killer
    oom = conn.run("dmesg | grep -i 'oom' | tail -5")
    if oom["success"] and oom["stdout"]:
        issues.append(f"OOM_KILLER_ACTIVE:{oom['stdout'][:200]}")
        result["oom_events"] = oom["stdout"]

    result["detected_issues"] = issues
    return result
