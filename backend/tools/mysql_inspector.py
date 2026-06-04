"""
MySQL Inspector — checks MySQL service health, connections,
slow queries, and database accessibility.
Works both locally and via SSH tunnel.
"""
import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def inspect_mysql(host: Optional[str] = None, port: Optional[int] = None,
                  user: Optional[str] = None, password: Optional[str] = None,
                  database: Optional[str] = None) -> dict:
    """
    Connect to MySQL and collect health metrics.
    Uses connection details from .env if not provided.
    """
    issues = []
    result = {}

    host = host or os.getenv("MYSQL_HOST", "localhost")
    port = port or int(os.getenv("MYSQL_PORT", "3306"))
    user = user or os.getenv("MYSQL_USER", "root")
    password = password or os.getenv("MYSQL_PASSWORD", "")
    database = database or os.getenv("MYSQL_DATABASE", "")

    result["host"] = host
    result["port"] = port
    result["database"] = database

    try:
        import pymysql
        conn = pymysql.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            database=database if database else None,
            connect_timeout=10,
            charset="utf8mb4",
        )
        result["connection_status"] = "connected"

        cursor = conn.cursor()

        # MySQL version
        cursor.execute("SELECT VERSION()")
        result["version"] = cursor.fetchone()[0]

        # Global status variables
        cursor.execute("SHOW GLOBAL STATUS LIKE 'Threads_connected'")
        row = cursor.fetchone()
        threads_connected = int(row[1]) if row else 0
        result["threads_connected"] = threads_connected

        cursor.execute("SHOW GLOBAL STATUS LIKE 'Threads_running'")
        row = cursor.fetchone()
        threads_running = int(row[1]) if row else 0
        result["threads_running"] = threads_running

        # Max connections
        cursor.execute("SHOW GLOBAL VARIABLES LIKE 'max_connections'")
        row = cursor.fetchone()
        max_conn = int(row[1]) if row else 100
        result["max_connections"] = max_conn

        conn_pct = round((threads_connected / max_conn) * 100, 1) if max_conn > 0 else 0
        result["connection_usage_percent"] = conn_pct
        if conn_pct > 80:
            issues.append(f"HIGH_CONNECTION_USAGE:{conn_pct}%_of_{max_conn}")

        # Slow queries
        cursor.execute("SHOW GLOBAL STATUS LIKE 'Slow_queries'")
        row = cursor.fetchone()
        slow_queries = int(row[1]) if row else 0
        result["slow_queries_total"] = slow_queries
        if slow_queries > 100:
            issues.append(f"HIGH_SLOW_QUERY_COUNT:{slow_queries}")

        # Aborted connections
        cursor.execute("SHOW GLOBAL STATUS LIKE 'Aborted_connects'")
        row = cursor.fetchone()
        aborted = int(row[1]) if row else 0
        result["aborted_connects"] = aborted
        if aborted > 50:
            issues.append(f"HIGH_ABORTED_CONNECTS:{aborted}")

        # InnoDB buffer pool usage
        cursor.execute("SHOW GLOBAL STATUS LIKE 'Innodb_buffer_pool_pages_total'")
        total_pages = cursor.fetchone()
        cursor.execute("SHOW GLOBAL STATUS LIKE 'Innodb_buffer_pool_pages_free'")
        free_pages = cursor.fetchone()
        if total_pages and free_pages:
            total = int(total_pages[1])
            free = int(free_pages[1])
            used_pct = round(((total - free) / total) * 100, 1) if total > 0 else 0
            result["innodb_buffer_pool_used_percent"] = used_pct
            if used_pct > 95:
                issues.append(f"INNODB_BUFFER_POOL_NEARLY_FULL:{used_pct}%")

        # Current processlist — look for locked/long-running queries
        cursor.execute("SHOW FULL PROCESSLIST")
        processes = cursor.fetchall()
        long_running = []
        for proc in processes:
            if proc[5] and int(proc[5]) > 30:  # running > 30 seconds
                long_running.append({
                    "id": proc[0],
                    "user": proc[1],
                    "db": proc[3],
                    "command": proc[4],
                    "time_seconds": proc[5],
                    "state": proc[6],
                    "query": str(proc[7])[:200] if proc[7] else "",
                })
                issues.append(f"LONG_RUNNING_QUERY:{proc[5]}s:{str(proc[7])[:100] if proc[7] else 'unknown'}")
        result["long_running_queries"] = long_running

        # Database sizes
        if database:
            cursor.execute(f"""
                SELECT table_name,
                       ROUND((data_length + index_length) / 1024 / 1024, 2) AS size_mb
                FROM information_schema.tables
                WHERE table_schema = '{database}'
                ORDER BY size_mb DESC
                LIMIT 10
            """)
            tables = cursor.fetchall()
            result["top_tables_by_size"] = [
                {"table": t[0], "size_mb": float(t[1])} for t in tables
            ]

        cursor.close()
        conn.close()

    except ImportError:
        return {"error": "pymysql not installed. Run: pip install pymysql", "detected_issues": ["MYSQL_DRIVER_NOT_INSTALLED"]}
    except Exception as e:
        error_msg = str(e)
        result["connection_status"] = "failed"
        result["connection_error"] = error_msg

        if "Connection refused" in error_msg or "Can't connect" in error_msg:
            issues.append(f"MYSQL_CONNECTION_REFUSED:{host}:{port}")
        elif "Access denied" in error_msg:
            issues.append(f"MYSQL_AUTH_FAILED:user={user}")
        elif "Unknown database" in error_msg:
            issues.append(f"MYSQL_DATABASE_NOT_FOUND:{database}")
        else:
            issues.append(f"MYSQL_ERROR:{error_msg[:200]}")

    result["detected_issues"] = issues
    return result


def inspect_mysql_via_winrm(conn, mysql_path: str = "C:\\Program Files\\MySQL\\MySQL Server 8.0\\bin\\mysql.exe") -> dict:
    """
    Check MySQL service status on Windows via WinRM when direct TCP isn't available.
    """
    issues = []
    result = {}

    # Check MySQL service
    svc = conn.run("""
        $svc = Get-Service -Name 'MySQL*' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($svc) { Write-Output "$($svc.Name)|$($svc.Status)" } else { Write-Output "NOT_FOUND" }
    """)
    if svc["success"]:
        if "NOT_FOUND" in svc["stdout"]:
            issues.append("MYSQL_SERVICE_NOT_FOUND")
            result["mysql_service"] = "not_installed"
        else:
            parts = svc["stdout"].split("|")
            result["mysql_service"] = {"name": parts[0], "status": parts[1] if len(parts) > 1 else "unknown"}
            if len(parts) > 1 and parts[1].strip() != "Running":
                issues.append(f"MYSQL_SERVICE_NOT_RUNNING:{parts[1]}")

    # MySQL error log (last 20 lines)
    log = conn.run("""
        $logPaths = @(
            "C:\\ProgramData\\MySQL\\MySQL Server 8.0\\Data\\*.err",
            "C:\\ProgramData\\MySQL\\MySQL Server 5.7\\Data\\*.err"
        )
        foreach ($path in $logPaths) {
            $file = Get-ChildItem $path -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($file) {
                Get-Content $file.FullName -Tail 20
                break
            }
        }
    """)
    if svc["success"] and log["stdout"]:
        result["mysql_error_log"] = log["stdout"]
        if "error" in log["stdout"].lower():
            issues.append("MYSQL_ERRORS_IN_LOG")

    result["detected_issues"] = issues
    return result
