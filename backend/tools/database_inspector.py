"""
Database Inspector — unified support for MySQL and SQL Server.

Auto-detects which database is configured in .env and runs
the appropriate checks. Supports both direct TCP connection
and WinRM passthrough (for DBs only accessible from inside the VM).

Supported:
  MySQL      → MYSQL_HOST in .env
  SQL Server → SQLSERVER_HOST in .env
"""
import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)


# ── Auto-detect which DBs are configured ─────────────────────────────

def get_configured_databases() -> list[dict]:
    """
    Reads .env and returns all configured database connections.
    Each entry has: type, host, port, user, password, databases[]
    """
    configured = []

    # MySQL
    if os.getenv("MYSQL_HOST", "").strip():
        configured.append({
            "type": "mysql",
            "host": os.getenv("MYSQL_HOST", "localhost"),
            "port": int(os.getenv("MYSQL_PORT", "3306")),
            "user": os.getenv("MYSQL_USER", "root"),
            "password": os.getenv("MYSQL_PASSWORD", ""),
            "databases": [d.strip() for d in os.getenv("MYSQL_DATABASES", os.getenv("MYSQL_DATABASE", "")).split(",") if d.strip()],
        })

    # SQL Server
    if os.getenv("SQLSERVER_HOST", "").strip():
        configured.append({
            "type": "sqlserver",
            "host": os.getenv("SQLSERVER_HOST", ""),
            "port": int(os.getenv("SQLSERVER_PORT", "1433")),
            "user": os.getenv("SQLSERVER_USER", "sa"),
            "password": os.getenv("SQLSERVER_PASSWORD", ""),
            "encrypt": os.getenv("SQLSERVER_ENCRYPT", "false").lower() == "true",
            # If SQLSERVER_DATABASES not set → auto-discovers from SQL Server
            "databases": [d.strip() for d in os.getenv("SQLSERVER_DATABASES", "").split(",") if d.strip()],
            "db_filter": os.getenv("SQLSERVER_DB_FILTER", ""),  # optional prefix filter
        })

    return configured


def inspect_all_databases(winrm_conn=None) -> dict:
    """
    Main entry point — inspects all configured databases.
    Tries direct TCP first, falls back to WinRM if available.
    """
    configured = get_configured_databases()

    if not configured:
        return {"status": "not_configured", "databases": []}

    results = []
    all_issues = []

    for db_config in configured:
        if db_config["type"] == "mysql":
            result = _inspect_mysql(db_config, winrm_conn)
        elif db_config["type"] == "sqlserver":
            result = _inspect_sqlserver(db_config, winrm_conn)
        else:
            result = {"type": db_config["type"], "error": "unsupported"}

        results.append(result)
        all_issues.extend(result.get("detected_issues", []))

    return {
        "databases": results,
        "detected_issues": all_issues,
        "total_configured": len(configured),
    }


# ── MySQL ─────────────────────────────────────────────────────────────

def _inspect_mysql(config: dict, winrm_conn=None) -> dict:
    """Inspect MySQL — direct TCP or via WinRM."""
    issues = []
    result = {"type": "mysql", "host": config["host"], "port": config["port"]}

    # Try direct TCP connection first
    try:
        import pymysql
        conn = pymysql.connect(
            host=config["host"],
            port=config["port"],
            user=config["user"],
            password=config["password"],
            connect_timeout=10,
            charset="utf8mb4",
        )
        result["connection_method"] = "direct_tcp"
        result.update(_run_mysql_checks(conn, config["databases"]))
        conn.close()

    except ImportError:
        issues.append("MYSQL_DRIVER_NOT_INSTALLED:run pip install pymysql")
        result["detected_issues"] = issues
        return result

    except Exception as e:
        error = str(e)
        result["direct_tcp_error"] = error

        # Fall back to WinRM if available
        if winrm_conn:
            logger.info("MySQL direct TCP failed, trying via WinRM")
            result["connection_method"] = "winrm_passthrough"
            result.update(_mysql_via_winrm(winrm_conn, config))
        else:
            result["connection_status"] = "failed"
            if "Connection refused" in error:
                issues.append(f"MYSQL_CONNECTION_REFUSED:{config['host']}:{config['port']}")
            elif "Access denied" in error:
                issues.append(f"MYSQL_AUTH_FAILED:user={config['user']}")
            else:
                issues.append(f"MYSQL_ERROR:{error[:200]}")
            result["detected_issues"] = issues

    return result


def _run_mysql_checks(conn, databases: list) -> dict:
    """Run MySQL health queries on an open connection."""
    issues = []
    result = {"connection_status": "connected"}
    cursor = conn.cursor()

    # Version
    cursor.execute("SELECT VERSION()")
    result["version"] = cursor.fetchone()[0]

    # Connections
    cursor.execute("SHOW GLOBAL STATUS LIKE 'Threads_connected'")
    threads_connected = int(cursor.fetchone()[1])
    cursor.execute("SHOW GLOBAL VARIABLES LIKE 'max_connections'")
    max_conn = int(cursor.fetchone()[1])
    conn_pct = round((threads_connected / max_conn) * 100, 1)
    result["connections"] = {"current": threads_connected, "max": max_conn, "usage_percent": conn_pct}
    if conn_pct > 80:
        issues.append(f"MYSQL_HIGH_CONNECTIONS:{conn_pct}%_of_{max_conn}")

    # Slow queries
    cursor.execute("SHOW GLOBAL STATUS LIKE 'Slow_queries'")
    slow = int(cursor.fetchone()[1])
    result["slow_queries"] = slow
    if slow > 100:
        issues.append(f"MYSQL_SLOW_QUERIES:{slow}")

    # Long running queries
    cursor.execute("SHOW FULL PROCESSLIST")
    long_running = [
        {"id": r[0], "user": r[1], "db": r[3], "time": r[5], "query": str(r[7])[:150] if r[7] else ""}
        for r in cursor.fetchall() if r[5] and int(r[5]) > 30
    ]
    result["long_running_queries"] = long_running
    for q in long_running:
        issues.append(f"MYSQL_LONG_QUERY:{q['time']}s:{q['query'][:80]}")

    # Per-database sizes
    if databases:
        db_list = "','".join(databases)
        cursor.execute(f"""
            SELECT table_schema,
                   ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS size_mb
            FROM information_schema.tables
            WHERE table_schema IN ('{db_list}')
            GROUP BY table_schema
        """)
        result["database_sizes_mb"] = {row[0]: float(row[1]) for row in cursor.fetchall()}

    cursor.close()
    result["detected_issues"] = issues
    return result


def _mysql_via_winrm(conn, config: dict) -> dict:
    """Check MySQL service status on Windows via WinRM."""
    issues = []
    result = {}

    svc = conn.run("""
        $svc = Get-Service -Name 'MySQL*' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($svc) { Write-Output "$($svc.Name)|$($svc.Status)" } else { Write-Output "NOT_FOUND" }
    """)
    if svc["success"]:
        if "NOT_FOUND" in svc["stdout"]:
            issues.append("MYSQL_SERVICE_NOT_INSTALLED")
        else:
            parts = svc["stdout"].split("|")
            status = parts[1].strip() if len(parts) > 1 else "unknown"
            result["service"] = {"name": parts[0], "status": status}
            if status != "Running":
                issues.append(f"MYSQL_SERVICE_NOT_RUNNING:{status}")

    result["detected_issues"] = issues
    return result


# ── SQL Server ────────────────────────────────────────────────────────

def _inspect_sqlserver(config: dict, winrm_conn=None) -> dict:
    """Inspect SQL Server — direct TCP or via WinRM."""
    issues = []
    result = {
        "type": "sqlserver",
        "host": config["host"],
        "port": config["port"],
        "databases": config["databases"],
    }

    # Try direct TCP first (pymssql)
    try:
        import pymssql
        # Handle named instance (e.g. WIN-918N8Q7JDCM\SQLEXPRESS)
        host = config["host"]
        conn = pymssql.connect(
            server=host,
            port=config["port"],
            user=config["user"],
            password=config["password"],
            tds_version="7.0",
            login_timeout=10,
        )
        result["connection_method"] = "direct_tcp"
        result.update(_run_sqlserver_checks(conn, config["databases"]))
        conn.close()

    except ImportError:
        # Try pyodbc as alternative
        try:
            result.update(_sqlserver_via_pyodbc(config))
            result["connection_method"] = "pyodbc"
        except Exception:
            if winrm_conn:
                logger.info("SQL Server direct TCP failed, trying via WinRM")
                result["connection_method"] = "winrm_passthrough"
                result.update(_sqlserver_via_winrm(winrm_conn, config))
            else:
                issues.append("SQLSERVER_DRIVER_NOT_INSTALLED:run pip install pymssql")
                result["detected_issues"] = issues
            return result

    except Exception as e:
        error = str(e)
        result["direct_tcp_error"] = error

        # Fall back to WinRM
        if winrm_conn:
            logger.info("SQL Server direct TCP failed (%s), trying via WinRM", error[:80])
            result["connection_method"] = "winrm_passthrough"
            result.update(_sqlserver_via_winrm(winrm_conn, config))
        else:
            result["connection_status"] = "failed"
            if "Connection refused" in error or "No connection" in error:
                issues.append(f"SQLSERVER_CONNECTION_REFUSED:{config['host']}:{config['port']}")
            elif "Login failed" in error:
                issues.append(f"SQLSERVER_AUTH_FAILED:user={config['user']}")
            else:
                issues.append(f"SQLSERVER_ERROR:{error[:200]}")
            result["detected_issues"] = issues

    return result


def _run_sqlserver_checks(conn, databases: list) -> dict:
    """Run SQL Server health queries on an open connection."""
    issues = []
    result = {"connection_status": "connected"}
    cursor = conn.cursor()

    # Version
    cursor.execute("SELECT @@VERSION")
    version = cursor.fetchone()[0]
    result["version"] = version.split("\n")[0] if version else "unknown"

    # Active connections per database
    cursor.execute("""
        SELECT DB_NAME(database_id) as db_name, COUNT(*) as connections
        FROM sys.dm_exec_sessions
        WHERE is_user_process = 1
        GROUP BY database_id
        ORDER BY connections DESC
    """)
    result["connections_per_db"] = {row[0]: row[1] for row in cursor.fetchall()}

    # Long running queries (> 30 seconds)
    cursor.execute("""
        SELECT
            r.session_id,
            DB_NAME(r.database_id) as database_name,
            r.status,
            r.wait_type,
            r.wait_time / 1000 as wait_seconds,
            r.total_elapsed_time / 1000 as elapsed_seconds,
            SUBSTRING(st.text, (r.statement_start_offset/2)+1,
                ((CASE r.statement_end_offset WHEN -1 THEN DATALENGTH(st.text)
                ELSE r.statement_end_offset END - r.statement_start_offset)/2)+1) AS query_text
        FROM sys.dm_exec_requests r
        CROSS APPLY sys.dm_exec_sql_text(r.sql_handle) st
        WHERE r.total_elapsed_time > 30000
        AND r.session_id != @@SPID
        ORDER BY r.total_elapsed_time DESC
    """)
    long_running = []
    for row in cursor.fetchall():
        long_running.append({
            "session_id": row[0],
            "database": row[1],
            "status": row[2],
            "wait_type": row[3],
            "wait_seconds": row[4],
            "elapsed_seconds": row[5],
            "query": str(row[6])[:200] if row[6] else "",
        })
        issues.append(f"SQLSERVER_LONG_QUERY:{row[5]}s:db={row[1]}:{str(row[6])[:80] if row[6] else 'unknown'}")
    result["long_running_queries"] = long_running

    # Blocking queries
    cursor.execute("""
        SELECT
            blocking_session_id,
            session_id,
            DB_NAME(database_id) as database_name,
            wait_type,
            wait_time / 1000 as wait_seconds
        FROM sys.dm_exec_requests
        WHERE blocking_session_id > 0
    """)
    blocking = [{"blocked_by": r[0], "session_id": r[1], "database": r[2], "wait_type": r[3], "wait_seconds": r[4]}
                for r in cursor.fetchall()]
    result["blocking_queries"] = blocking
    if blocking:
        issues.append(f"SQLSERVER_BLOCKING_DETECTED:{len(blocking)}_blocked_sessions")

    # Auto-discover databases if not explicitly configured
    db_filter = ""
    if not databases:
        try:
            cursor.execute("""
                SELECT name FROM sys.databases
                WHERE name NOT IN ('master','tempdb','model','msdb')
                AND state_desc = 'ONLINE'
                ORDER BY name
            """)
            databases = [row[0] for row in cursor.fetchall()]
            result["databases_auto_discovered"] = True
            logger.info("Auto-discovered %d databases from SQL Server", len(databases))
        except Exception as e:
            logger.warning("Could not auto-discover databases: %s", e)

    # Apply optional filter (e.g. SQLSERVER_DB_FILTER=QA → only QA* databases)
    if db_filter and databases:
        databases = [d for d in databases if d.startswith(db_filter)]
        logger.info("Filtered to %d databases matching '%s'", len(databases), db_filter)

    result["discovered_databases"] = databases

    # Get size and status for all discovered databases
    if databases:
        db_info = []
        for db_name in databases:
            try:
                cursor.execute("""
                    SELECT
                        name,
                        state_desc,
                        recovery_model_desc,
                        ROUND(SUM(size * 8.0 / 1024), 2) as size_mb
                    FROM sys.databases d
                    JOIN sys.master_files f ON d.database_id = f.database_id
                    WHERE name = %s
                    GROUP BY name, state_desc, recovery_model_desc
                """, (db_name,))
                row = cursor.fetchone()
                if row:
                    db_status = {
                        "name": row[0],
                        "state": row[1],
                        "recovery_model": row[2],
                        "size_mb": float(row[3]),
                    }
                    if row[1] != "ONLINE":
                        issues.append(f"SQLSERVER_DB_NOT_ONLINE:{row[0]}:{row[1]}")
                    db_info.append(db_status)
                else:
                    issues.append(f"SQLSERVER_DB_NOT_FOUND:{db_name}")
            except Exception as e:
                db_info.append({"name": db_name, "error": str(e)})
        result["database_info"] = db_info

    # Failed SQL Agent jobs (last 24 hours)
    try:
        cursor.execute("""
            SELECT TOP 5
                j.name as job_name,
                h.run_date,
                h.run_time,
                h.message
            FROM msdb.dbo.sysjobhistory h
            JOIN msdb.dbo.sysjobs j ON h.job_id = j.job_id
            WHERE h.run_status = 0
            AND h.step_id = 0
            ORDER BY h.run_date DESC, h.run_time DESC
        """)
        failed_jobs = [{"job": r[0], "date": str(r[1]), "time": str(r[2]), "message": str(r[3])[:200]}
                      for r in cursor.fetchall()]
        result["failed_sql_agent_jobs"] = failed_jobs
        if failed_jobs:
            issues.append(f"SQLSERVER_FAILED_JOBS:{len(failed_jobs)}_failed_recently")
    except Exception:
        pass  # msdb might not be accessible

    cursor.close()
    result["detected_issues"] = issues
    return result


def _sqlserver_via_pyodbc(config: dict) -> dict:
    """Try SQL Server connection via pyodbc (alternative driver)."""
    import pyodbc
    conn_str = (
        f"DRIVER={{ODBC Driver 17 for SQL Server}};"
        f"SERVER={config['host']},{config['port']};"
        f"UID={config['user']};"
        f"PWD={config['password']};"
        f"Encrypt={'yes' if config.get('encrypt') else 'no'};"
        f"TrustServerCertificate=yes;"
    )
    conn = pyodbc.connect(conn_str, timeout=10)
    result = _run_sqlserver_checks(conn, config["databases"])
    conn.close()
    return result


def _sqlserver_via_winrm(conn, config: dict) -> dict:
    """
    Run SQL Server checks via WinRM using sqlcmd.
    Used when direct TCP connection is not available.
    """
    issues = []
    result = {}

    host = config["host"]
    user = config["user"]
    password = config["password"]
    databases = config["databases"]

    # Check SQL Server service
    svc = conn.run("""
        $svc = Get-Service -Name 'MSSQL*' -ErrorAction SilentlyContinue
        $svc | ForEach-Object { "$($_.Name)|$($_.Status)" }
    """)
    if svc["success"] and svc["stdout"]:
        services = []
        for line in svc["stdout"].splitlines():
            parts = line.split("|")
            if len(parts) == 2:
                status = parts[1].strip()
                services.append({"name": parts[0], "status": status})
                if status != "Running":
                    issues.append(f"SQLSERVER_SERVICE_NOT_RUNNING:{parts[0]}:{status}")
        result["sql_services"] = services
    else:
        issues.append("SQLSERVER_SERVICE_NOT_FOUND")

    # Auto-discover databases via sqlcmd if not explicitly listed
    db_filter = config.get("db_filter", "")
    if not databases:
        discover = conn.run(f"""
            $dbs = sqlcmd -S "{host}" -U "{user}" -P "{password}" -Q "
                SET NOCOUNT ON;
                SELECT name FROM sys.databases
                WHERE name NOT IN ('master','tempdb','model','msdb')
                AND state_desc = 'ONLINE'
                ORDER BY name
            " -h -1 -W 2>&1
            Write-Output $dbs
        """)
        if discover["success"] and discover["stdout"]:
            databases = [line.strip() for line in discover["stdout"].splitlines()
                        if line.strip() and not line.strip().startswith("(") and not line.strip().startswith("-")]
            result["databases_auto_discovered"] = True

    # Apply optional filter
    if db_filter and databases:
        databases = [d for d in databases if d.startswith(db_filter)]

    result["discovered_databases"] = databases

    # Check each database
    db_results = []
    for db_name in databases:
        db_check = conn.run(f"""
            $result = sqlcmd -S "{host}" -U "{user}" -P "{password}" -d "{db_name}" -Q "
                SET NOCOUNT ON;
                SELECT
                    DB_NAME() as db_name,
                    (SELECT COUNT(*) FROM sys.dm_exec_sessions WHERE is_user_process=1 AND DB_NAME(database_id)=DB_NAME()) as connections,
                    (SELECT COUNT(*) FROM sys.dm_exec_requests WHERE blocking_session_id > 0) as blocking
            " -h -1 -W 2>&1
            Write-Output $result
        """)
        db_info = {"name": db_name}
        if db_check["success"] and db_check["stdout"]:
            db_info["raw_output"] = db_check["stdout"][:300]
            if "error" in db_check["stdout"].lower() or "failed" in db_check["stdout"].lower():
                issues.append(f"SQLSERVER_DB_ERROR:{db_name}:{db_check['stdout'][:150]}")
        else:
            db_info["error"] = db_check["stderr"][:200]
            issues.append(f"SQLSERVER_DB_UNREACHABLE:{db_name}")
        db_results.append(db_info)
    result["database_checks"] = db_results

    # SQL Server error log (last 20 lines)
    error_log = conn.run("""
        $logPath = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\*\\Setup' -ErrorAction SilentlyContinue).SQLPath
        if ($logPath) {
            $errorLog = Join-Path $logPath "LOG\\ERRORLOG"
            if (Test-Path $errorLog) {
                Get-Content $errorLog -Tail 20
            }
        }
    """)
    if error_log["success"] and error_log["stdout"]:
        result["error_log_tail"] = error_log["stdout"]
        if "error" in error_log["stdout"].lower():
            issues.append("SQLSERVER_ERRORS_IN_LOG")

    result["detected_issues"] = issues
    return result
