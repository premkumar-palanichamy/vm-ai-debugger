"""
Service Detector — auto-detects what web servers, app servers,
databases, and runtimes are running on a Windows or Linux VM.

Used by investigator.py to build a dynamic LLM prompt
based on what's actually installed — not hardcoded assumptions.
"""
import logging
from typing import Optional

logger = logging.getLogger(__name__)


# ── Windows service detection ─────────────────────────────────────────

def detect_windows_services(conn) -> dict:
    """
    Detect all running services and installed software on a Windows VM.
    Returns structured dict of what's found.
    """
    detected = {
        "web_servers": [],
        "app_servers": [],
        "databases": [],
        "runtimes": [],
        "other_services": [],
        "raw_services": [],
    }

    # Get all running services in one call
    services = conn.run("""
        Get-Service | Where-Object { $_.Status -eq 'Running' } |
        ForEach-Object { "$($_.Name)|$($_.DisplayName)" }
    """)

    running = {}
    if services["success"] and services["stdout"]:
        for line in services["stdout"].splitlines():
            parts = line.split("|", 1)
            if len(parts) == 2:
                running[parts[0].lower()] = parts[1]
        detected["raw_services"] = list(running.keys())

    # ── Web Servers ───────────────────────────────────────────────────
    if "w3svc" in running:
        detected["web_servers"].append("IIS")
    if any(k in running for k in ["apache", "apache2", "httpd"]):
        detected["web_servers"].append("Apache")
    if any(k in running for k in ["nginx", "nginx service"]):
        detected["web_servers"].append("Nginx")

    # ── App Servers ───────────────────────────────────────────────────
    # Tomcat
    tomcat = conn.run("""
        Get-Service | Where-Object { $_.Name -like '*tomcat*' -or $_.DisplayName -like '*tomcat*' } |
        Select-Object -First 1 -ExpandProperty DisplayName
    """)
    if tomcat["success"] and tomcat["stdout"].strip():
        detected["app_servers"].append("Tomcat")

    # Check for Java processes
    java_proc = conn.run("""
        Get-Process -Name 'java','javaw' -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty Name
    """)
    if java_proc["success"] and java_proc["stdout"].strip():
        if "Tomcat" not in detected["app_servers"]:
            detected["app_servers"].append("Java")

    # .NET / Kestrel
    dotnet_proc = conn.run("""
        Get-Process -Name 'dotnet','w3wp' -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty Name
    """)
    if dotnet_proc["success"] and dotnet_proc["stdout"].strip():
        detected["app_servers"].append("DotNet")

    # Node.js
    node_proc = conn.run("""
        Get-Process -Name 'node' -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty Name
    """)
    if node_proc["success"] and node_proc["stdout"].strip():
        detected["app_servers"].append("NodeJS")

    # Python
    python_proc = conn.run("""
        Get-Process -Name 'python','python3','pythonw' -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty Name
    """)
    if python_proc["success"] and python_proc["stdout"].strip():
        detected["app_servers"].append("Python")

    # ── Databases ─────────────────────────────────────────────────────
    # SQL Server
    if any(k.startswith("mssql") for k in running):
        detected["databases"].append("SQLServer")

    # MySQL
    if any(k.startswith("mysql") for k in running):
        detected["databases"].append("MySQL")

    # PostgreSQL
    if any(k.startswith("postgresql") or k == "pg" for k in running):
        detected["databases"].append("PostgreSQL")

    # MongoDB
    if any(k.startswith("mongodb") or k == "mongod" for k in running):
        detected["databases"].append("MongoDB")

    # Redis
    if any(k.startswith("redis") for k in running):
        detected["databases"].append("Redis")

    # ── Runtimes ──────────────────────────────────────────────────────
    # .NET version
    dotnet_ver = conn.run("""
        if (Get-Command dotnet -ErrorAction SilentlyContinue) {
            dotnet --version
        }
    """)
    if dotnet_ver["success"] and dotnet_ver["stdout"].strip():
        detected["runtimes"].append(f"DotNet-{dotnet_ver['stdout'].strip()}")

    # Java version
    java_ver = conn.run("""
        if (Get-Command java -ErrorAction SilentlyContinue) {
            java -version 2>&1 | Select-Object -First 1
        }
    """)
    if java_ver["success"] and java_ver["stdout"].strip():
        detected["runtimes"].append(f"Java")

    # Python version
    python_ver = conn.run("""
        if (Get-Command python -ErrorAction SilentlyContinue) {
            python --version 2>&1
        }
    """)
    if python_ver["success"] and python_ver["stdout"].strip():
        detected["runtimes"].append(f"Python")

    # Node version
    node_ver = conn.run("""
        if (Get-Command node -ErrorAction SilentlyContinue) {
            node --version
        }
    """)
    if node_ver["success"] and node_ver["stdout"].strip():
        detected["runtimes"].append(f"NodeJS-{node_ver['stdout'].strip()}")

    logger.info(
        "Detected on Windows VM: web=%s app=%s db=%s runtime=%s",
        detected["web_servers"],
        detected["app_servers"],
        detected["databases"],
        detected["runtimes"],
    )
    return detected


# ── Linux service detection ───────────────────────────────────────────

def detect_linux_services(conn) -> dict:
    """
    Detect all running services and installed software on a Linux VM.
    """
    detected = {
        "web_servers": [],
        "app_servers": [],
        "databases": [],
        "runtimes": [],
        "other_services": [],
    }

    # Get all active systemd services
    services = conn.run(
        "systemctl list-units --type=service --state=running --no-pager --no-legend | awk '{print $1}'"
    )
    running = []
    if services["success"] and services["stdout"]:
        running = [s.strip().replace(".service", "").lower()
                   for s in services["stdout"].splitlines()]

    # ── Web Servers ───────────────────────────────────────────────────
    if "nginx" in running:
        detected["web_servers"].append("Nginx")
    if any(s in running for s in ["apache2", "httpd"]):
        detected["web_servers"].append("Apache")

    # ── App Servers ───────────────────────────────────────────────────
    if any("tomcat" in s for s in running):
        detected["app_servers"].append("Tomcat")
    if any("gunicorn" in s for s in running):
        detected["app_servers"].append("Gunicorn")
    if any("uvicorn" in s for s in running):
        detected["app_servers"].append("Uvicorn")
    if any("pm2" in s for s in running):
        detected["app_servers"].append("PM2-NodeJS")

    # Check processes for more coverage
    procs = conn.run("ps aux | awk '{print $11}' | sort -u")
    if procs["success"] and procs["stdout"]:
        proc_list = procs["stdout"].lower()
        if "java" in proc_list and "Tomcat" not in detected["app_servers"]:
            detected["app_servers"].append("Java")
        if "node" in proc_list and "PM2-NodeJS" not in detected["app_servers"]:
            detected["app_servers"].append("NodeJS")
        if "python" in proc_list:
            detected["app_servers"].append("Python")
        if "dotnet" in proc_list:
            detected["app_servers"].append("DotNet")

    # ── Databases ─────────────────────────────────────────────────────
    if any(s in running for s in ["mysql", "mysqld", "mariadb"]):
        detected["databases"].append("MySQL")
    if any("postgresql" in s or s == "postgres" for s in running):
        detected["databases"].append("PostgreSQL")
    if any("mongodb" in s or s == "mongod" for s in running):
        detected["databases"].append("MongoDB")
    if any("redis" in s for s in running):
        detected["databases"].append("Redis")
    if any("elasticsearch" in s for s in running):
        detected["databases"].append("Elasticsearch")

    # ── Runtimes ──────────────────────────────────────────────────────
    for cmd, label in [("java -version 2>&1 | head -1", "Java"),
                       ("python3 --version", "Python"),
                       ("node --version", "NodeJS"),
                       ("dotnet --version", "DotNet")]:
        result = conn.run(f"command -v {cmd.split()[0]} && {cmd} 2>/dev/null || true")
        if result["success"] and result["stdout"].strip():
            detected["runtimes"].append(label)

    logger.info(
        "Detected on Linux VM: web=%s app=%s db=%s",
        detected["web_servers"],
        detected["app_servers"],
        detected["databases"],
    )
    return detected


# ── Dynamic prompt builder ────────────────────────────────────────────

def build_system_prompt(detected: dict) -> str:
    """
    Build a dynamic LLM system prompt based on detected services.
    Only includes relevant context and failure categories.
    """
    web = detected.get("web_servers", [])
    app = detected.get("app_servers", [])
    dbs = detected.get("databases", [])
    runtimes = detected.get("runtimes", [])

    # Base intro
    stack_parts = []
    if web:
        stack_parts.append(f"web server: {', '.join(web)}")
    if app:
        stack_parts.append(f"app server: {', '.join(app)}")
    if dbs:
        stack_parts.append(f"database: {', '.join(dbs)}")

    stack_desc = " | ".join(stack_parts) if stack_parts else "general Windows/Linux server"

    prompt = f"""You are an expert Site Reliability Engineer (SRE) specializing in Windows and Linux VM troubleshooting.

This VM is running: {stack_desc}

This is NOT Kubernetes. Analyze the VM evidence and identify the root cause.

"""

    # Add technology-specific context
    if "IIS" in web:
        prompt += """IIS context: Check app pool state, W3SVC service, site bindings, and application errors.
"""
    if "Apache" in web:
        prompt += """Apache context: Check httpd service, virtual host config, error logs at /var/log/apache2/ or /var/log/httpd/.
"""
    if "Nginx" in web:
        prompt += """Nginx context: Check nginx service, site config in /etc/nginx/, error logs at /var/log/nginx/.
"""
    if "Tomcat" in app:
        prompt += """Tomcat context: Check catalina.out logs, JVM heap space, connector port availability, webapp deployment.
"""
    if "DotNet" in app:
        prompt += """ASP.NET Core context: Check dotnet process, appsettings.json, SAML2 metadata, app pool identity.
"""
    if "NodeJS" in app or "PM2-NodeJS" in app:
        prompt += """Node.js context: Check PM2 process list, node process, package.json, environment variables.
"""
    if "Python" in app or "Gunicorn" in app:
        prompt += """Python context: Check gunicorn/uvicorn process, virtual environment, requirements, app logs.
"""
    if "SQLServer" in dbs:
        prompt += """SQL Server context: Check MSSQL service, database state, blocking queries, disk space for data files.
"""
    if "MySQL" in dbs:
        prompt += """MySQL context: Check MySQL service, connection count, slow queries, InnoDB buffer pool.
"""
    if "PostgreSQL" in dbs:
        prompt += """PostgreSQL context: Check postgresql service, pg_hba.conf, connection limits, vacuum status.
"""
    if "MongoDB" in dbs:
        prompt += """MongoDB context: Check mongod service, replica set status, storage engine, oplog size.
"""
    if "Redis" in dbs:
        prompt += """Redis context: Check redis service, memory usage, eviction policy, persistence config.
"""

    # Build relevant failure categories
    categories = _build_categories(web, app, dbs)

    prompt += f"""
FAILURE CATEGORIES (pick exactly one):
{', '.join(categories)}

Respond ONLY with valid JSON — no markdown, no explanation outside JSON:
{{
  "root_cause": "concise description of root cause",
  "failure_category": "one category from the list above",
  "confidence": 85,
  "severity": "critical|high|medium|low",
  "signals": ["signal 1", "signal 2", "signal 3"],
  "affected_resources": ["Service/Name", "Drive/E:", "DB/DatabaseName"],
  "fix_recommendations": [
    {{
      "step": 1,
      "description": "what to do",
      "command": "exact PowerShell, bash, or CLI command",
      "expected_outcome": "what success looks like"
    }}
  ],
  "prevention": "how to prevent this in future",
  "summary": "2-3 sentence plain English explanation"
}}"""

    return prompt


def _build_categories(web: list, app: list, dbs: list) -> list:
    """Build relevant failure categories based on detected stack."""
    categories = []

    # Web server failures
    if "IIS" in web:
        categories.append("iis_failure")
    if "Apache" in web:
        categories.append("apache_failure")
    if "Nginx" in web:
        categories.append("nginx_failure")
    if "Tomcat" in app:
        categories.extend(["tomcat_failure", "java_crash"])
    if "DotNet" in app:
        categories.extend(["dotnet_crash", "saml2_error"])
    if "NodeJS" in app or "PM2-NodeJS" in app:
        categories.append("nodejs_crash")
    if "Python" in app or "Gunicorn" in app or "Uvicorn" in app:
        categories.append("python_crash")

    # Database failures
    if "SQLServer" in dbs:
        categories.extend(["sqlserver_down", "sqlserver_performance"])
    if "MySQL" in dbs:
        categories.extend(["mysql_down", "mysql_performance"])
    if "PostgreSQL" in dbs:
        categories.extend(["postgresql_down", "postgresql_performance"])
    if "MongoDB" in dbs:
        categories.append("mongodb_down")
    if "Redis" in dbs:
        categories.append("redis_down")

    # Always include system-level categories
    categories.extend([
        "high_cpu",
        "high_memory",
        "disk_full",
        "ssl_expiry",
        "network_blocked",
        "service_crashed",
        "config_error",
        "pending_reboot",
        "unknown",
    ])

    # Deduplicate while preserving order
    seen = set()
    return [c for c in categories if not (c in seen or seen.add(c))]
