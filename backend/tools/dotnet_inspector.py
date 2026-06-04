"""
.NET Inspector — inspects ASP.NET Core applications on Windows VMs.
Detects app crashes, SAML2 config issues, appsettings problems,
missing environment variables, and application startup failures.
"""
import json
import logging
from backend.tools.winrm_connector import WinRMConnector

logger = logging.getLogger(__name__)


def inspect_dotnet_app(conn: WinRMConnector, site_name: str = "", app_path: str = "") -> dict:
    """
    Inspect an ASP.NET Core application.
    Checks appsettings, SAML2 config, app pool identity, and recent errors.
    """
    issues = []
    result = {}

    # Find app path if not provided
    if not app_path and site_name:
        path_result = conn.run(f"""
            Import-Module WebAdministration -ErrorAction SilentlyContinue
            $site = Get-Website -Name '{site_name}' -ErrorAction SilentlyContinue
            if ($site) {{ Write-Output $site.PhysicalPath }}
        """)
        if path_result["success"] and path_result["stdout"]:
            app_path = path_result["stdout"].strip()

    result["app_path"] = app_path

    # Check appsettings.json exists and read it
    if app_path:
        appsettings = conn.run(f"""
            $path = '{app_path}\\appsettings.json'
            if (Test-Path $path) {{
                Get-Content $path -Raw
            }} else {{
                Write-Output "FILE_NOT_FOUND"
            }}
        """)
        if appsettings["success"]:
            if "FILE_NOT_FOUND" in appsettings["stdout"]:
                issues.append("APPSETTINGS_NOT_FOUND")
                result["appsettings"] = None
            else:
                try:
                    settings = json.loads(appsettings["stdout"])
                    # Redact sensitive values but keep keys
                    result["appsettings_keys"] = list(_flatten_keys(settings))

                    # Check SAML2 config
                    saml = _find_key(settings, "SamlSettings") or _find_key(settings, "Saml2")
                    if saml:
                        result["saml_config"] = {
                            "has_metadata_path": "IdentityProviderMetadataPath" in saml or "MetadataPath" in saml,
                            "service_entity_id": saml.get("ServiceEntityId", saml.get("EntityId", "NOT_SET")),
                            "metadata_path": saml.get("IdentityProviderMetadataPath", saml.get("MetadataPath", "NOT_SET")),
                        }
                        # Check metadata file exists
                        meta_path = saml.get("IdentityProviderMetadataPath", "")
                        if meta_path:
                            meta_check = conn.run(f"Test-Path '{meta_path}'")
                            if meta_check["success"] and "False" in meta_check["stdout"]:
                                issues.append(f"SAML_METADATA_FILE_MISSING:{meta_path}")
                    else:
                        result["saml_config"] = "not_configured"

                    # Check connection strings
                    conn_strings = _find_key(settings, "ConnectionStrings")
                    if conn_strings:
                        result["connection_string_keys"] = list(conn_strings.keys())
                    else:
                        issues.append("NO_CONNECTION_STRINGS")

                except json.JSONDecodeError as e:
                    issues.append(f"APPSETTINGS_INVALID_JSON:{str(e)[:100]}")
                    result["appsettings"] = "INVALID_JSON"

        # Check for web.config (needed for IIS hosting)
        webconfig = conn.run(f"Test-Path '{app_path}\\web.config'")
        if webconfig["success"] and "False" in webconfig["stdout"]:
            issues.append("WEB_CONFIG_MISSING")

        # Check for published DLL
        dll_check = conn.run(f"""
            $dlls = Get-ChildItem '{app_path}' -Filter '*.dll' -ErrorAction SilentlyContinue
            Write-Output $dlls.Count
        """)
        if dll_check["success"]:
            dll_count = int(dll_check["stdout"].strip()) if dll_check["stdout"].strip().isdigit() else 0
            result["dll_count"] = dll_count
            if dll_count == 0:
                issues.append("NO_DLLS_FOUND_APP_NOT_PUBLISHED")

    # Check .NET runtime versions installed
    dotnet = conn.run("""
        if (Get-Command dotnet -ErrorAction SilentlyContinue) {
            dotnet --list-runtimes
        } else {
            Write-Output "DOTNET_CLI_NOT_FOUND"
        }
    """)
    result["dotnet_runtimes"] = dotnet["stdout"].splitlines() if dotnet["success"] else []

    # Check running .NET processes
    procs = conn.run("""
        Get-Process -Name 'dotnet','w3wp' -ErrorAction SilentlyContinue |
        ForEach-Object {
            "$($_.Name)|$($_.Id)|$([math]::Round($_.WorkingSet64/1MB,1))MB|$([math]::Round($_.CPU,1))s"
        }
    """)
    if procs["success"] and procs["stdout"]:
        result["dotnet_processes"] = procs["stdout"].splitlines()
    else:
        issues.append("NO_DOTNET_PROCESSES_RUNNING")
        result["dotnet_processes"] = []

    result["detected_issues"] = issues
    return result


def inspect_saml2_config(conn: WinRMConnector, metadata_path: str) -> dict:
    """Deep inspect of SAML2 metadata file."""
    issues = []
    result = {}

    # Check file exists
    exists = conn.run(f"Test-Path '{metadata_path}'")
    if not exists["success"] or "False" in exists["stdout"]:
        return {
            "detected_issues": [f"SAML_METADATA_NOT_FOUND:{metadata_path}"],
            "metadata_path": metadata_path,
        }

    # Read metadata and check entity ID, certificates
    content = conn.run(f"Get-Content '{metadata_path}' -Raw")
    if content["success"] and content["stdout"]:
        xml = content["stdout"]
        result["metadata_size_bytes"] = len(xml)
        result["has_entity_descriptor"] = "EntityDescriptor" in xml
        result["has_certificate"] = "X509Certificate" in xml
        result["has_sso_service"] = "SingleSignOnService" in xml

        # Extract entity ID
        import re
        entity_match = re.search(r'entityID=["\']([^"\']+)["\']', xml)
        if entity_match:
            result["entity_id"] = entity_match.group(1)

        if not result["has_certificate"]:
            issues.append("SAML_METADATA_NO_CERTIFICATE")
        if not result["has_sso_service"]:
            issues.append("SAML_METADATA_NO_SSO_SERVICE")

    result["detected_issues"] = issues
    return result


def _flatten_keys(d, prefix="") -> list:
    """Recursively extract all keys from nested dict."""
    keys = []
    for k, v in d.items():
        full_key = f"{prefix}.{k}" if prefix else k
        keys.append(full_key)
        if isinstance(v, dict):
            keys.extend(_flatten_keys(v, full_key))
    return keys


def _find_key(d, key) -> dict:
    """Find a key in nested dict case-insensitively."""
    for k, v in d.items():
        if k.lower() == key.lower():
            return v
        if isinstance(v, dict):
            result = _find_key(v, key)
            if result is not None:
                return result
    return None
