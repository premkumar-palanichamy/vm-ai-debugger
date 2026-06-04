# 🖥 VM AI Debugger

AI-powered Windows and Linux VM troubleshooting with actionable fixes.

Connects to your VMs via WinRM (Windows) or SSH (Linux), collects diagnostic evidence across IIS, .NET apps, MySQL, Event Viewer, SSL, and system resources, then uses Claude/Gemini/OpenRouter to identify the root cause and provide exact fix commands.

## What it detects

| Category | What it checks |
|---|---|
| `iis_failure` | IIS app pool stopped, W3SVC down, site not started |
| `dotnet_crash` | ASP.NET Core unhandled exception, startup failure, missing DLLs |
| `saml2_error` | Metadata file missing, wrong entity ID, SSO config error |
| `mysql_down` | MySQL service stopped, connection refused, auth failed |
| `mysql_performance` | Slow queries, too many connections, buffer pool full |
| `high_cpu` | CPU critical, runaway process identified |
| `high_memory` | Memory exhaustion, OOM kill |
| `disk_full` | Disk usage critical on OS or data drive |
| `ssl_expiry` | Certificate expired or expiring within 30 days |
| `network_blocked` | Port blocked, firewall rule, DNS failure |
| `service_crashed` | Windows service stopped unexpectedly |
| `config_error` | appsettings.json misconfigured, missing env vars |
| `pending_reboot` | Windows update pending restart causing instability |

## Architecture

```
Windows VM (WinRM)          Linux VM (SSH)
        ↓                           ↓
backend/tools/
  ├── winrm_connector.py    SSH connector
  ├── ssh_connector.py      WinRM connector
  ├── iis_inspector.py      IIS app pools + sites
  ├── dotnet_inspector.py   ASP.NET Core + SAML2 config
  ├── windows_events.py     Event Viewer errors + crash dumps
  ├── mysql_inspector.py    MySQL service + queries
  ├── system_inspector.py   CPU, memory, disk
  └── network_inspector.py  Ports, SSL, DNS
        ↓
backend/agents/
  ├── investigator.py       Evidence gathering + LLM analysis
  └── ensemble.py           Multi-model correlation (auto)
        ↓
backend/db/database.py      SQLite — investigation history
        ↓
FastAPI backend + dark mode dashboard
```

## Quick start

```bash
git clone https://github.com/premkumar-palanichamy/vm-ai-debugger.git
cd vm-ai-debugger
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` with your VM credentials and at least one LLM API key:

```env
# LLM (add one or more — auto-detects ensemble mode)
OPENROUTER_API_KEY=sk-or-...

# Windows VM
VM_WINDOWS_HOST=192.168.1.100
VM_WINDOWS_USER=Administrator
VM_WINDOWS_PASSWORD=your_password

# MySQL (optional — direct connection)
MYSQL_HOST=localhost
MYSQL_USER=root
MYSQL_PASSWORD=your_password
```

Run:

```bash
PYTHONPATH=. uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

Open:
- Dashboard: http://localhost:8000
- API docs: http://localhost:8000/docs

## Enabling WinRM on Windows Server

Run this in PowerShell as Administrator on the target Windows VM:

```powershell
# Enable WinRM
Enable-PSRemoting -Force

# Allow unencrypted (for HTTP — use HTTPS in production)
winrm set winrm/config/service '@{AllowUnencrypted="true"}'
winrm set winrm/config/service/auth '@{Basic="true"}'

# Open firewall port
netsh advfirewall firewall add rule name="WinRM HTTP" dir=in action=allow protocol=TCP localport=5985

# Verify
winrm enumerate winrm/config/listener
```

## LLM configuration

Same automatic ensemble as k8s-ai-debugger:

| Keys configured | Mode |
|---|---|
| 1 key | Single model |
| 2 keys | 2-way correlation |
| 3 keys | Full ensemble |

```env
ANTHROPIC_API_KEY=sk-ant-...
OPENROUTER_API_KEY=sk-or-...
GEMINI_API_KEY=...
```

## API usage

```bash
# Full VM investigation
curl -X POST http://localhost:8000/api/v1/investigate/sync \
  -H "Content-Type: application/json" \
  -d '{"site_name": "ConpendQA1", "target_host": "qa1.conpend.ai"}'

# Async investigation
curl -X POST http://localhost:8000/api/v1/investigate \
  -H "Content-Type: application/json" \
  -d '{"site_name": "ConpendQA1", "check_mysql": true, "check_network": true}'

# Health check (shows what's configured)
curl http://localhost:8000/api/v1/health
```

## Project structure

```
vm-ai-debugger/
├── backend/
│   ├── main.py
│   ├── agents/
│   │   ├── investigator.py
│   │   └── ensemble.py
│   ├── api/
│   │   └── routes.py
│   ├── db/
│   │   └── database.py
│   └── tools/
│       ├── winrm_connector.py
│       ├── ssh_connector.py
│       ├── iis_inspector.py
│       ├── dotnet_inspector.py
│       ├── windows_events.py
│       ├── mysql_inspector.py
│       ├── system_inspector.py
│       └── network_inspector.py
└── frontend/
    └── index.html
```

## 📝 License

MIT License

## 🌐 Connect With Me

🏠 [Portfolio](https://ladviksolutions.netlify.app/)<br>
🐙 [GitHub](https://github.com/premkumar-palanichamy)<br>
💼 [LinkedIn](https://linkedin.com/in/premkumarpalanichamy)<br>
▶️ [YouTube](https://www.youtube.com/channel/UCJKEn6HeAxRNirDMBwFfi3w)
