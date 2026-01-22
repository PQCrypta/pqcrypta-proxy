# Windows Service Installation

PQCrypta Proxy can run as a Windows Service using either NSSM (Non-Sucking Service Manager) or the native `sc.exe` command.

## Prerequisites

1. Windows Server 2016 or later / Windows 10 or later
2. Administrator privileges
3. OpenSSL 3.x installed (for TLS support)
4. TLS certificates

## Option 1: Using NSSM (Recommended)

NSSM provides better service management, logging, and recovery options.

### Install NSSM

Download NSSM from https://nssm.cc/download and extract to `C:\Tools\nssm\`

### Create Service

```powershell
# Run as Administrator

# Create the service
C:\Tools\nssm\nssm.exe install pqcrypta-proxy "C:\Program Files\pqcrypta-proxy\pqcrypta-proxy.exe"

# Configure arguments
C:\Tools\nssm\nssm.exe set pqcrypta-proxy AppParameters "--config C:\ProgramData\pqcrypta\config.toml"

# Set working directory
C:\Tools\nssm\nssm.exe set pqcrypta-proxy AppDirectory "C:\Program Files\pqcrypta-proxy"

# Configure environment variables
C:\Tools\nssm\nssm.exe set pqcrypta-proxy AppEnvironmentExtra "PQCRYPTA_LOG_LEVEL=info" "PQCRYPTA_JSON_LOGS=true"

# Configure stdout/stderr logging
C:\Tools\nssm\nssm.exe set pqcrypta-proxy AppStdout "C:\ProgramData\pqcrypta\logs\stdout.log"
C:\Tools\nssm\nssm.exe set pqcrypta-proxy AppStderr "C:\ProgramData\pqcrypta\logs\stderr.log"
C:\Tools\nssm\nssm.exe set pqcrypta-proxy AppStdoutCreationDisposition 4
C:\Tools\nssm\nssm.exe set pqcrypta-proxy AppStderrCreationDisposition 4
C:\Tools\nssm\nssm.exe set pqcrypta-proxy AppRotateFiles 1
C:\Tools\nssm\nssm.exe set pqcrypta-proxy AppRotateOnline 1
C:\Tools\nssm\nssm.exe set pqcrypta-proxy AppRotateBytes 10485760

# Configure service recovery (restart on failure)
C:\Tools\nssm\nssm.exe set pqcrypta-proxy AppExit Default Restart
C:\Tools\nssm\nssm.exe set pqcrypta-proxy AppRestartDelay 5000

# Set service to start automatically
C:\Tools\nssm\nssm.exe set pqcrypta-proxy Start SERVICE_AUTO_START

# Set description
C:\Tools\nssm\nssm.exe set pqcrypta-proxy Description "PQCrypta Proxy - QUIC/HTTP3/WebTransport Proxy with PQC TLS"

# Start the service
C:\Tools\nssm\nssm.exe start pqcrypta-proxy
```

### Manage Service with NSSM

```powershell
# Check status
C:\Tools\nssm\nssm.exe status pqcrypta-proxy

# Stop service
C:\Tools\nssm\nssm.exe stop pqcrypta-proxy

# Restart service
C:\Tools\nssm\nssm.exe restart pqcrypta-proxy

# Remove service
C:\Tools\nssm\nssm.exe remove pqcrypta-proxy confirm
```

## Option 2: Using Native sc.exe

For simpler deployments without NSSM.

### Create Service

```powershell
# Run as Administrator

# Create the service
sc.exe create pqcrypta-proxy binPath= "\"C:\Program Files\pqcrypta-proxy\pqcrypta-proxy.exe\" --config \"C:\ProgramData\pqcrypta\config.toml\"" DisplayName= "PQCrypta Proxy" start= auto

# Set description
sc.exe description pqcrypta-proxy "PQCrypta Proxy - QUIC/HTTP3/WebTransport Proxy with PQC TLS"

# Configure failure recovery
sc.exe failure pqcrypta-proxy reset= 86400 actions= restart/5000/restart/10000/restart/30000

# Start the service
sc.exe start pqcrypta-proxy
```

### Manage Service with sc.exe

```powershell
# Check status
sc.exe query pqcrypta-proxy

# Stop service
sc.exe stop pqcrypta-proxy

# Start service
sc.exe start pqcrypta-proxy

# Delete service (must be stopped first)
sc.exe delete pqcrypta-proxy
```

## Directory Structure

Create the following directories:

```
C:\Program Files\pqcrypta-proxy\
├── pqcrypta-proxy.exe
└── README.md

C:\ProgramData\pqcrypta\
├── config.toml
├── logs\
│   ├── stdout.log
│   └── stderr.log
└── certs\
    ├── cert.pem
    └── key.pem
```

### PowerShell Setup Script

```powershell
# Create directories
New-Item -ItemType Directory -Force -Path "C:\Program Files\pqcrypta-proxy"
New-Item -ItemType Directory -Force -Path "C:\ProgramData\pqcrypta"
New-Item -ItemType Directory -Force -Path "C:\ProgramData\pqcrypta\logs"
New-Item -ItemType Directory -Force -Path "C:\ProgramData\pqcrypta\certs"

# Set permissions (restrict to Administrators and SYSTEM)
$acl = Get-Acl "C:\ProgramData\pqcrypta"
$acl.SetAccessRuleProtection($true, $false)
$rule1 = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators","FullControl","ContainerInherit,ObjectInherit","None","Allow")
$rule2 = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM","FullControl","ContainerInherit,ObjectInherit","None","Allow")
$acl.SetAccessRule($rule1)
$acl.SetAccessRule($rule2)
Set-Acl "C:\ProgramData\pqcrypta" $acl
```

## Example Configuration

Save to `C:\ProgramData\pqcrypta\config.toml`:

```toml
[server]
bind_address = "0.0.0.0"
udp_port = 4433

[tls]
cert_path = "C:\\ProgramData\\pqcrypta\\certs\\cert.pem"
key_path = "C:\\ProgramData\\pqcrypta\\certs\\key.pem"

[pqc]
enabled = false  # Enable when OpenSSL 3.5 with OQS is available

[admin]
enabled = true
bind_address = "127.0.0.1"
port = 8081

[logging]
level = "info"
format = "json"

[backends.default]
name = "default"
type = "http1"
address = "127.0.0.1:8080"
timeout_ms = 30000
max_connections = 100

[[routes]]
name = "default"
path_prefix = "/"
backend = "default"
```

## Firewall Rules

Allow UDP traffic for QUIC:

```powershell
# Allow QUIC (UDP 4433)
New-NetFirewallRule -DisplayName "PQCrypta Proxy QUIC" -Direction Inbound -Protocol UDP -LocalPort 4433 -Action Allow

# Allow Admin API (TCP 8081, localhost only)
New-NetFirewallRule -DisplayName "PQCrypta Proxy Admin" -Direction Inbound -Protocol TCP -LocalPort 8081 -RemoteAddress 127.0.0.1 -Action Allow
```

## Troubleshooting

### View Windows Event Logs

```powershell
Get-EventLog -LogName Application -Source pqcrypta-proxy -Newest 50
```

### Check Service Status

```powershell
Get-Service pqcrypta-proxy | Format-List *
```

### View Log Files

```powershell
Get-Content "C:\ProgramData\pqcrypta\logs\stdout.log" -Tail 100 -Wait
```
