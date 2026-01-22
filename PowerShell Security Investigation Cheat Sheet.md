

This cheat sheet, based on the article "Using PowerShell for Security Investigations" by GK, provides blue team security professionals with concise PowerShell commands for threat detection, incident response, system monitoring, and forensic analysis. It includes practical commands and scripts to enhance security operations.

---

## Setting Up a Secure Environment

### Set Execution Policy

- **Purpose**: Restrict untrusted script execution to prevent malicious scripts.
- **Commands**:
    
    ```powershell
    Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy RemoteSigned
    ```
    

### Enable PowerShell Logging

- **Purpose**: Log all executed PowerShell commands for auditing.
- **Commands**:
    
    ```powershell
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
    ```
    

### Monitor PowerShell Events

- **Purpose**: Track PowerShell activity in event logs.
- **Commands**:
    - Script block execution (EID 4104):
        
        ```powershell
        Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 100 | Where-Object { $_.Id -eq 4104 } | Select-Object TimeCreated, @{Name="ScriptBlock";Expression={$_.Properties[2].Value}}
        ```
        
    - New process creation (EID 4688):
        
        ```powershell
        Get-WinEvent -LogName "Security" -MaxEvents 100 | Where-Object { $_.Id -eq 4688 } | Select-Object TimeCreated, Message
        ```
        

---

## Log Analysis & Threat Detection

### Detect Failed Login Attempts

- **Purpose**: Identify brute-force attacks via failed logins (EID 4625).
- **Command**:
    
    ```powershell
    Get-WinEvent -LogName "Security" -MaxEvents 100 | Where-Object { $_.Id -eq 4625 } | Format-List TimeCreated, Message
    ```
    

### Find Newly Created User Accounts

- **Purpose**: Detect unauthorized account creation (EID 4720).
- **Command**:
    
    ```powershell
    Get-WinEvent -LogName "Security" -MaxEvents 100 | Where-Object { $_.Id -eq 4720 } | Select-Object TimeCreated, Message
    ```
    

### Identify Suspicious Network Connections

- **Purpose**: Detect external connections excluding local IPs.
- **Command**:
    
    ```powershell
    Get-NetTCPConnection | Where-Object { $_.State -eq "Established" -and $_.RemoteAddress -notlike "192.168.*" } | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort
    ```
    

### Check for Suspicious Processes

- **Purpose**: Identify processes running from unusual directories or scripting engines.
- **Command**:
    
    ```powershell
    Get-Process | Where-Object { $_.Path -like "*AppData*" -or $_.ProcessName -match "powershell|cmd|wscript|cscript" } | Select-Object Name, Id, Path
    ```
    

---

## Incident Response

### Isolate a Compromised System

- **Purpose**: Disconnect a system from the network to contain a threat.
- **Command**:
    
    ```powershell
    Disable-NetAdapter -Name "Ethernet" -Confirm:$false
    ```
    

### Kill Malicious Processes

- **Purpose**: Terminate suspicious processes.
- **Commands**:
    - Specific process:
        
        ```powershell
        Stop-Process -Name "notepad" -Force
        ```
        
    - All PowerShell or cmd.exe instances:
        
        ```powershell
        Get-Process | Where-Object { $_.ProcessName -match "powershell|cmd" } | Stop-Process -Force
        ```
        

### Remove Suspicious Scheduled Tasks

- **Purpose**: Eliminate persistence mechanisms via scheduled tasks.
- **Command**:
    
    ```powershell
    Get-ScheduledTask | Where-Object { $_.TaskPath -like "*\Microsoft\Windows\*" -and $_.Actions -match "powershell" } | Select-Object TaskName, TaskPath, Actions
    Unregister-ScheduledTask -TaskName "MaliciousTask" -Confirm:$false
    ```
    

---

## Forensic Analysis

### Retrieve Browser History

- **Purpose**: Extract browsing history for evidence (e.g., Microsoft Edge).
- **Command**:
    
    ```powershell
    Get-ChildItem -Path "C:\Users\*\AppData\Local\Microsoft\Edge\User Data\Default\History" -Force
    ```
    

### Check Registry for Suspicious Entries

- **Purpose**: Identify malware persistence in registry startup keys.
- **Commands**:
    - List startup programs:
        
        ```powershell
        Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
        ```
        
    - Remove malicious registry key:
        
        ```powershell
        Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Malware"
        ```
        

### Dump Recently Accessed Files

- **Purpose**: Identify recently accessed files for evidence of compromise.
- **Command**:
    
    ```powershell
    Get-ChildItem -Path "C:\Users\*\Recent" -Force
    ```
    

---

## Automation and Scripting

### Automate Log Collection

- **Purpose**: Collect security logs and save to CSV for analysis.
- **Command**:
    
    ```powershell
    $logPath = "C:\SecurityLogs\"
    New-Item -ItemType Directory -Path $logPath -Force
    Get-WinEvent -LogName "Security" -MaxEvents 1000 | Export-Csv -Path "$logPath\SecurityLogs.csv" -NoTypeInformation
    ```
    

### Automated Threat Detection Script

- **Purpose**: Alert on excessive failed login attempts.
- **Command**:
    
    ```powershell
    $logins = Get-WinEvent -LogName "Security" -MaxEvents 100 | Where-Object { $_.Id -eq 4625 }
    if ($logins.Count -gt 10) {
        Send-MailMessage -To "admin@example.com" -From "alert@example.com" -Subject "High Failed Login Attempts" -Body "Multiple failed logins detected."
    }
    ```
    

---

## Quick Commands

### Post-Exploitation

- **Find Specific Files**:
    
    ```powershell
    Get-ChildItem -Path "C:\Users\" -Recurse -Include "credentials.txt"
    ```
    
- **List Installed Updates**:
    
    ```powershell
    Get-HotFix | Select-Object HotFixID, Description, InstalledOn
    ```
    
- **Access Registry**:
    
    ```powershell
    Set-Location -Path "HKLM:\"
    Get-ChildItem
    ```
    
- **List Startup Programs**:
    
    ```powershell
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    ```
    
- **Get Firewall Rules**:
    
    ```powershell
    Get-NetFirewallRule -All | Select-Object Name, DisplayName, Action, Direction
    ```
    

### Frequently Used

- **Copy Files**:
    
    ```powershell
    Copy-Item -Path "src.txt" -Destination "dst.txt"
    ```
    
- **Move Files**:
    
    ```powershell
    Move-Item -Path "src.txt" -Destination "dst.txt"
    ```
    
- **List Process Info**:
    
    ```powershell
    Get-Process | Select-Object Name, Id, Path
    ```
    
- **List Services**:
    
    ```powershell
    Get-Service | Select-Object Name, Status, DisplayName
    ```
    
- **Get File Hash**:
    
    ```powershell
    Get-FileHash -Path "file.txt" -Algorithm SHA1
    ```
    
- **Export to CSV**:
    
    ```powershell
    Get-Process | Export-Csv -Path "processes.csv" -NoTypeInformation
    ```
    
- **Get Help**:
    
    ```powershell
    Get-Help
    ```
    

---

## Basic Forensic Collection Script

### Purpose

Collect system, user, process, network, and event log data for forensic analysis.

### Script

```powershell
# Create forensic directory
New-Item -Path "C:\Forensics" -ItemType Directory -Force

# Collect system information
Write-Output "Collecting system information..."
$systemInfo = Get-ComputerInfo
$systemInfo | Out-File -FilePath "C:\Forensics\SystemInfo.txt"

# Collect user information
Write-Output "Collecting user information..."
$userInfo = Get-LocalUser
$userInfo | Out-File -FilePath "C:\Forensics\UserInfo.txt"

# Collect running processes
Write-Output "Collecting running processes..."
$processes = Get-Process
$processes | Out-File -FilePath "C:\Forensics\Processes.txt"

# Collect network connections
Write-Output "Collecting network connections..."
$networkConnections = Get-NetTCPConnection
$networkConnections | Out-File -FilePath "C:\Forensics\NetworkConnections.txt"

# Collect event logs
Write-Output "Collecting event logs..."
$eventLogs = Get-EventLog -LogName System -Newest 150
$eventLogs | Out-File -FilePath "C:\Forensics\EventLogs.txt"

Write-Output "Forensic data collection completed."
```

---

## Notes

- **Run as Administrator**: Many commands require elevated privileges.
    
    ```powershell
    Start-Process PowerShell -Verb RunAs
    ```
    
- **Test Environment**: Validate scripts in a non-production environment to avoid unintended changes.
- **Forensic Integrity**: Use read-only cmdlets (e.g., `Get-*`) to preserve evidence.
- **Email Alerts**: Configure `Send-MailMessage` with valid SMTP settings for automated alerts.
- **Log Retention**: Ensure sufficient disk space for logs and forensic outputs.

This cheat sheet equips blue teams with PowerShell commands and scripts to enhance threat detection, incident response, and forensic investigations.
