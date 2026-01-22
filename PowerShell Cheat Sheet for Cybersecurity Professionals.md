
---
## System Information

### Get System Details

- **System Info**: Retrieve system information (OS, hardware, etc.).
    
    ```powershell
    Get-ComputerInfo
    ```
    
- **OS Version**: Check operating system version.
    
    ```powershell
    Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber
    ```

- **List Installed Software**: Display installed applications.
    
    ```powershell
    Get-WmiObject -Class Win32_Product | Select-Object Name, Version
    ```

### Check Running Services

- **List Services**: Display all services and their status.
    
    ```powershell
    Get-Service | Sort-Object Status, Name | Select-Object Name, DisplayName, Status
    ```
    
- **Filter Running Services**: Show only running services.
    
    ```powershell
    Get-Service | Where-Object { $_.Status -eq "Running" }
    ```

- **Service Details**: Retrieve service paths and startup modes.
    
    ```powershell
    Get-WmiObject -Class Win32_Service | Select-Object Name, PathName, StartMode
    ```


### Disk and File System

- **Disk Usage**: Check disk space and usage.
    
    ```powershell
    Get-Disk
    Get-Volume
    ```
    
- **List Drives**: Enumerate all drives on the system.
    
    ```powershell
    Get-PSDrive -PSProvider FileSystem
    ```
    

---

## Process Analysis

### List Processes

- **All Processes**: Display all running processes with details.
    
    ```powershell
    Get-Process | Select-Object Name, Id, Path, StartTime, @{Name="ParentProcess";Expression={(Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)").ParentProcessId}}
    ```
    
- **Suspicious Processes**: Filter processes with high CPU usage or unusual paths.
    
    ```powershell
    Get-Process | Where-Object { $_.CPU -gt 1000 -or $_.Path -like "*\Temp\*" -or $_.Path -like "*\AppData\*" } | Sort-Object CPU -Descending
    ```
    
- **Non-Microsoft Processes**: List processes not signed by Microsoft.
    
    ```powershell
    Get-Process | Where-Object { $_.Company -notlike "*Microsoft*" } | Select-Object Name, Path, Company
    ```

### Process Details

- **Process Modules**: List loaded modules for a specific process.
    
    ```powershell
    Get-Process -Name "process_name" | Select-Object -ExpandProperty Modules
    ```
    
- **Process Network Connections**: Find network connections for a process.
    
    ```powershell
    Get-NetTCPConnection | Where-Object { $_.OwningProcess -eq (Get-Process -Name "process_name").Id }
    ```
    

### Kill a Process

- **Terminate Process**: Stop a process by ID or name.
    
    ```powershell
    Stop-Process -Id 1234
    Stop-Process -Name "notepad"
    ```
    

---

## Network Investigation

### Network Connections

- **Active Connections**: List all active TCP connections.
    
    ```powershell
    Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
    ```
    
- **Listening Ports**: Show listening ports and associated processes.
    
    ```powershell
    Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess
    ```
    
- **Export Connections**: Save network connections to CSV.
    
    ```powershell
    Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State | Export-Csv -Path connections.csv -NoTypeInformation
    ```

### DNS Queries

- **DNS Cache**: View DNS resolver cache.
    
    ```powershell
    Get-DnsClientCache
    ```
    
- **Clear DNS Cache**: Flush the DNS resolver cache.
    
    ```powershell
    Clear-DnsClientCache
    ```
    

### Network Interfaces

- **Network Adapters**: List network adapter details.
    
    ```powershell
    Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress
    ```
    
- **IP Configuration**: Display IP configuration.
    
    ```powershell
    Get-NetIPConfiguration
    ```
    
- **Test Connectivity**: Ping a remote host.
    
    ```powershell
    Test-Connection -ComputerName 192.168.1.1 -Count 4
    ```

---

## Event Log Analysis

### Query Event Logs

- **Security Logs**: Retrieve security events (e.g., logon events).
    
    ```powershell
    Get-WinEvent -LogName Security -MaxEvents 100 | Where-Object { $_.Id -eq 4624 } | Select-Object TimeCreated, @{Name="Account";Expression={$_.Properties[5].Value}}
    ```
    
- **Filter by Time**: Get events from the last 24 hours.
    
    ```powershell
    Get-WinEvent -LogName System -FilterHashtable @{LogName="System"; StartTime=(Get-Date).AddHours(-24)}
    ```
    
- **PowerShell Operational Logs**: Query PowerShell execution details.
    
    ```powershell
    Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 50
    ```
    
- **Sysmon Logs**: Analyze Sysmon process creation or network events.
    
    ```powershell
    Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object { $_.Id -eq 1 } | Select-Object @{Name="Process";Expression={$_.Properties[4].Value}}, @{Name="CommandLine";Expression={$_.Properties[10].Value}}
    ```

### Common Event IDs

- **Logon Success**: Event ID 4624 (Successful logon).
    
- **Logon Failure**: Event ID 4625 (Failed logon).
    
- **Account Changes**: Event ID 4720, 4722 (User account created/enabled).
    
- **Registry Changes**: Event ID 4657 (Registry value modified).
    
- **PowerShell Execution**: Event ID 4104 (Script block execution).
    

### Export Logs

- **Export to CSV**: Save event logs for analysis.
    
    ```powershell
    Get-WinEvent -LogName Security -MaxEvents 1000 | Export-Csv -Path SecurityLogs.csv -NoTypeInformation
    ```
    

### Enable PowerShell Logging

- **Script Block Logging**: Enable logging of PowerShell script execution.
    
    ```powershell
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
    ```
    
- **Module Logging**: Enable logging of PowerShell modules.
    
    ```powershell
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1
    ```

---

## File and Registry Forensics

### File System Analysis

- **List Files**: Check files in a directory with timestamps.
    
    ```powershell
    Get-ChildItem -Path C:\Users -Recurse | Select-Object FullName, LastWriteTime
    ```
    
- **Find Recently Modified Files**: Look for files modified in the last 24 hours.
    
    ```powershell
    Get-ChildItem -Path C:\ -Recurse | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-1) }
    ```
    
- **Find Suspicious Files**: Search for files by extension or name.
    
    ```powershell
    Get-ChildItem -Path C:\ -Recurse -Include *malware*.ps1
    ```
    
- **Check Unsigned Executables**: Identify unsigned executables.
    
    ```powershell
    Get-ChildItem -Path C:\ -Recurse -Include *.exe | Where-Object { (Get-AuthenticodeSignature $_.FullName).Status -ne "Valid" }
    ```
    

### Hash Files

- **Calculate File Hash**: Compute SHA256 hash for a file.
    
    ```powershell
    Get-FileHash -Path "C:\Path\To\File.exe" -Algorithm SHA256
    ```
    

### Registry Analysis

- **List Registry Keys**: Enumerate keys in a registry path.
    
    ```powershell
    Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
    ```
    
- **Monitor Registry Changes**: Detect recent registry modifications.
    
    ```powershell
    Get-WinEvent -LogName Security | Where-Object { $_.Id -eq 4657 }
    ```
    
- **WMI Subscriptions**: Check for persistence via WMI.
    
    ```powershell
    Get-WmiObject -Namespace root\subscription -Class __EventConsumer | Select-Object Name, CommandLineTemplate
    ```

---

## User and Account Management

### List Users

- **Local Users**: Display all local user accounts.
    
    ```powershell
    Get-LocalUser | Select-Object Name, Enabled, LastLogon
    ```
    
- **Active Directory Users**: Query AD users (requires RSAT).
    
    ```powershell
    Get-ADUser -Filter * | Select-Object Name, UserPrincipalName, Enabled
    ```
    

### Check Privileges

- **Admin Accounts**: List users in the Administrators group.
    
    ```powershell
    Get-LocalGroupMember -Group "Administrators"
    ```
    

### Password Policies

- **Check Password Policy**: Display password policy settings.
    
    ```powershell
    Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty UserPassword
    ```
    

---

## Security Configuration

### Firewall Rules

- **List Firewall Rules**: Display all firewall rules.
    
    ```powershell
    Get-NetFirewallRule | Select-Object Name, DisplayName, Action, Direction
    ```
    
- **Block Suspicious IP**: Create a firewall rule to block an IP.
    
    ```powershell
    New-NetFirewallRule -Name "BlockIP" -Action Block -RemoteAddress "192.168.1.100"
    ```
    

### Windows Defender

- **Scan Status**: Check Windows Defender scan status.
    
    ```powershell
    Get-MpComputerStatus
    ```
    
- **Run Quick Scan**: Initiate a quick antivirus scan.
    
    ```powershell
    Start-MpScan -ScanType QuickScan
    ```
    

### Patch Management

- **Check Installed Updates**: List installed Windows updates.
    
    ```powershell
    Get-HotFix | Select-Object HotFixID, Description, InstalledOn
    ```
    

---
## Detecting Malicious PowerShell Activity

### Indicators of Malicious Activity

- **Obfuscated Commands**: Look for long, unreadable strings or concatenated commands.
    
    ```powershell
    $a = "I"; $b = "n"; $c = "v"; $d = "o"; $e = "k"; $f = "e"; &$($a+$b+$c+$d+$e+$f)-Command whoami
    ```
    
- **Encoded Payloads**: Identify Base64-encoded strings in scripts or command lines.
    
    ```powershell
    powershell -EncodedCommand JABhAD0AIgBJACIAOwAkAGIAIAA9ACAAIgBuACIAOwAkAGMAIAA9ACAAIgB2ACIAOw==
    ```
    
- **Suspicious Execution Patterns**:
    
    - PowerShell launched from unusual directories (e.g., %Temp%, %AppData%).
        
    - Non-standard parent processes (e.g., cmd.exe, mshta.exe).
        
    - High CPU/memory usage by powershell.exe.
        

### Detection Techniques

- **Check Running PowerShell Processes**:
    
    ```powershell
    Get-Process -Name powershell | Select-Object Name, ID, Path, @{Name="CommandLine";Expression={(Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)").CommandLine}}
    ```
    
- **Monitor PowerShell Command History**:
    
    ```powershell
    Get-History | Select-Object CommandLine, ExecutionStatus
    ```
    
- **Search for Encoded Commands**:
    
    ```powershell
    Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 100 | Where-Object { $_.Id -eq 4104 } | Select-Object @{Name="ScriptBlock";Expression={$_.Properties[2].Value}}
    ```
    
- **Decode Base64 Commands**:
    
    ```powershell
    $encoded = "JABhAD0AIgBJACIAOwAkAGIAIAA9ACAAIgBuACIAOwAkAGMAIAA9ACAAIgB2ACIAOw=="
    [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encoded))
    ```
    
- **Identify Suspicious Scripts**:
    
    ```powershell
    Get-Content suspicious.ps1 | Select-String "Invoke-Expression|System.Net.WebClient|Invoke-WebRequest"
    ```
---
## Automation and Scripting Tips

### Scheduled Tasks

- **List Scheduled Tasks**: Display all scheduled tasks.
    
    ```powershell
    Get-ScheduledTask | Select-Object TaskName, State, LastRunTime
    ```
    
- **Create a Task**: Schedule a script to run daily.
    
    ```powershell
    $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File C:\Scripts\Monitor.ps1"
    $trigger = New-ScheduledTaskTrigger -Daily -At "9:00AM"
    Register-ScheduledTask -TaskName "DailyMonitor" -Action $action -Trigger $trigger
    ```
    

### Monitor System in Real-Time

- **Monitor Processes**: Continuously monitor new processes.
    
    ```powershell
    while ($true) {
        Get-Process | Where-Object { $_.StartTime -ge (Get-Date).AddMinutes(-5) } | Select-Object Name, Id, StartTime
        Start-Sleep -Seconds 60
    }
    ```
    
### Persistence Mechanisms

- **Startup Items**: Check for startup programs.
    
    ```powershell
    Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, User
    ```
---

## Error Handling and Logging

### Try-Catch Block

- **Handle Errors**: Use try-catch for robust scripts.
    
    ```powershell
    try {
        Get-Process -Name "nonexistent" -ErrorAction Stop
    }
    catch {
        Write-Error "Process not found: $_"
    }
    ```
    
### Log Script Output

- **Write to Log File**: Append script output to a log file.
    
    ```powershell
    $logPath = "C:\Logs\ScriptLog.txt"
    "Event occurred at $(Get-Date)" | Out-File -FilePath $logPath -Append
    ```
    
- **Start Transcript**: Log all PowerShell session output.
    
    ```powershell
    Start-Transcript -Path C:\Forensics\Investigation_Log.txt
    ```
---
## Safe PowerShell Usage in Forensics

- **Avoid Live System Changes**:
    
    - Use read-only cmdlets (e.g., Get-* instead of Set-*).
        
    - Avoid running scripts directly on the system; analyze copies in a sandbox.
        
- **Work with Forensic Copies**:
    
    - Query disk images mounted in a forensic tool:
        
        ```powershell
        Get-ChildItem -Path E:\ -Recurse | Where-Object { $_.Extension -eq ".ps1" }
        ```
        
- **Use Isolated Environments**:
    
    - Run PowerShell in a VM or sandbox to analyze scripts safely.
        
- **Enable Constrained Language Mode**:
    
    ```powershell
    $ExecutionContext.SessionState.LanguageMode = "ConstrainedLanguage"
    ```
    

---

## Example Investigation Workflow

1. **Triage the System**:
    
    ```powershell
    Get-Process | Select-Object Name, ID, Path, StartTime | Sort-Object StartTime -Descending
    ```
    
2. **Check Network Activity**:
    
    ```powershell
    Get-NetTCPConnection | Where-Object { $_.State -eq "Established" } | Select-Object LocalAddress, RemoteAddress, RemotePort
    ```
    
3. **Review Recent Event Logs**:
    
    ```powershell
    Get-WinEvent -LogName Security -MaxEvents 50 | Where-Object { $_.Id -eq 4624 -or $_.Id -eq 4672 }
    ```
    
4. **Identify Persistence**:
    
    ```powershell
    Get-ScheduledTask | Where-Object { $_.State -eq "Ready" } | Select-Object TaskName, Actions
    Get-CimInstance Win32_StartupCommand | Select-Object Name, Command
    ```
    
5. **Analyze PowerShell Logs**:
    
    ```powershell
    Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 100 | Where-Object { $_.Id -eq 4104 }
    ```
    
6. **Export Findings**:
    
    ```powershell
    Get-Process | Select-Object Name, ID, Path | Export-Csv -Path process_report.csv -NoTypeInformation
    ```
----
## Notes

- **Execution Policy**: Ensure scripts can run by setting the execution policy.
    
    ```powershell
    Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
    ```
    
- **Run as Administrator**: Many commands require elevated privileges.
    
    ```powershell
    Start-Process PowerShell -Verb RunAs
    ```
    
- **Modules**: Install additional modules like `ActiveDirectory` for AD tasks.
    
    ```powershell
    Install-Module -Name ActiveDirectory
    ```
    

This cheat sheet provides a foundation for cybersecurity tasks in PowerShell. Always verify commands in a test environment before production use.