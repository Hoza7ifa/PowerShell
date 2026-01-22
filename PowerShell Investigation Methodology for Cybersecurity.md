
---

## 1. Preparation

### Objective

Set up a secure environment and ensure tools are ready for investigation.

### Steps

- **Verify Execution Policy**: Ensure PowerShell scripts can run.
    
    ```powershell
    Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
    ```
    
- **Run as Administrator**: Elevate PowerShell privileges for access to system resources.
    
    ```powershell
    Start-Process PowerShell -Verb RunAs
    ```
    
- **Enable Logging**: Start a transcript to log all commands and outputs.
    
    ```powershell
    Start-Transcript -Path C:\Forensics\Investigation_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt
    ```
    
- **Set Up Isolated Environment**: Use a virtual machine or sandbox for analyzing suspicious scripts or files.
- **Enable Constrained Language Mode**: Restrict PowerShell capabilities to prevent accidental execution of malicious code.
    
    ```powershell
    $ExecutionContext.SessionState.LanguageMode = "ConstrainedLanguage"
    ```
    
- **Install Required Modules**: Ensure modules like `ActiveDirectory` or `Sysmon` tools are available.
    
    ```powershell
    Install-Module -Name ActiveDirectory -Force
    ```
    

---

## 2. System Triage

### Objective

Quickly assess the system’s state to identify signs of compromise.

### Steps

- **Gather System Information**: Collect OS, hardware, and software details.
    
    ```powershell
    Get-ComputerInfo | Select-Object WindowsProductName, OsVersion, CsTotalPhysicalMemory
    Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber
    Get-WmiObject -Class Win32_Product | Select-Object Name, Version
    ```
    
- **List Running Processes**: Identify running processes and their details.
    
    ```powershell
    Get-Process | Select-Object Name, Id, Path, StartTime, @{Name="ParentProcess";Expression={(Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)").ParentProcessId}} | Sort-Object StartTime -Descending
    ```
    
- **Check Services**: Review running services and their configurations.
    
    ```powershell
    Get-Service | Where-Object { $_.Status -eq "Running" } | Select-Object Name, DisplayName, Status
    Get-WmiObject -Class Win32_Service | Select-Object Name, PathName, StartMode
    ```
    
- **Inspect Network Activity**: Identify active connections and listening ports.
    
    ```powershell
    Get-NetTCPConnection | Where-Object { $_.State -eq "Established" } | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess
    Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess
    ```
    

---

## 3. Identify Indicators of Compromise (IoCs)

### Objective

Detect suspicious processes, files, network activity, and persistence mechanisms.

### Steps

- **Check Suspicious Processes**: Look for processes with unusual paths or high resource usage.
    
    ```powershell
    Get-Process | Where-Object { $_.Path -like "*\Temp\*" -or $_.Path -like "*\AppData\*" -or $_.CPU -gt 1000 } | Select-Object Name, Path, CPU
    ```
    
- **Identify Unsigned Executables**: Find executables without valid digital signatures.
    
    ```powershell
    Get-ChildItem -Path C:\ -Recurse -Include *.exe | Where-Object { (Get-AuthenticodeSignature $_.FullName).Status -ne "Valid" }
    ```
    
- **Search for Suspicious Files**: Locate recently modified or suspicious files.
    
    ```powershell
    Get-ChildItem -Path C:\ -Recurse | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-1) -or $_.Name -like "*malware*" }
    ```
    
- **Check Persistence Mechanisms**:
    - Scheduled Tasks:
        
        ```powershell
        Get-ScheduledTask | Where-Object { $_.State -eq "Ready" } | Select-Object TaskName, TaskPath, Actions
        ```
        
    - Startup Items:
        
        ```powershell
        Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, User
        ```
        
    - WMI Subscriptions:
        
        ```powershell
        Get-WmiObject -Namespace root\subscription -Class __EventConsumer | Select-Object Name, CommandLineTemplate
        ```
        
    - Registry Run Keys:
        
        ```powershell
        Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
        ```
        
- **Monitor Network Connections**: Identify connections to suspicious IPs or ports.
    
    ```powershell
    Get-NetTCPConnection | Where-Object { $_.State -eq "Established" } | Select-Object LocalAddress, RemoteAddress, RemotePort | Export-Csv -Path connections.csv -NoTypeInformation
    ```
    

---

## 4. Analyze Logs

### Objective

Review event logs and PowerShell logs to identify malicious activity or anomalies.

### Steps

- **Query Security Logs**: Check for logon events, account changes, or privilege escalations.
    
    ```powershell
    Get-WinEvent -LogName Security -MaxEvents 100 | Where-Object { $_.Id -eq 4624 -or $_.Id -eq 4625 -or $_.Id -eq 4672 } | Select-Object TimeCreated, Id, @{Name="Account";Expression={$_.Properties[5].Value}}
    ```
    
- **Analyze PowerShell Logs**: Look for script execution or encoded commands.
    
    ```powershell
    Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 100 | Where-Object { $_.Id -eq 4104 } | Select-Object @{Name="ScriptBlock";Expression={$_.Properties[2].Value}}
    ```
    
- **Check Sysmon Logs**: Review process creation or network events.
    
    ```powershell
    Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object { $_.Id -eq 1 -or $_.Id -eq 3 } | Select-Object @{Name="Process";Expression={$_.Properties[4].Value}}, @{Name="CommandLine";Expression={$_.Properties[10].Value}}
    ```
    
- **Decode Base64 Commands**: Extract and decode encoded PowerShell commands.
    
    ```powershell
    Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | Where-Object { $_.Id -eq 4104 } | ForEach-Object { [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($_.Properties[2].Value)) }
    ```
    
- **Export Logs for Analysis**:
    
    ```powershell
    Get-WinEvent -LogName Security -MaxEvents 1000 | Export-Csv -Path SecurityLogs.csv -NoTypeInformation
    ```
    

---

## 5. Detect Malicious PowerShell Activity

### Objective

Identify obfuscated scripts, encoded payloads, or suspicious execution patterns.

### Steps

- **Check Running PowerShell Processes**:
    
    ```powershell
    Get-Process -Name powershell | Select-Object Name, ID, Path, @{Name="CommandLine";Expression={(Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)").CommandLine}}
    ```
    
- **Monitor Command History**:
    
    ```powershell
    Get-History | Select-Object CommandLine, ExecutionStatus
    ```
    
- **Search for Suspicious Scripts**: Look for `Invoke-Expression`, `System.Net.WebClient`, or `Invoke-WebRequest`.
    
    ```powershell
    Get-Content suspicious.ps1 | Select-String "Invoke-Expression|System.Net.WebClient|Invoke-WebRequest"
    ```
    
- **Enable PowerShell Logging** (if not already enabled):
    - Script Block Logging:
        
        ```powershell
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
        ```
        
    - Module Logging:
        
        ```powershell
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1
        ```
        

---

## 6. Collect and Preserve Artifacts

### Objective

Gather forensic artifacts while minimizing system impact.

### Steps

- **Hash Files**: Calculate hashes for suspicious files to verify integrity.
    
    ```powershell
    Get-FileHash -Path "C:\Path\To\File.exe" -Algorithm SHA256
    ```
    
- **Copy Files Safely**: Copy suspicious files to a forensic directory (avoid executing).
    
    ```powershell
    Copy-Item -Path "C:\Suspicious\file.exe" -Destination "E:\Forensic_Copies\file.exe"
    ```
    
- **Work with Forensic Copies**: Analyze disk images or copies in a forensic tool.
    
    ```powershell
    Get-ChildItem -Path E:\ -Recurse | Where-Object { $_.Extension -eq ".ps1" -or $_.Extension -eq ".exe" }
    ```
    
- **Export Process and Network Data**:
    
    ```powershell
    Get-Process | Select-Object Name, ID, Path | Export-Csv -Path process_report.csv -NoTypeInformation
    Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State | Export-Csv -Path connections.csv -NoTypeInformation
    ```
    

---

## 7. Remediate and Contain

### Objective

Mitigate threats by isolating systems, blocking malicious IPs, or terminating processes.

### Steps

- **Kill Suspicious Processes**:
    
    ```powershell
    Stop-Process -Name "suspicious_process" -Force
    ```
    
- **Block Malicious IPs**:
    
    ```powershell
    New-NetFirewallRule -Name "BlockMaliciousIP" -Action Block -RemoteAddress "192.168.1.100"
    ```
    
- **Run Antivirus Scan**:
    
    ```powershell
    Start-MpScan -ScanType QuickScan
    ```
    
- **Disable Compromised Accounts**:
    
    ```powershell
    Disable-LocalUser -Name "compromised_user"
    ```
    
- **Remove Persistence Mechanisms**:
    - Delete Scheduled Tasks:
        
        ```powershell
        Unregister-ScheduledTask -TaskName "MaliciousTask" -Confirm:$false
        ```
        
    - Remove Registry Run Keys:
        
        ```powershell
        Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SuspiciousKey"
        ```
        

---

## 8. Document and Report Findings

### Objective

Compile findings into a clear, actionable report for stakeholders.

### Steps

- **Compile Artifacts**: Organize collected data (logs, hashes, process lists) in a secure directory.
    
    ```powershell
    New-Item -ItemType Directory -Path "C:\Forensics\Case_$(Get-Date -Format 'yyyyMMdd')"
    Move-Item -Path *.csv -Destination "C:\Forensics\Case_$(Get-Date -Format 'yyyyMMdd')"
    ```
    
- **Generate Report**: Summarize findings in a text file or CSV.
    
    ```powershell
    $report = "Investigation Report - $(Get-Date)`n"
    $report += "System Info: $(Get-ComputerInfo | Select-Object WindowsProductName, OsVersion | Out-String)`n"
    $report += "Suspicious Processes: $(Get-Process | Where-Object { $_.Path -like '*Temp*' } | Out-String)"
    $report | Out-File -FilePath "C:\Forensics\Report_$(Get-Date -Format 'yyyyMMdd').txt"
    ```
    
- **Stop Transcript**: End logging and review the transcript for completeness.
    
    ```powershell
    Stop-Transcript
    ```
    

---

## 9. Post-Investigation Actions

### Objective

Ensure the system is secure and lessons are learned for future investigations.

### Steps

- **Verify Remediation**: Confirm malicious processes, files, or connections are removed.
    
    ```powershell
    Get-Process | Where-Object { $_.Path -like "*\Temp\*" }
    Get-NetTCPConnection | Where-Object { $_.RemoteAddress -eq "192.168.1.100" }
    ```
    
- **Check for Updates**: Ensure the system is patched.
    
    ```powershell
    Get-HotFix | Select-Object HotFixID, Description, InstalledOn | Sort-Object InstalledOn -Descending
    ```
    
- **Review Security Configurations**:
    - Firewall Rules:
        
        ```powershell
        Get-NetFirewallRule | Select-Object Name, DisplayName, Action, Direction
        ```
        
    - Windows Defender Status:
        
        ```powershell
        Get-MpComputerStatus
        ```
        
- **Document Lessons Learned**: Update internal documentation with new IoCs or techniques observed.
- **Secure Backups**: Store forensic copies and reports in a secure, offline location.

---

## Notes

- **Forensic Integrity**: Use read-only cmdlets (e.g., `Get-*`) to avoid modifying the system.
- **Test Commands**: Validate scripts and commands in a non-production environment.
- **Chain of Custody**: Maintain a clear record of all actions and artifacts collected.
- **Escalate as Needed**: If findings indicate a broader compromise, escalate to senior analysts or external IR teams.

This methodology provides a repeatable, PowerShell-driven process for investigating security incidents while preserving evidence and ensuring thorough documentation.