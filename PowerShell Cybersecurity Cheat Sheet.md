
## For SOC Analysts and Digital Forensics Investigators

This cheat sheet provides a concise, actionable guide for cybersecurity professionals using PowerShell for incident response, digital forensics, and security investigations. It covers essential commands, security-specific cmdlets, one-liners, log analysis, malicious activity detection, and safe forensic practices.

---

## 1. Essential PowerShell Commands

### File System Navigation

- **List directory contents**: `Get-ChildItem` (alias: `dir`, `ls`)
    
    ```powershell
    Get-ChildItem -Path C:\ -Recurse -Include *.exe
    ```
    
- **Change directory**: `Set-Location` (alias: `cd`)
    
    ```powershell
    Set-Location -Path C:\Windows\System32
    ```
    
- **Get file content**: `Get-Content` (alias: `cat`, `type`)
    
    ```powershell
    Get-Content -Path C:\Logs\example.log
    ```
    
- **Search for files by name**: `Get-ChildItem` with wildcards
    
    ```powershell
    Get-ChildItem -Path C:\ -Recurse -Include *malware*.ps1
    ```
    

### Process Management

- **List running processes**: `Get-Process` (alias: `ps`)
    
    ```powershell
    Get-Process | Select-Object Name, ID, Path, StartTime
    ```
    
- **Stop a process**: `Stop-Process`
    
    ```powershell
    Stop-Process -Name notepad -Force
    ```
    
- **Get process details**: `Get-Process` with filtering
    
    ```powershell
    Get-Process | Where-Object { $_.CPU -gt 1000 }
    ```
    

### Network Activity Monitoring

- **List network connections**: `Get-NetTCPConnection`
    
    ```powershell
    Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State
    ```
    
- **Get network adapters**: `Get-NetAdapter`
    
    ```powershell
    Get-NetAdapter | Select-Object Name, Status, MacAddress
    ```
    
- **Test network connectivity**: `Test-Connection`
    
    ```powershell
    Test-Connection -ComputerName 192.168.1.1 -Count 4
    ```
    

### System Information Gathering

- **Get system info**: `Get-ComputerInfo`
    
    ```powershell
    Get-ComputerInfo | Select-Object WindowsProductName, OsVersion, CsTotalPhysicalMemory
    ```
    
- **List installed software**: `Get-WmiObject -Class Win32_Product`
    
    ```powershell
    Get-WmiObject -Class Win32_Product | Select-Object Name, Version
    ```
    
- **Get user accounts**: `Get-LocalUser`
    
    ```powershell
    Get-LocalUser | Select-Object Name, Enabled, LastLogon
    ```
    

---

## 2. Security Investigation Cmdlets

### Process and Service Information

- **Detailed process info**: `Get-Process` with extended properties
    
    ```powershell
    Get-Process | Select-Object Name, ID, Path, Company, @{Name="ParentProcess";Expression={(Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)").ParentProcessId}}
    ```
    
- **List services**: `Get-Service`
    
    ```powershell
    Get-Service | Where-Object { $_.Status -eq "Running" } | Select-Object Name, DisplayName, Status
    ```
    
- **Service details**: `Get-WmiObject -Class Win32_Service`
    
    ```powershell
    Get-WmiObject -Class Win32_Service | Select-Object Name, PathName, StartMode
    ```
    

### Network Connections

- **Active connections**: `Get-NetTCPConnection`
    
    ```powershell
    Get-NetTCPConnection | Where-Object { $_.State -eq "Established" } | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess
    ```
    
- **Listening ports**: `Get-NetTCPConnection`
    
    ```powershell
    Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort
    ```
    

### Event Log Querying

- **Query event logs**: `Get-WinEvent`
    
    ```powershell
    Get-WinEvent -LogName Security -MaxEvents 100 | Where-Object { $_.Id -eq 4624 } | Select-Object TimeCreated, @{Name="Account";Expression={$_.Properties[5].Value}}
    ```
    
- **Filter by time**: `Get-WinEvent` with time range
    
    ```powershell
    Get-WinEvent -LogName System -FilterHashtable @{LogName="System"; StartTime=(Get-Date).AddHours(-24)}
    ```
    

### Persistence Mechanisms

- **Scheduled tasks**: `Get-ScheduledTask`
    
    ```powershell
    Get-ScheduledTask | Where-Object { $_.State -eq "Ready" } | Select-Object TaskName, TaskPath, Actions
    ```
    
- **Startup items**: `Get-CimInstance Win32_StartupCommand`
    
    ```powershell
    Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, User
    ```
    
- **WMI subscriptions**: `Get-WmiObject -Namespace root\subscription -Class __EventConsumer`
    
    ```powershell
    Get-WmiObject -Namespace root\subscription -Class __EventConsumer | Select-Object Name, CommandLineTemplate
    ```
    

---

## 3. Useful One-Liners for Incident Response

- **Find recently modified files**:
    
    ```powershell
    Get-ChildItem -Path C:\ -Recurse | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-1) }
    ```
    
- **Detect suspicious processes**:
    
    ```powershell
    Get-Process | Where-Object { $_.Path -like "*\Temp\*" -or $_.Path -like "*\AppData\*" }
    ```
    
- **List non-Microsoft processes**:
    
    ```powershell
    Get-Process | Where-Object { $_.Company -notlike "*Microsoft*" } | Select-Object Name, Path, Company
    ```
    
- **Check for unsigned executables**:
    
    ```powershell
    Get-ChildItem -Path C:\ -Recurse -Include *.exe | Where-Object { (Get-AuthenticodeSignature $_.FullName).Status -ne "Valid" }
    ```
    
- **Export network connections to CSV**:
    
    ```powershell
    Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State | Export-Csv -Path connections.csv -NoTypeInformation
    ```
    

---

## 4. Detecting Malicious PowerShell Activity

### Indicators of Malicious Activity

- **Obfuscated commands**: Look for long, unreadable strings, excessive use of variables, or concatenated commands.
    
    ```powershell
    $a = "I"; $b = "n"; $c = "v"; $d = "o"; $e = "k"; $f = "e"; &$($a+$b+$c+$d+$e+$f)-Command whoami
    ```
    
- **Encoded payloads**: Base64-encoded strings in scripts or command lines.
    
    ```powershell
    powershell -EncodedCommand JABhAD0AIgBJACIAOwAkAGIAIAA9ACAAIgBuACIAOwAkAGMAIAA9ACAAIgB2ACIAOw==
    ```
    
- **Suspicious execution patterns**:
    - PowerShell launched from unusual directories (e.g., `%Temp%`, `%AppData%`).
    - Non-standard parent processes (e.g., `cmd.exe`, `mshta.exe`).
    - High CPU/memory usage by `powershell.exe`.

### Detection Techniques

- **Check running PowerShell processes**:
    
    ```powershell
    Get-Process -Name powershell | Select-Object Name, ID, Path, @{Name="CommandLine";Expression={(Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)").CommandLine}}
    ```
    
- **Monitor PowerShell command history**:
    
    ```powershell
    Get-History | Select-Object CommandLine, ExecutionStatus
    ```
    
- **Search for encoded commands**:
    
    ```powershell
    Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 100 | Where-Object { $_.Id -eq 4104 } | Select-Object @{Name="ScriptBlock";Expression={$_.Properties[2].Value}}
    ```
    

---

## 5. PowerShell Log Analysis

### Key Log Sources

- **Windows Event Logs**:
    
    - **Security Log**: Events like logons (ID 4624), privilege changes (ID 4672).
    - **PowerShell Operational Log**: Script block logging (ID 4104), pipeline execution (ID 4103).
    
    ```powershell
    Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 50
    ```
    
- **Sysmon Logs**:
    
    - Process creation (ID 1), network connections (ID 3), file creation (ID 11).
    
    ```powershell
    Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object { $_.Id -eq 1 } | Select-Object @{Name="Process";Expression={$_.Properties[4].Value}}, @{Name="CommandLine";Expression={$_.Properties[10].Value}}
    ```
    

### Enabling PowerShell Logging

- Enable Script Block Logging:
    
    ```powershell
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
    ```
    
- Enable Module Logging:
    
    ```powershell
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1
    ```
    

---

## 6. Artifacts and Indicators to Investigate

- **File Artifacts**:
    - Suspicious `.ps1`, `.vbs`, `.bat` files in `%Temp%`, `%AppData%`, or `%ProgramData%`.
    - Unsigned executables or DLLs.
- **Registry Keys**:
    
    - Run keys: `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
    - WMI subscriptions: `HKLM\SOFTWARE\Microsoft\Wbem`
    
    ```powershell
    Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
    ```
    
- **Event Log Indicators**:
    - Frequent failed logons (ID 4625).
    - PowerShell execution from unusual processes (ID 4104).
- **Network Indicators**:
    - Connections to known malicious IPs or domains.
    - Unusual ports or protocols.

---

## 7. Example Investigation Workflow

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
    

---

## 8. Decoding Base64 and Identifying Suspicious Scripts

### Decode Base64 Commands

- **Decode encoded command**:
    
    ```powershell
    $encoded = "JABhAD0AIgBJACIAOwAkAGIAIAA9ACAAIgBuACIAOwAkAGMAIAA9ACAAIgB2ACIAOw=="
    [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encoded))
    ```
    
- **Extract from event logs**:
    
    ```powershell
    Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | Where-Object { $_.Id -eq 4104 } | ForEach-Object { [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($_.Properties[2].Value)) }
    ```
    

### Identify Suspicious Scripts

- Look for:
    
    - Random variable names (e.g., `$x12`, `$z9`).
    - Excessive use of string concatenation or `Invoke-Expression`.
    - Calls to `System.Net.WebClient` or `Invoke-WebRequest` for downloading payloads.
    
    ```powershell
    Get-Content suspicious.ps1 | Select-String "Invoke-Expression|System.Net.WebClient|Invoke-WebRequest"
    ```
    
