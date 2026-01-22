
This cheat sheet, derived from the "Investigating PowerShell Attacks" white paper by Ryan Kazanciyan and Matt Hastings (Black Hat USA 2014), provides cybersecurity professionals with concise PowerShell commands and techniques to investigate PowerShell-based attacks. It focuses on identifying forensic artifacts, analyzing malicious activity, and detecting persistence mechanisms specific to PowerShell usage.

---

## Registry Analysis

### Check PowerShell Execution Policy

- **Purpose**: Detect if attackers modified the execution policy to `Bypass` for malicious script execution.
- **Command**: Inspect the `ExecutionPolicy` registry value and its last modified timestamp.
    
    ```powershell
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
    Get-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" | Select-Object LastWriteTime
    ```
    

### Monitor Registry for Persistence

- **Purpose**: Identify suspicious entries in common persistence locations.
- **Command**: Check `Run` keys for PowerShell script execution.
    
    ```powershell
    Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
    Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    ```
    

---

## Prefetch Analysis

### Examine PowerShell Prefetch Files

- **Purpose**: Identify PowerShell script execution via prefetch file artifacts (`powershell.exe` or `wsmprovhost.exe`).
- **Command**: List prefetch files related to PowerShell.
    
    ```powershell
    Get-ChildItem -Path "C:\Windows\Prefetch" -Filter "POWERSHELL*.pf"
    Get-ChildItem -Path "C:\Windows\Prefetch" -Filter "WSMPROVHOST*.pf"
    ```
    
- **Note**: Check creation and last run timestamps. Use forensic tools (e.g., `strings`) to extract accessed file information from `.pf` files.

---

## Network Traffic Analysis

### Identify PowerShell Remoting Activity

- **Purpose**: Detect PowerShell remoting via WinRM (Windows Remote Management).
- **Command**: Check for WinRM-related network connections.
    
    ```powershell
    Get-NetTCPConnection | Where-Object { $_.LocalPort -eq 5985 -or $_.LocalPort -eq 5986 } | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess
    ```
    
- **Note**: WinRM uses ports 5985 (HTTP) and 5986 (HTTPS). Look for `wsmprovhost.exe` as the host process for remote commands.

### Monitor WinRM Service

- **Purpose**: Identify if the WinRM service was started for remoting.
- **Command**: Check WinRM service status and process.
    
    ```powershell
    Get-Service -Name "WinRM" | Select-Object Name, Status, StartType
    Get-Process -Name "svchost" | Where-Object { (Get-CimInstance Win32_Service -Filter "ProcessId=$($_.Id)").Name -eq "WinRM" }
    ```
    

---

## Memory Forensics

### Search for PowerShell Commands in Memory

- **Purpose**: Recover remnants of PowerShell commands or scripts in memory, especially from `svchost.exe` (WinRM) or `wsmprovhost.exe`.
- **Command**: Use memory forensic tools (e.g., Volatility) to search for strings, but PowerShell can assist in live analysis.
    
    ```powershell
    Get-Process -Name "svchost", "wsmprovhost" | Select-Object Name, Id, @{Name="CommandLine";Expression={(Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)").CommandLine}}
    ```
    
- **Note**: Memory analysis may yield Web Services Management (WSMAN) SOAP messages or command fragments. Expect noise due to PowerShell’s verbose object structure.

### Check Kernel and Pagefile

- **Purpose**: Look for PowerShell command artifacts in kernel memory or pagefile.
- **Command**: Requires forensic tools, but PowerShell can enumerate running processes for context.
    
    ```powershell
    Get-Process | Where-Object { $_.Path -like "*powershell.exe" -or $_.Path -like "*wsmprovhost.exe" }
    ```
    

---

## Event Log Analysis

### Windows PowerShell Log

- **Purpose**: Identify PowerShell session start (EID 400) and stop (EID 403).
- **Command**: Query PowerShell session events.
    
    ```powershell
    Get-WinEvent -LogName "Windows PowerShell" -MaxEvents 100 | Where-Object { $_.Id -eq 400 -or $_.Id -eq 403 } | Select-Object TimeCreated, Id, Message
    ```
    

### PowerShell Operational Log

- **Purpose**: Capture script block execution (EID 4104) and module logging (EID 4103).
- **Command**: Query script block execution events.
    
    ```powershell
    Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 100 | Where-Object { $_.Id -eq 4104 } | Select-Object @{Name="ScriptBlock";Expression={$_.Properties[2].Value}}
    ```
    
- **Decode Base64 Commands**:
    
    ```powershell
    Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | Where-Object { $_.Id -eq 4104 } | ForEach-Object { [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($_.Properties[2].Value)) }
    ```
    
- **Module Logging**:
    
    ```powershell
    Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 100 | Where-Object { $_.Id -eq 4103 } | Select-Object TimeCreated, @{Name="CommandOutput";Expression={$_.Properties[1].Value}}
    ```
    

### WinRM Operational Log

- **Purpose**: Detect failed remote shell connections (EID 142).
- **Command**:
    
    ```powershell
    Get-WinEvent -LogName "Microsoft-Windows-WinRM/Operational" -MaxEvents 100 | Where-Object { $_.Id -eq 142 } | Select-Object TimeCreated, Message
    ```
    

### AppLocker Logs

- **Purpose**: Identify PowerShell script execution attempts (EID 8005, 8006).
- **Command**: Check AppLocker script events.
    
    ```powershell
    Get-WinEvent -LogName "Microsoft-Windows-AppLocker/MSI and Script" -MaxEvents 100 | Where-Object { $_.Id -eq 8005 -or $_.Id -eq 8006 } | Select-Object TimeCreated, Message
    ```
    

### Enable Analytic Logging

- **Purpose**: Enable PowerShell and WinRM analytic logging for detailed events (not enabled by default).
- **Command**:
    
    ```powershell
    wevtutil set-log "Microsoft-Windows-PowerShell/Analytic" /enabled:true
    wevtutil set-log "Microsoft-Windows-WinRM/Analytic" /enabled:true
    ```
    

---

## Persistence Mechanisms

### Check WMI Event Consumers

- **Purpose**: Detect persistent PowerShell scripts via WMI subscriptions.
- **Command**: List WMI event filters, consumers, and bindings.
    
    ```powershell
    Get-WmiObject -Namespace root\subscription -Class __EventFilter | Select-Object Name, Query
    Get-WmiObject -Namespace root\subscription -Class __EventConsumer | Select-Object Name, CommandLineTemplate
    Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
    ```
    
- **Note**: Search for `powershell.exe` or suspicious `CommandLineTemplate` values. Exclude default consumers like `NTEventLogEventConsumer`.

### Scheduled Tasks

- **Purpose**: Identify malicious scheduled tasks invoking PowerShell.
- **Command**:
    
    ```powershell
    Get-ScheduledTask | Where-Object { $_.Actions.Execute -like "*powershell.exe*" } | Select-Object TaskName, TaskPath, Actions
    ```
    

### Startup Folder and Registry

- **Purpose**: Check for PowerShell scripts in startup locations.
- **Command**:
    
    ```powershell
    Get-CimInstance Win32_StartupCommand | Where-Object { $_.Command -like "*powershell*" } | Select-Object Name, Command, User
    Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" | Where-Object { $_ -like "*powershell*" }
    ```
    

---

## General Investigation Tips

### Enable PowerShell Logging

- **Script Block Logging**:
    
    ```powershell
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
    ```
    
- **Module Logging**:
    
    ```powershell
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1
    ```
    

### Search for Suspicious Scripts

- **Purpose**: Identify scripts with malicious patterns (e.g., `Invoke-Expression`, `System.Net.WebClient`).
- **Command**:
    
    ```powershell
    Get-ChildItem -Path "C:\Temp","C:\Users","C:\ProgramData" -Recurse -Include *.ps1 | Select-String "Invoke-Expression|System.Net.WebClient|Invoke-WebRequest"
    ```
    

### Analyze PowerShell Process Activity

- **Purpose**: Check running PowerShell instances and their command lines.
- **Command**:
    
    ```powershell
    Get-Process -Name "powershell","wsmprovhost" | Select-Object Name, Id, Path, @{Name="CommandLine";Expression={(Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)").CommandLine}}
    ```
    

### Baseline WMI Consumers

- **Purpose**: Establish a baseline of legitimate WMI consumers to detect anomalies.
- **Command**: Run across multiple systems to identify unique entries.
    
    ```powershell
    Get-WmiObject -Namespace root\subscription -Class __EventConsumer | Select-Object Name, CommandLineTemplate | Export-Csv -Path "WMI_Baseline.csv" -NoTypeInformation
    ```
    

### Collect Artifacts

- **Purpose**: Preserve evidence for analysis.
- **Command**: Export process and network data.
    
    ```powershell
    Get-Process | Select-Object Name, Id, Path, StartTime | Export-Csv -Path "processes.csv" -NoTypeInformation
    Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State | Export-Csv -Path "connections.csv" -NoTypeInformation
    ```
    

### Notes

- **Forensic Integrity**: Use read-only cmdlets (e.g., `Get-*`) to avoid system modification.
- **Time Sensitivity**: Memory artifacts are volatile; capture memory snapshots promptly.
- **Noise in Memory Analysis**: PowerShell objects and SOAP messages generate significant noise. Use targeted string searches.
- **Test Environment**: Validate commands in a sandbox before production use.
- **References**: Consult prior research by Lee Holmes, Chris Campbell, and others for advanced techniques.

This cheat sheet provides actionable PowerShell commands for investigating attacks, focusing on artifacts specific to PowerShell as outlined in the 2014 Mandiant white paper.