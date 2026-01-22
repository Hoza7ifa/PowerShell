
1. **Get Running Processes**
    
    ```powershell
    Get-Process | Select-Object Id, ProcessName, CPU
    ```
    
    Quick glance at what’s running on a machine to identify resource-heavy or suspicious processes.
    
2. **Find Suspicious Processes by Parent**
    
    ```powershell
    Get-CimInstance Win32_Process | Where-Object { $_.ParentProcessId -eq 0 }
    ```
    
    Spot orphaned or suspicious processes that lack a legitimate parent process, often a sign of malicious activity.
    
3. **Get Active Network Connections**
    
    ```powershell
    Get-NetTCPConnection | Select-Object LocalAddress, RemoteAddress, State
    ```
    
    See active TCP connections to identify communication with potentially malicious IPs or domains.
    
4. **Check for Unusual Listening Ports**
    
    ```powershell
    Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -gt 1024 }
    ```
    
    Detect processes listening on high (non-standard) ports, which could indicate backdoors or unauthorized services.
    
5. **Retrieve Recent Security Events**
    
    ```powershell
    Get-WinEvent -LogName Security -MaxEvents 50
    ```
    
    Pull the latest security events from the Windows Event Log for auditing logons, privilege changes, or suspicious activity.
    
6. **List Installed Software**
    
    ```powershell
    Get-WmiObject -Class Win32_Product | Select-Object Name, Version
    ```
    
    Identify installed software to check for unauthorized or vulnerable applications.
    
7. **Check for Admin Users**
    
    ```powershell
    Get-LocalGroupMember -Group "Administrators"
    ```
    
    List users with administrative privileges to detect unauthorized privilege escalation.
    
8. **Get Failed Logon Attempts**
    
    ```powershell
    Get-WinEvent -LogName Security | Where-Object { $_.Id -eq 4625 } | Select-Object TimeCreated, @{Name="Account";Expression={$_.Properties[5].Value}}
    ```
    
    Identify potential brute-force attacks by reviewing failed logon attempts (Event ID 4625).
    
9. **List Running Services**
    
    ```powershell
    Get-Service | Where-Object { $_.Status -eq "Running" } | Select-Object Name, DisplayName
    ```
    
    Review running services to spot unauthorized or suspicious services.
    
10. **Check for Suspicious Scheduled Tasks**
    
    ```powershell
    Get-ScheduledTask | Where-Object { $_.State -eq "Ready" } | Select-Object TaskName, TaskPath
    ```
    
    Identify potentially malicious scheduled tasks used for persistence.
    
11. **Get System Uptime**
    
    ```powershell
    (Get-Date) - (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
    ```
    
    Check system uptime to determine if a reboot was missed or if suspicious activity occurred since last boot.
    
12. **List Open Files**
    
    ```powershell
    Get-SmbOpenFile | Select-Object ClientComputerName, Path
    ```
    
    Identify files opened over the network, useful for detecting unauthorized access.
    
13. **Check for Unsigned Drivers**
    
    ```powershell
    Get-CimInstance Win32_PnPSignedDriver | Where-Object { $_.IsSigned -eq $false }
    ```
    
    Detect unsigned drivers, which could indicate rootkits or malicious kernel modules.
    
14. **Get Firewall Rules**
    
    ```powershell
    Get-NetFirewallRule | Select-Object Name, Enabled, Direction, Action
    ```
    
    Review firewall rules to ensure no unauthorized inbound/outbound connections are allowed.
    
15. **Find Large Files**
    
    ```powershell
    Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt 100MB }
    ```
    
    Locate unusually large files that might indicate data exfiltration or malware storage.
    
16. **Check for Hidden Files**
    
    ```powershell
    Get-ChildItem -Path C:\ -Recurse -Hidden -ErrorAction SilentlyContinue
    ```
    
    Identify hidden files that could be used to conceal malicious payloads.
    
17. **Get Recent File Modifications**
    
    ```powershell
    Get-ChildItem -Path C:\ -Recurse | Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-24) }
    ```
    
    Find files modified in the last 24 hours, useful for detecting recent malicious activity.
    
18. **List Active PowerShell Sessions**
    
    ```powershell
    Get-PSSession
    ```
    
    Check for active PowerShell sessions that might indicate remote access or persistence.
    
19. **Get Registry AutoRun Entries**
    
    ```powershell
    Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
    ```
    
    Review auto-run registry keys for persistence mechanisms used by malware.
    
20. **Check for Suspicious DNS Queries**
    
    ```powershell
    Get-DnsClientCache | Where-Object { $_.Data -match "[a-z0-9-]+\.xyz" }
    ```
    
    Identify DNS queries to suspicious domains (e.g., .xyz, often used by malicious actors).
    
21. **List USB Device History**
    
    ```powershell
    Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*"
    ```
    
    Review USB device history to detect unauthorized device usage.
    
22. **Get Process Command Line Arguments**
    
    ```powershell
    Get-CimInstance Win32_Process | Select-Object ProcessId, Name, CommandLine
    ```
    
    Inspect command-line arguments for suspicious process execution.
    
23. **Check for PowerShell Script Execution**
    
    ```powershell
    Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | Where-Object { $_.Id -eq 4104 }
    ```
    
    Detect PowerShell script execution (Event ID 4104) for potential malicious scripts.
    
24. **List Network Shares**
    
    ```powershell
    Get-SmbShare
    ```
    
    Identify network shares that could be misconfigured or used for lateral movement.
    
25. **Get Logged-On Users**
    
    ```powershell
    Get-CimInstance -ClassName Win32_LoggedOnUser
    ```
    
    List users currently logged on to detect unauthorized access.
    
26. **Check for Remote Desktop Connections**
    
    ```powershell
    Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" | Where-Object { $_.Id -eq 21 }
    ```
    
    Identify successful RDP connections (Event ID 21) for potential unauthorized access.
    
27. **List Installed Patches**
    
    ```powershell
    Get-HotFix | Select-Object HotFixID, Description, InstalledOn
    ```
    
    Verify patch status to identify unpatched vulnerabilities.
    
28. **Check for Suspicious Registry Modifications**
    
    ```powershell
    Get-WinEvent -LogName System | Where-Object { $_.Id -eq 4657 }
    ```
    
    Detect registry modifications (Event ID 4657) that could indicate persistence or configuration changes.
    
29. **Get System Environment Variables**
    
    ```powershell
    Get-ChildItem Env:
    ```
    
    Review environment variables for suspicious entries like malicious paths.
    
30. **List Active Directory Users**
    
    ```powershell
    Get-ADUser -Filter * | Select-Object Name, Enabled
    ```
    
    List Active Directory users to identify disabled or suspicious accounts (requires Active Directory module).
    
31. **Check for Suspicious Group Membership**
    
    ```powershell
    Get-ADGroupMember -Identity "Domain Admins" | Select-Object Name
    ```
    
    Verify Domain Admins group membership for unauthorized accounts.
    
32. **Get Event Log Cleared Events**
    
    ```powershell
    Get-WinEvent -LogName Security | Where-Object { $_.Id -eq 1102 }
    ```
    
    Detect event log clearing (Event ID 1102), a common attacker tactic to cover tracks.
    
33. **List Running Drivers**
    
    ```powershell
    Get-WmiObject Win32_SystemDriver | Select-Object Name, State
    ```
    
    Review running drivers to identify potentially malicious ones.
    
34. **Check for Suspicious WMI Subscriptions**
    
    ```powershell
    Get-WmiObject -Namespace root\subscription -Class __EventConsumer
    ```
    
    Detect persistent WMI subscriptions used by malware for execution.
    
35. **Get File Hashes**
    
    ```powershell
    Get-FileHash -Path "C:\path\to\file.exe" -Algorithm SHA256
    ```
    
    Calculate file hashes to verify integrity or check against known malicious hashes.
    
36. **List Open Ports**
    
    ```powershell
    netstat -ano | ConvertFrom-String | Select-Object P2, P4, P5
    ```
    
    Parse netstat output to list open ports and associated processes.
    
37. **Check for Suspicious Startup Programs**
    
    ```powershell
    Get-CimInstance Win32_StartupCommand
    ```
    
    Identify programs set to run at startup, which could include malware.
    
38. **Get System Memory Usage**
    
    ```powershell
    Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize, FreePhysicalMemory
    ```
    
    Monitor memory usage to detect anomalies caused by malicious processes.
    
39. **List Active Directory Group Policies**
    
    ```powershell
    Get-GPO -All | Select-Object DisplayName, GPOStatus
    ```
    
    Review Group Policy Objects for misconfigurations or unauthorized changes.
    
40. **Check for Suspicious File Extensions**
    
    ```powershell
    Get-ChildItem -Path C:\ -Recurse | Where-Object { $_.Extension -in ".bat", ".vbs", ".ps1" }
    ```
    
    Identify scripts in sensitive locations that could be malicious.
    
41. **Get Recent Account Lockouts**
    
    ```powershell
    Get-WinEvent -LogName Security | Where-Object { $_.Id -eq 4740 }
    ```
    
    Detect account lockouts (Event ID 4740) to investigate potential brute-force attacks.
    
42. **List Connected Drives**
    
    ```powershell
    Get-Disk
    ```
    
    Identify connected drives, including external or network drives, for unauthorized access.
    
43. **Check for Suspicious Service Changes**
    
    ```powershell
    Get-WinEvent -LogName System | Where-Object { $_.Id -eq 7045 }
    ```
    
    Detect new service installations (Event ID 7045), which could indicate malware persistence.
    
44. **Get ARP Cache**
    
    ```powershell
    Get-NetNeighbor | Select-Object IPAddress, LinkLayerAddress
    ```
    
    Review ARP cache for signs of ARP spoofing or unauthorized devices.
    
45. **List Installed PowerShell Modules**
    
    ```powershell
    Get-Module -ListAvailable
    ```
    
    Identify installed PowerShell modules that could be used maliciously.
    
46. **Check for Suspicious User Profile Changes**
    
    ```powershell
    Get-WinEvent -LogName Security | Where-Object { $_.Id -eq 4738 }
    ```
    
    Detect user account changes (Event ID 4738) that could indicate unauthorized modifications.
    
47. **Get System Boot Configuration**
    
    ```powershell
    bcdedit
    ```
    
    Review boot configuration for tampering or dual-boot malware.
    
48. **List Active Directory Computers**
    
    ```powershell
    Get-ADComputer -Filter * | Select-Object Name, LastLogonDate
    ```
    
    Identify stale or suspicious computer accounts in Active Directory.
    
49. **Check for Suspicious Kerberos Events**
    
    ```powershell
    Get-WinEvent -LogName Security | Where-Object { $_.Id -eq 4768 }
    ```
    
    Monitor Kerberos authentication events (Event ID 4768) for signs of ticket abuse.
    
50. **Export Event Logs to CSV**
    
    ```powershell
    Get-WinEvent -LogName Security -MaxEvents 100 | Export-Csv -Path "security_logs.csv" -NoTypeInformation
    ```
    
    Export security event logs for offline analysis or reporting.