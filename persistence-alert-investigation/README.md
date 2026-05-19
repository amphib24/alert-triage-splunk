# Alert Triage Splunk - Persistence Investigation

## Introduction

&nbsp;&nbsp;&nbsp; Persistence is when an attacker is able to maintain access for extended periods of time after establishing initial access to the system. This can be achieved through various techniques such as creating scheduled tasks, modifying system files, creating new user accounts, and adding users to privileged groups.

## Scenario 
 
&nbsp;&nbsp;&nbsp; I am working as a SOC Level 1 Analyst for an MSSP. I have been tasked with investigating a suspicious scheduled task that was created on a Microsoft host, utilizing Splunk to determine whether it should be considered suspicious and require escalation. The investigation is being conducted using logs sourced from:
  - index=win-alert

### Alert Details
  
   -	Alert Name: Potential Task Scheduler Persistence Identified
   -	Time: `30/08/2025 10:06:07`
   -	Target Host: `WIN-H015`
   -	User: `oliver.thompson`
   -	Task Name: AssessmentTaskOne
   -  No asset inventory table provided

## Potential Indicators of Attack (IOAs)
  - suspicious scheduled task created on a host

## Analysis

## Initial Query 

#### Splunk Query Used:
   - index="win-alert"

#### Analyst Observation
   - The initial query came back with 6,992 results indicating a large volume of log data. Further filtering will be required to narrow down the search and isolate events relevant to the investigation.

<img width="1863" height="762" alt="initial index" src="https://github.com/user-attachments/assets/d0e567a6-1814-4f46-a19b-097c909acab5" />

## Query by Event Code
 The Windows Event ID for the creation of scheduled tasks is 4698, which I used to narrow down the search to relevant activity.

#### Splunk Query Used:
   - -	index=”win-alert” EventCode=4698

#### Analyst Observation: 
   - A single event was returned by the query with the user account `oliver.thompson` on the `host WIN-H015`, indicating the scheduled host was created on the system. Further analysis is required to determine the purpose and execution behavior of the task

<img width="1862" height="769" alt="second filter by event code" src="https://github.com/user-attachments/assets/3699f01c-a48d-434a-93bd-6c67348afb34" />

## Event Analysis

#### Analyst Observation:
   - Further investigation reveals the task was configured to execute daily starting on 2025-08-30 at 10:15:00. The task launches PowerShell and executed a command utilizing certutil.exe to download the file `rv.exe` from `http://tryhotme:9876/rv[.]exe` to the local path `C:\Users\OLIVER~1.THO\AppData\Local Temp\3\DataCollector.exe`. Following the download, the task executes the payload. This is highly suspicious behavior which is consistent with a persistence mechanism used to        repeatably download and execute malicious tooling. The Parent Process ID (PPID) was also found which is 4218, which will be used to further investigate the incident.

<img width="1051" height="836" alt="start_time and frequency" src="https://github.com/user-attachments/assets/2bcb554c-5f21-4f24-b0db-dab114f95999" />

<img width="1433" height="443" alt="malicious command" src="https://github.com/user-attachments/assets/b9afc74d-8869-485a-b6ec-5a1d66d80406" />

## Parent Process ID Investigation

#### Splunk Query used:
   - index=”win-alert” ParentProcessId=4128

#### Analyst Observation:
   - The analysis of PPID 4128 revealed that cmd.exe was the parent process responsible for creating the scheduled task used to establish persistence on the host. The use of cmd.exe is suspicious, because its commonly used by attackers to           execute commands, launch scripts, execute payloads, along with other malicious activity, while blending in with legitimate system activity.

<img width="1535" height="635" alt="PPID-result_1" src="https://github.com/user-attachments/assets/430cb27b-0f2b-47d8-a230-34b70fa7e573" />

<img width="1580" height="382" alt="PPID-result-2" src="https://github.com/user-attachments/assets/ea207a83-a4de-4d85-8bb5-f204d62cf3a0" />

## Command Line Investigation

#### Splunk Query Used:
   - index =”win-alert” ParentProcessId=4218
     | table _time ParentCommandLine CommandLine

#### Analyst Observation
   - The analysis of command-line activity revealed the execution of net localgroup Administrators, which was used to add the user oliver.thompsoin to the local Administrators group. This activity is indicative of successful privilege               escalation and contributes to persistence by granting the attacker elevated and persistent access to the system.

<img width="1857" height="652" alt="cmd_investifation" src="https://github.com/user-attachments/assets/06df6c60-7651-4d5c-9ae1-097b14f6bd1c" />

## Source Host Identification
 The originating workstation was identified by pivoting from successful login attempts using Event ID 4624 and the compromised user account.

#### Splunk Queries Used:
   - Index=”win-alert” EventCode=4624 Account_Name=”oliver.thompson”
    Followed by 
   - Index=”win-alert” EventCode=4624 Account_Name=”oliver.thompson” Workstation_Name=”DEV-QA-SERVER”

#### Analyst Observation:
   - Further Investigation revealed the originating workstation associated with the suspicious activity. The attacker logged into the user account `oliver.thompson` on host `WIN-H01`5 from workstation `DEV-QA-SERVER`, indicating that this system is the likely source of the initial point of compromise. 

<img width="1526" height="708" alt="source host id" src="https://github.com/user-attachments/assets/87e2c1f0-017d-4500-9043-9be50592a438" />

## Conclusion

&nbsp;&nbsp;&nbsp; The investigation identified a successful compromise of the account oliver.thompson, which originated from the workstation `DEV-QA-SERVER` and targeted the host `WIN-H015`. Initial access was achieved via valid authentication, followed by the creation of a scheduled task `Event ID 4968` used to establish persistence. Further analysis, revealed the use of `cmd.exe` to execute malicious commands. Privilege escalation was confirmed via the use of `net localgroup Administrators`, which added the compromised host to the local Administrators group, granting elevated privileges on the system. In addition, a malicious payload `DataCollector.exe` was downloaded via `certutil.exe`. Due to the severity of the activity and confirmed persistence on the host, this incident is verified to be a true positive and requires immediate escalation to SOC Tier 2 for containment, further remediation, and remediation.

