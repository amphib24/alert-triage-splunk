## Alert Triage Splunk - Initial Access Investigation

## Introduction

&nbsp;&nbsp;&nbsp; Initial access is the point of the attack where the attacker successfully gains their initial foothold into a system or network, typically through compromised credentials or exploiting authentication
vulnerabilities such as brute force attacks. This investigation is focused on repeated failed login attempts followed by a successful login to a valid user account. 

## Scenario 
 
&nbsp;&nbsp;&nbsp; I am working as SOC Level 1 Analyst for an MSSP. I have been tasked with investigating a possible brute force attack on a Linux host utilizing Splunk to determine whether it should be considered suspicious and require escalation. The investigation is being conducted using logs sourced from:
  - index=linux-alert

## Potential Indicators of Attack (IOAs)
  - repeated failed SSH authentication attempts followed by multiple successful logins for the same user.

## Analysis

### Alert Details
  
   -	Alert Name: Brute Force Activity Detection
   -	Time: 17/09/2025 9:00:21 AM
   -	Target Host: tryhackme-2404
   -	Source IP: 10.10.242.248
   -	No asset inventory table provided

### Initial Insights
   - I began by searching for the available options under source_type.

#### Analyst Observation: 
   - Two log sources were available, linux_secure and syslog-alert. The linux_secure index was chosen because it contains authentication and security-related events for Linux hosts.

<img width="1851" height="841" alt="step-1-verify-sourcetype" src="https://github.com/user-attachments/assets/86291c7e-a061-42c5-bc22-143c56e3fe0c" />

### Initial Logon Activity Analysis

#### Splunk Query used:
   - index="linux-alert" sourcetype="linux_secure" 10.10.242.248
     | search "Accepted password for" OR "Failed password for" OR "Invalid user"
     | sort +_ time

### Analyst Observation:
   - Multiple login attempts were observed, to include a high volume of failed attempts and invalid user attempts. This is suspicious as it is consistent with brute force activity and requires further
     analysis.

<img width="1866" height="770" alt="step 2 initial filter" src="https://github.com/user-attachments/assets/d50919d7-949f-4144-8ebb-287f7d4eb419" />

### User Authentication Analysis

#### Splunk Query used:
   - index="linux-alert" sourcetype="linux_secure" 10.10.242.248
     | eval action=lower(action)
     | eval action=case(match(action,"fail|blocked|invalid|rejected"), "failed",        match(action,"accepted|success"),"success")
     | stats count values(src_ip) as src_ip values(hostname) as hostname values(process) as process by user action

#### Analyst Observation:
   - There was a large volume of failed attempts observed by the user john.smith, accompanied by multiple successful attempts. These findings further validate a successful brute force attack.

<img width="1864" height="763" alt="step-3-action-by-user-and-process" src="https://github.com/user-attachments/assets/e67940b0-6c0a-46c6-9428-ef855d3142ce" />

### Investigate Successful Logins
   - No query was needed as I was able to click the relevant link in the column, followed by clicking the "View Events" option.

#### Analyst Observation:
   - The attacker successfully logged into the account john.smith at 09:06:01 on 17/09/2025, which confirms initial access to the system. Further analysis is required to determine what actions the attacker took post authentication.

#### Post Authentication Investigation
 I am conducting further analysis on the raw event data to determine what the attacker accomplished post authentication.

#### Analyst Observation: 
   - The attacker gained initial access to the system via the john.smith account. There was multiple authentication sessions observed due to the attacker experiencing multiple disconnections. During the attacker's activity they were able to escalate privileges to root, indicating a successful privilege escalation attempt. Following root access, the attacker created a new user named system-utm. The account was added to multiple privileged groups, indicated by the modifications to /etc/group and /etc/gshadow, indicating the attacker established persistence mechanisms allowing for long-term system access.

<img width="1858" height="458" alt="view raw data" src="https://github.com/user-attachments/assets/cf459262-a89b-4d0f-9899-c539a2f2f1cd" />

<img width="1855" height="743" alt="raw_data_1" src="https://github.com/user-attachments/assets/6bf3e9e5-c77d-4262-a5c0-5e0026c80301" />

<img width="1867" height="743" alt="RAW_DATA_2" src="https://github.com/user-attachments/assets/4bb45585-50df-4434-98ee-46ea5ffeecee" />

## Conlusion
&nbsp;&nbsp;&nbsp; The investigation uncovered a high volume of failed authentication attempts isolated to one user (john.smith), accompanied by multiple successful attempts under the same username. This behavior is indicative of a successful brute force attack, which lead to the attacker gaining privileged access via the root account. The attacker then used this access to create a new user system-utm, which was then added to multiple privileged groups allowing the attacker to establish persistence for a long period of time if not remediated. Due to the severity of this event I will be escalating this alert up to the SOC 2 Level for further investigation and triage. 

