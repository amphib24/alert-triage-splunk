## Aler Triage Splunk - Initial Access Investigation

## Introduction

&nbsp;&nbsp;&nbsp; Initial access is the point of the attack where the attacker successfuly gains their initial foothold into a system or network, typically through compromised credentials or exploiting authentication
vulnerabilities such as brute force attacks. This investigation is focused on repeated failed login attempts followed by a successfull login to a valid user account. 

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
I began by searching for the available options under source_type.

#### Analyst Observation: 
   - Two log sources were available, linux_secure and syslog-alert. The linux_secure index was chosen because it contains authentication and security-related events for Linux hosts.

<img width="1851" height="841" alt="step-1-verify-sourcetype" src="https://github.com/user-attachments/assets/86291c7e-a061-42c5-bc22-143c56e3fe0c" />
