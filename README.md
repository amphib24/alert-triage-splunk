# Alert Triage Splunk Repository
&nbsp;&nbsp;&nbsp;This repository is a collection of SOC Level alert triage investigations using Splunk. The investigations follow the labs from TryHackMe's SOC 1 Alert Triage With Splunk room. Each investigation represents separate security
alert triggered across various environments. These include Linux endpoints, Windows systems, and a web server. The purpose is to demonstrate SOC Tier 1 workflows including log analysis, alert validation, escalation decisions and identifying 
malicious activity. 

# Demonstrated Skills
   - Splunk SIEM analysis and query writing
   - Authentication log investigation (Linux)
   - Windows event log analysis
   - Web server log investigation
   - Alert triage and escalation decisions
   - Attack pattern recognition
   - Persistence and privilege escalation detection
   - Web shell identification
   - IOC extraction and correlation

# Investigations

## Linux Brute Force Investigation
 An Analysis of authentication logs identifying brute force activity that leads to an attacker gaining initial access to the system, followed by privilege escalation and establishing persistence. 

 ## Technical Analysis
 <a href="https://github.com/amphib24/alert-triage-splunk/tree/main/initial-access-investigation">Analysis</a>

## Persistence Alert
 Investigation of a Windows host to identify and analyze attacker-established persistence mechanisms through scheduled tasks, privilege escalation, and malicious command execution.

## Technical Analysis
 <a href = "https://github.com/amphib24/alert-triage-splunk/tree/main/persistence-alert-investigation">Analysis</a>

## Web Shell Alert


