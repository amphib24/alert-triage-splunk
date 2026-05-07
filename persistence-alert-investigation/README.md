## Alert Triage Splunk - Persistence Investigation

## Introduction

&nbsp;&nbsp;&nbsp; Persistence is when an attacker is able to maintain access for extended periods of time after establishing initial access to the system. This can be achieved through various techniques such as, creating scheduled task, modifying system files, creating new user accounts , and adding users to privileged groups.

## Scenario 
 
&nbsp;&nbsp;&nbsp; I am working as SOC Level 1 Analyst for an MSSP. I have been tasked with investigating a suspicious sheculed task that was created on a Microsoft host, utilizing Splunk to determine whether it should be considered suspicious and require escalation. The investigation is being conducted using logs sourced from:
  - index=win-alert


## Potential Indicators of Attack (IOAs)
  - suspicious scheduled task created on a host

## Analysis

### Alert Details
  
   -	Alert Name: Potential Task Scheduler Persistence Identified
   -	Time: 30/08/2025 10:06:07
   -	Target Host: WIN-H015
   -	User: oliver.thompson
   -	Task Name: AssessmentTaskOne
   -  No asset inventory table provided
