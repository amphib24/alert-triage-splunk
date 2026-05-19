# Alert Triage Splunk – Web Shell Investigation

## Introduction
&nbsp;&nbsp;&nbsp;Web shells are malicious scripts uploaded to a web server that allows an attacker to remotely execute commands and compromise the server. They are commonly used for unauthorized access, data exfiltration, and further network compromise.

## Scenario 
&nbsp;&nbsp;&nbsp; I am working as a SOC Level 1 Analyst for an MSSP. I have been tasked with investigating a possible webs shell on a web server utilizing Splunk to determine whether it should be considered suspicious and require escalation. The investigation is being conducted using logs sourced from:
  
   - index="web-alert"

### Alert Details
-	Alert Name: Potential Web Shell Upload Detected
-	Time: `14/09/2025 09:31:51 AM`
-	Resources: `http://web.trywinme.thm` (web server)
-	Suspicious IP: `171[.]251[.]232[.]40`

## Potential Indicators of Attack (IOA’s)
-	High volume of brute-force attempts 
-	Request for a suspicious file associated with known web shell activity
-	Multiple HTTP 302 responses following brute-force attempts
-	IP associated with malicious activity

## Analysis

### IP Address Reputation Analysis

#### Analyst Observation:

-	Initial investigation into the suspicious IP `171[.]251[.]232[.]40` was conducted using AbuseIPDB. Evidence indicates a high confidence of abuse score (100%), further validating the initial alert. Additional investigation into related network activity is needed to determine the scope and impact of any correlated events.  

Note: The screenshot used for this write up was provided as part of the TryHackMe lab and does not reflect the current real-time AbuseIPDB status.

<img width="775" height="653" alt="abuseipdb" src="https://github.com/user-attachments/assets/3ce3cdd3-1623-41eb-9f8e-b4a2ec0dfd95" />

### IP Activity Analysis

#### Splunk Query Used:

-	Index=”web-alert” 171.251.232.40
  | table _time clientip useragent method status uri_path

#### Analyst Observation:

-	Start Time: `21:20:27`
-	Finish Time: `21:20:42`
-	Log analysis of activity related to the suspicious IP revealed behavior consistent with brute force attempts against the web servers `/wp-login.php` page, with 340 total events recorded. The observed user agent, `Mozilla/5.0 (Hydra)`, suggests that the attacker used Hydra, a tool commonly used to automate credential brute-force attacks. Although the majority of HTTP responses returned ‘200 OK’ (333 total) status codes, this indicates successful processing of the HTTP request and does not represent a successful login attempt. This behavior is highly suspicious and requires further investigation to determine whether the attack was successful or not. 

<img width="1865" height="787" alt="hyrda" src="https://github.com/user-attachments/assets/4a33420c-452b-457e-bf77-c69ea9fb7a17" />

### Successful Login Attempt

#### Splunk Query Used:

-	index="web-alert" 171.251.232.40 status=302
	| table _time clientip useragent method status uri_path referer referer_domain

 #### Analyst Observation

-	Analysis into events with a HTTP 302 code identified two sessions of interest associated with the suspicious IP. HTTP 302 responses may indicate possible login events, as the code is commonly used to redirect users following successful login.

-	 At 21:20:42 Hydra appears to have successfully cracked login credentials. This was followed by a second login attempt at `21:21:27` via a different user-agent `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36`, which is consistent with behavior that may indicate an attacker transitioning from automated attack activity to manual or browser-based access. Further investigation is needed to identify any further actions taken.

<img width="1857" height="712" alt="302" src="https://github.com/user-attachments/assets/5c83c5e2-0a65-4d0e-926c-4895bd6fa0bb" />

### User-Agent Exclusion Analysis

#### Splunk Query Used:
   
-  index="web-alert" 171.251.232.40 useragent!="Mozilla/5.0 (Hydra)"
   | table _time clientip useragent method status uri_path referer referer_domain

-	 index="web-alert" 171.251.232.40 b374k.php 
   | table _time clientip useragent method status uri_path referer referer_domain

#### Analyst Observation:

-	Investigation of HTTP activity excluding the Hydra user-agent `Mozilla/5.0 (Hydra)` identified a request to `/wp-admin/admin-ajax.php` containing a query parameter referencing a suspicious file `b374k.php`. The request returned a 200 ok status code, indicating successful processing of the request. 

<img width="1861" height="510" alt="webshell_identified" src="https://github.com/user-attachments/assets/63e65f13-765b-48e9-a5e4-61508bbf5ecf" />

-	According to open-source intelligence sources (Huntress) `b374k.php` is identified as being a PHP-based web shell commonly used for remote access and command executions on compromised servers. 

<img width="1862" height="802" alt="opensource-intel" src="https://github.com/user-attachments/assets/50c44bf6-ca5b-44d8-ac34-dc3aadf1976a" />

-	Further log analysis of queries specific to `b374k.php` identified four successful POST requests related to the web shell suggesting the web shell may have been used in some form of execution activity on the server. However, evidence of specific actions taken was not provided in the logs. 

<img width="1853" height="595" alt="further_activity" src="https://github.com/user-attachments/assets/9e90772b-fa5a-4861-8172-d4ee79627fc6" />

## Conclusion

&nbsp;&nbsp;&nbsp The investigation identified a high-volume of authentication attempts from a user-agent associated with THC Hydra, indicating a brute-force authentication attack against the server. After investigating the source IP `171[.]251[.]232[.]40` using AbuseIPDB it was confirmed as being a well-known IP tied to malicious activity. Log analysis using Splunk revealed activity consistent with a successful login, followed by execution activity related to a well-known web shell `b374k.php`. Specifics into what the execution activity consisted of were unavailable. This event is assessed as a True Positive and should be escalated to a Tier 2 Analyst for further investigation into the scope, impact, and potential persistence mechanisms.
