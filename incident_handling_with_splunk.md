http://www.imreallynotbatman.com

	index=botsv1 imreallynotbatman.com -> sourcetype: Suricata, stream:http, fortigate_utm, iis

	index=botsv1 imreallynotbatman.com sourcetype=stream:http -> src_ip: 40.80.148.42 (93%), 23.22.63.114

# Reconnaissance Phase

1. One suricata alert highlighted the CVE value associated with the attack attempt. What is the CVE value? 
```
index=botsv1 imreallynotbatman.com src=40.80.148.42 sourcetype=suricata 
	-> alert.signature 
		-> CVE-2014-6271
```

2. What is the CMS our web server is using?
3. What is the web scanner, the attacker used to perform the scanning attempts?
```
index=botsv1 imreallynotbatman.com sourcetype=stream:http 
	-> src_headers 
		-> Acunetix (web scanner)
	-> uri 
		-> joomla (CMS)
```

4. What is the IP address of the server imreallynotbatman.com?
```
index=botsv1 imreallynotbatman.com sourcetype="suricata" src=40.80.148.42 event_type=alert 
	-> IP: 192.168.250.70
```

# Exploitation Phase

```
index=botsv1 imreallynotbatman.com sourcetype=stream* | stats count(src_ip) as Requests by src_ip | sort - Requests
```

```
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" 
	-> http_method (POST:70%)

index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST 
	-> src_ip (40.80.148.42), form_data, http_user_agent, uri (/joomla/administrator/index.php)

index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST uri="/joomla/administrator/index.php" | table _time uri src_ip dest_ip form_data 
	-> src_ip=23.22.63.114 (attacker ip -> bruteforce)

index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST form_data=*username*passwd* | rex field=form_data "passwd=(?<creds>\w+)" | table src_ip creds

index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST form_data=*username*passwd* | rex field=form_data "passwd=(?<creds>\w+)" | table _time src_ip uri http_user_agent creds 
	-> 1 passwd from Mozilla => passwd correct
```
5. What IP address is likely attempting a brute force password attack against **imreallynotbatman.com**?  

>Answer: 23.22.63.114

6. What was the URI which got multiple brute force attempts?  

>Answer: /joomla/administrator/index.php

7. Against which username was the brute force attempt made?

>Answer: admin

8. What was the correct password for admin access to the content management system running **imreallynotbatman.com**?  

>Answer: batman

9. How many unique passwords were attempted in the brute force attempt?  

>Answer: 412

10. After finding the correct password, which IP did the attacker use to log in to the admin panel?  

>Answer: 40.80.148.42

# Installation Phase

```
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" *.exe
	-> part_filename
		-> 3791.exe
```
```
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" "part_filename{}"="3791.exe"
	-> c_ip (client ip)
		-> 40.80.148.42
```
```
index=botsv1 "3791.exe" sourcetype=xmlwineventlog EventID=1
	-> CommandLine
		-> cmd.exe /c "3791.exe 2&gt;&amp;1"
		-> 3791.exe
```

11. Sysmon also collects the Hash value of the processes being created. What is the MD5 HASH of the program 3791.exe?

> Answer: AAE3F5A29935E6ABCC2C2754D12A9AF0

12. Looking at the logs, which user executed the program 3791.exe on the server?

> Answer: NT AUTHORITY\\IUSR

13. Search hash on the virustotal. What other name is associated with this file 3791.exe?

 > Answer: ab.exe
 
#  Action on Objectives

```
index=botsv1 src=192.168.250.70 sourcetype=suricata
	-> dest_ip
		-> 40.80.148.42, 23.22.63.114
```
```
index=botsv1 src=192.168.250.70 sourcetype=suricata dest_ip=23.22.63.114
	-> url
		-> /poisonivy-is-coming-for-you-batman.jpeg
		-> /joomla/administrator/index.php
```
```
index=botsv1 url="/poisonivy-is-coming-for-you-batman.jpeg" dest_ip="192.168.250.70" | table _time src dest_ip http.hostname url
	-> http.hostname
		-> prankglassinebracket.jumpingcrab.com
```
14. What is the name of the file that defaced the imreallynotbatman.com website ?

> Answer: poisonivy-is-coming-for-you-batman.jpeg

15. Fortigate Firewall 'fortigate_utm' detected SQL attempt from the attacker's IP 40.80.148.42. What is the name of the rule that was triggered during the SQL Injection attempt?

```
index=botsv1 sourcetype="fortigate_utm" srcip="40.80.148.42"
	-> msg: web_misc: HTTP.URI.SQL.Injection
	-> attack: HTTP.URI.SQL.Injection
```

> Answer: HTTP.URI.SQL.Injection

# Command and Control Phase
```
index=botsv1 sourcetype=fortigate_utm"poisonivy-is-coming-for-you-batman.jpeg"
	-> srcip, url
```
```
index=botsv1 sourcetype=stream:http dest_ip=23.22.63.114 "poisonivy-is-coming-for-you-batman.jpeg" src_ip=192.168.250.70
	-> request
	-> site
```
16. This attack used dynamic DNS to resolve to the malicious IP. What fully qualified domain name (FQDN) is associated with this attack?
> Answer: prankglassinebracket.jumpingcrab.com

# Weaponization Phase
17. What IP address has P01s0n1vy tied to domains that are pre-staged to attack Wayne Enterprises?

> Answer: 23.22.63.114

18. Based on the data gathered from this attack and common open-source intelligence sources for domain names, what is the email address that is most likely associated with the P01s0n1vy APT group?

[Hostname: www.po1s0n1vy.com - AlienVault - Open Threat Exchange](https://otx.alienvault.com/indicator/hostname/www.po1s0n1vy.com)

> Answer: lillian[.]rose@po1s0n1vy[.]com

# Delivery Phase

19. What is the HASH of the Malware associated with the APT group?  

> Answer: c99131e0169171935c5ac32615ed6261

20. What is the name of the Malware associated with the Poison Ivy Infrastructure?

> Answer: MirandaTateScreensaver.scr.exe

# Conclusion

In this fun exercise, as a SOC Analyst, we have investigated a cyber-attack where the attacker had defaced a website 'imreallynotbatman.com' of the Wayne Enterprise. We mapped the attacker's activities into the 7 phases of the Cyber Kill Chain. Let us recap everything we have found so far:

**Reconnaissance Phase:**

We first looked at any reconnaissance activity from the attacker to identify the IP address and other details about the adversary.

**Findings:**

-   IP Address `40.80.148.42` was found to be scanning our webserver.
-   The attacker was using Acunetix as a web scanner.

**Exploitation Phase:**

We then looked into the traces of exploitation attempts and found brute-force attacks against our server, which were successful.

**Findings:**

-   Brute force attack originated from IP `23.22.63.114.`
-   The IP address used to gain access: `40.80.148.42`
-   142 unique brute force attempts were made against the server, out of which one attempt was successful

**Installation Phase:**

Next, we looked at the installation phase to see any executable from the attacker's IP Address uploaded to our server.

**Findings:**

-   A malicious executable file `3791.exe` was observed to be uploaded by the attacker.
-   We looked at the sysmon logs and found the MD5 hash of the file.

**Action on Objective:**

After compromising the web server, the attacker defaced the website.

**Findings:**

-   We examined the logs and found the file name used to deface the webserver.

**Weaponization Phase:**

We used various threat Intel platforms to find the attacker's infrastructure based on the following information we saw in the above activities.

Information we had:

Domain: `prankglassinebracket.jumpingcrab.com`

IP Address: `23.22.63.114`

**Findings:**

-   Multiple masquerading domains were found associated with the attacker's IPs.
-   An email of the user `Lillian.rose@po1s0n1vy.com` was also found associated with the attacker's IP address.

**Deliver Phase:**

In this phase, we again leveraged online Threat Intel sites to find malware associated with the adversary's IP address, which appeared to be a secondary attack vector if the initial compromise failed.

**Findings:**

-   A malware name `MirandaTateScreensaver.scr.exe` was found associated with the adversary.
-   MD5 of the malware was `c99131e0169171935c5ac32615ed6261`