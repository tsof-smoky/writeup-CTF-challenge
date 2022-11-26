You work as a Tier 1 Security Analyst L1 for a Managed Security Service Provider (MSSP). Again, you're tasked with monitoring network alerts.

An alert triggered: Misc activity, A Network Trojan Was Detected, and Potential Corporate Privacy Violation. 

The case was assigned to you. Inspect the PCAP and retrieve the artifacts to confirm this alert is a true positive. 

Your tools:

-   [Brim](https://tryhackme.com/room/brim)
-   [Network Miner](https://tryhackme.com/room/networkminer)
-   [Wireshark](https://tryhackme.com/room/wireshark)


1. What was the alert signature for A Network Trojan was Detected?
```
event_type=="alert" alert.category=="A Network Trojan was detected"
```
![Pasted image 20221126220510](https://user-images.githubusercontent.com/107832241/204097605-08e4f408-9fae-440a-8668-963b7dc9105a.png)
![Pasted image 20221126220555](https://user-images.githubusercontent.com/107832241/204097617-da0cb10a-cb02-4d80-bd33-6f24c6172b04.png)

>Answer: ET MALWARE Likely Evil EXE download from MSXMLHTTP non-exe extension M2

2. What was the alert signature for Potential Corporate Privacy Violation?
```
event_type=="alert" alert.category=="Potential Corporate Privacy Violation"
```
![Pasted image 20221126220857](https://user-images.githubusercontent.com/107832241/204097623-9e322556-d14b-49a2-8dfc-4c5b7466caf1.png)

>Answer: ET POLICY PE EXE or DLL Windows file download HTTP

3. What was the IP to trigger either alert? Enter your answer in a defanged format.  

>Answer: 185[.]118[.]164[.]8

4. Provide the full URI for the malicious downloaded file. In your answer, defang the URI. 

![Pasted image 20221126221254](https://user-images.githubusercontent.com/107832241/204097640-7631149a-bfc8-4ac4-b6be-ca5bcb9184b0.png)

>Answer: awh93dhkylps5ulnq-be[.]com/czwih/fxla[.]php?l=gap1[.]cab

5. What is the name of the payload within the cab file?

![Pasted image 20221126221341](https://user-images.githubusercontent.com/107832241/204097697-fe1084c8-842e-41ca-87c0-1902294dbbca.png)
![Pasted image 20221126221358](https://user-images.githubusercontent.com/107832241/204097711-69b42bc6-0cbb-4e60-88e5-30530e7f7748.png)
![Pasted image 20221126221421](https://user-images.githubusercontent.com/107832241/204097721-1c429e7e-6912-42df-ba3f-482c5aa39f47.png)

>Answer: draw.dll

6. What is the user-agent associated with this network traffic?

![Pasted image 20221126221532](https://user-images.githubusercontent.com/107832241/204097739-9ae5cf0f-b76e-4a5b-b760-87b9e369690b.png)

>Answer: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64; Trident/8.0; .NET4.0C; .NET4.0E)

7. What other domains do you see in the network traffic that are labelled as malicious by VirusTotal? Enter the domains defanged and in alphabetical order. (format: domain[.]zzz,domain[.]zzz)

```
_path=="dns" | count() by query | sort -r
```
![Pasted image 20221126223027](https://user-images.githubusercontent.com/107832241/204097775-e07eff31-8e97-4010-89af-a96a5f94a50d.png)
![Pasted image 20221126223013](https://user-images.githubusercontent.com/107832241/204097794-02e61ab9-8ab8-47e8-ba5e-ba7e293c859f.png)
![Pasted image 20221126222954](https://user-images.githubusercontent.com/107832241/204097811-5f451345-e7c9-41f9-8fac-20bd1f3b97e3.png)

>Answer: a-zcorner[.]com,knockoutlights[.]com

8. There are IP addresses flagged as Not Suspicious Traffic. What are the IP addresses? Enter your answer in numerical order and defanged. (format: IPADDR,IPADDR)
```
event_type=="alert" alert.severity==3 alert.category=="Not Suspicious Traffic"
```
![Pasted image 20221126223652](https://user-images.githubusercontent.com/107832241/204097820-4e6233ad-b761-445a-b53b-820847f5219d.png)

>Answer: 64[.]225[.]65[.]166,142[.]93[.]211[.]176

9. For the first IP address flagged as Not Suspicious Traffic. According to VirusTotal, there are several domains associated with this one IP address that was flagged as malicious. What were the domains you spotted in the network traffic associated with this IP address? Enter your answer in a defanged format. Enter your answer in alphabetical order, in a defanged format. (format: domain[.]zzz,domain[.]zzz,etc)

![Pasted image 20221126224506](https://user-images.githubusercontent.com/107832241/204097825-d0d98040-18e1-47d3-a521-53a4f600f29f.png)
![Pasted image 20221126224531](https://user-images.githubusercontent.com/107832241/204097835-adb7e9c0-737e-44b7-97b7-49ef60f57828.png)

>Answer:safebanktest[.]top,tocsicambar[.]xyz,ulcertification[.]xyz

10. Now for the second IP marked as Not Suspicious Traffic. What was the domain you spotted in the network traffic associated with this IP address? Enter your answer in a defanged format. (format: domain[.]zzz)

![Pasted image 20221126224938](https://user-images.githubusercontent.com/107832241/204097847-ee876ad1-9252-47b7-b8dc-5312a07ed58a.png)

>Answer: 2partscow[.]top
