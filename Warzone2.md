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
![[Pasted image 20221126220510.png]]
![[Pasted image 20221126220555.png]]

>Answer: ET MALWARE Likely Evil EXE download from MSXMLHTTP non-exe extension M2

2. What was the alert signature for Potential Corporate Privacy Violation?
```
event_type=="alert" alert.category=="Potential Corporate Privacy Violation"
```
![[Pasted image 20221126220857.png]]

>Answer: ET POLICY PE EXE or DLL Windows file download HTTP

3. What was the IP to trigger either alert? Enter your answer in a defanged format.  

>Answer: 185[.]118[.]164[.]8

4. Provide the full URI for the malicious downloaded file. In your answer, defang the URI. 

![[Pasted image 20221126221254.png]]

>Answer: awh93dhkylps5ulnq-be[.]com/czwih/fxla[.]php?l=gap1[.]cab

5. What is the name of the payload within the cab file?
![[Pasted image 20221126221341.png]]
![[Pasted image 20221126221358.png]]
![[Pasted image 20221126221421.png]]

>Answer: draw.dll

6. What is the user-agent associated with this network traffic?

![[Pasted image 20221126221532.png]]

>Answer: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64; Trident/8.0; .NET4.0C; .NET4.0E)

7. What other domains do you see in the network traffic that are labelled as malicious by VirusTotal? Enter the domains defanged and in alphabetical order. (format: domain[.]zzz,domain[.]zzz)

```
_path=="dns" | count() by query | sort -r
```
![[Pasted image 20221126223027.png]]
![[Pasted image 20221126223013.png]]
![[Pasted image 20221126222954.png]]

>Answer: a-zcorner[.]com,knockoutlights[.]com

8. There are IP addresses flagged as Not Suspicious Traffic. What are the IP addresses? Enter your answer in numerical order and defanged. (format: IPADDR,IPADDR)
```
event_type=="alert" alert.severity==3 alert.category=="Not Suspicious Traffic"
```
![[Pasted image 20221126223652.png]]

>Answer: 64[.]225[.]65[.]166,142[.]93[.]211[.]176

9. For the first IP address flagged as Not Suspicious Traffic. According to VirusTotal, there are several domains associated with this one IP address that was flagged as malicious. What were the domains you spotted in the network traffic associated with this IP address? Enter your answer in a defanged format. Enter your answer in alphabetical order, in a defanged format. (format: domain[.]zzz,domain[.]zzz,etc)

![[Pasted image 20221126224506.png]]
![[Pasted image 20221126224531.png]]

>Answer:safebanktest[.]top,tocsicambar[.]xyz,ulcertification[.]xyz

10. Now for the second IP marked as Not Suspicious Traffic. What was the domain you spotted in the network traffic associated with this IP address? Enter your answer in a defanged format. (format: domain[.]zzz)

![[Pasted image 20221126224938.png]]

>Answer: 2partscow[.]top
