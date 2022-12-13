One of the client’s IDS indicated a potentially suspicious process execution indicating one of the hosts from the HR department was compromised. Some tools related to network information gathering / scheduled tasks were executed which confirmed the suspicion. Due to limited resources, we could only pull the process execution logs with Event ID: 4688 and ingested them into Splunk with the index **win_eventlogs** for further investigation.  

About the Network Information

The network is divided into three logical segments. It will help in the investigation.  

**IT Department**

-   James
-   Moin
-   Katrina

**HR department**

-   Haroon
-   Chris
-   Diana

**Marketing department**

-   Bell
-   Amelia
-   Deepak

1. How many logs are ingested from the month of March?

```
index="win_eventlogs"
	-> Time range: during March 2021
```

>Answer: 13959

2. Imposter Alert: There seems to be an imposter account observed in the logs, what is the name of that user?

```
index="win_eventlogs"| rare limit=20 UserName
	-> Visualization
```

>Answer: Amel1a

3. Which user from the HR department was observed to be running scheduled tasks?

```
index="win_eventlogs" schtasks.exe
	-> Username
```

>Answer: Chris.fort

4. Which user from the HR department executed a system process (LOLBIN) to download a payload from a file-sharing host.

```
index="win_eventlogs" (UserName=haroon OR Chris.fort OR Daina) 
| table UserName ProcessName CommandLine
| dedup ProcessName
```
***Note: Pay attention to case sensitive (ex. UserName ≠ Username)***

![Pasted image 20221203175933](https://user-images.githubusercontent.com/107832241/205443162-38f8b227-49e7-487b-8a60-e3b16859bf46.png)

>Answer: haroon

5. To bypass the security controls, which system process (lolbin) was used to download a payload from the internet?

```
index="win_eventlogs" certutil.exe
| table _time UserName ProcessName CommandLine
| dedup ProcessName
```

![Pasted image 20221203202015](https://user-images.githubusercontent.com/107832241/205443177-283d2db3-2e43-4222-a98f-09b365ff2310.png)

>Answer: certutil.exe

6. What was the date that this binary was executed by the infected host? format (YYYY-MM-DD)

>Answer: 2022-03-04

7. Which third-party site was accessed to download the malicious payload?

>Answer: controlc.com

8. What is the name of the file that was saved on the host machine from the C2 server during the post-exploitation phase?

>Answer: benign.exe

9. The suspicious file downloaded from the C2 server contained malicious content with the pattern THM{..........}; what is that pattern?

![Pasted image 20221203202319](https://user-images.githubusercontent.com/107832241/205443183-605e2907-4d79-454b-baa0-37ff134136ea.png)

>Answer: THM{KJ&\*H^B0}

10. What is the URL that the infected host connected to?

>Answer: hxxps[://]controlc[.]com/548ab556
