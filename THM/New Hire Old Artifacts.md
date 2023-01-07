**Scenario**: You are a SOC Analyst for an MSSP (managed Security Service Provider) company called TryNotHackMe.

A newly acquired customer (Widget LLC) was recently onboarded with the managed Splunk service. The sensor is live, and all the endpoint events are now visible on TryNotHackMe's end. Widget LLC has some concerns with the endpoints in the Finance Dept, especially an endpoint for a recently hired Financial Analyst. The concern is that there was a period (December 2021) when the endpoint security product was turned off, but an official investigation was never conducted. 

Your manager has tasked you to sift through the events of Widget LLC's Splunk instance to see if there is anything that the customer needs to be alerted on. 

Happy Hunting!

**Other Splunk Rooms**:

-   [Splunk 101](https://tryhackme.com/room/splunk101)  
-   [Splunk 2](https://tryhackme.com/room/splunk2gcd5)
-   [Splunk 3](https://tryhackme.com/room/splunk3zs)
-   [Conti](https://tryhackme.com/room/contiransomwarehgh)
-   [Incident Handling with Splunk](https://tryhackme.com/room/splunk201)  
---

1. A Web Browser Password Viewer executed on the infected machine. What is the name of the binary? Enter the full path.

```Copy
| eventcount summarize=false index=* index=_* | dedup index | fields index
```

![Pasted image 20230107122021](https://user-images.githubusercontent.com/107832241/211134812-1f883971-6c20-426d-8cd6-dea46fa2cf92.png)

```Copy
index=main "Web Browser Password Viewer"
```

![Pasted image 20230107122341](https://user-images.githubusercontent.com/107832241/211134814-7a856d5e-935d-4cc3-a5b4-6491078e850d.png)

>Answer: C:\\Users\\FINANC~1\\AppData\\Local\\Temp\\11111.exe

2. What is listed as the company name?  

![Pasted image 20230107122630](https://user-images.githubusercontent.com/107832241/211134817-69d475e8-efc2-4c4b-8c71-c02eede21c60.png)

>Answer: NirSoft

3. Another suspicious binary running from the same folder was executed on the workstation. What was the name of the binary? What is listed as its original filename? (**format: file.xyz,file.xyz**)  

```Copy
index=main "Image: C:\\Users\\Finance01\\AppData\\Local\\Temp"| top limit=20 Image
```

![Pasted image 20230107124847](https://user-images.githubusercontent.com/107832241/211134821-4aa27892-0cf5-4fea-a4ae-8e08b96bb9ed.png)

['IonicLarge.exe' (hybrid-analysis.com)](https://www.hybrid-analysis.com/sample/a798591090c33182526993e634f67fb09e69d243b82a042d26d63c0b9bfba47a/61c5762fb65f0b3a1855be89)

![Pasted image 20230107124914](https://user-images.githubusercontent.com/107832241/211134824-547b71c6-d25d-42dd-975f-124cc1dfd22e.png)

>Answer: IonicLarge.exe, PalitExplorer.exe

4. The binary from the previous question made two outbound connections to a malicious IP address. What was the IP address? Enter the answer in a defang format.  

![Pasted image 20230107125140](https://user-images.githubusercontent.com/107832241/211134828-d4b70ce0-3370-41b5-ab91-5831239d5e89.png)


>Answer: 2[.]56[.]59[.]42

5. The same binary made some change to a registry key. What was the key path?  

```Copy
index=main "Image: C:\\Users\\Finance01\\AppData\\Local\\Temp\\IonicLarge.exe" "EventType: SetValue" 
| top limit=20 TargetObject
```

![Pasted image 20230107125525](https://user-images.githubusercontent.com/107832241/211134833-c7d8d8a5-6a78-4e89-b8ba-170496dab897.png)

>Answer: HKLM\SOFTWARE\Policies\Microsoft\Windows Defender

6. Some processes were killed and the associated binaries were deleted. What were the names of the two binaries? (**format: file.xyz,file.xyz**)  

```Copy
index=main "taskkill \/im"| top limit=20 ParentCommandLine
```

![Pasted image 20230107130758](https://user-images.githubusercontent.com/107832241/211134836-0fdca467-285a-496c-ac89-833f7a3bcb1c.png)

>Answer: phcIAmLJMAIMSa9j9MpgJo1m.exe, WvmIOrcfsuILdX6SNwIRmGOJ.exe

7. The attacker ran several commands within a PowerShell session to change the behaviour of Windows Defender. What was the last command executed in the series of similar commands?  

```Copy
index=main powershell Command | sort -_time
```

![Pasted image 20230107131512](https://user-images.githubusercontent.com/107832241/211134844-f89e53ef-dd97-4810-aeef-0933e1e1d1f2.png)

>Answer: powershell  WMIC /NAMESPACE:\\\\root\\Microsoft\\Windows\\Defender PATH MSFT_MpPreference call Add ThreatIDDefaultAction_Ids=2147737394 ThreatIDDefaultAction_Actions=6 Force=True

8. Based on the previous answer, what were the four IDs set by the attacker? Enter the answer in order of execution. (format: 1st,2nd,3rd,4th)  

>Answer: 2147737394, 2147737007, 2147737010, 2147735503

9. Another malicious binary was executed on the infected workstation from another AppData location. What was the full path to the binary?  

```Copy
index=main "Image: C:\\*\\AppData\\"| top limit=100 Image
```

![Pasted image 20230107132957](https://user-images.githubusercontent.com/107832241/211134855-d19088f9-aa3c-4abb-93c8-ef1bda181c77.png)

>Answer: C:\\Users\\Finance01\\AppData\\Roaming\\EasyCalc\\EasyCalc.exe

10. What were the DLLs that were loaded from the binary from the previous question? Enter the answers in alphabetical order. (format: file1.dll,file2.dll,file3.dll)  

```Copy
index=main "C:\\Users\\Finance01\\AppData\\Roaming\\EasyCalc\\EasyCalc.exe" "ImageLoaded: C:\\Users\\Finance01\\AppData\\Roaming\\EasyCalc\\*.dll"
```

![Pasted image 20230107132847](https://user-images.githubusercontent.com/107832241/211134859-da617222-614a-4b33-a667-1a4ed199d67a.png)

>Answer: ffmpeg.dll, nw.dll, nw_elf.dll