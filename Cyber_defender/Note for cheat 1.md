```Splunk Search - Meterpreter and Cobalt Strike (Splunk, Sysmon native)
index=__your_sysmon_index__ (ParentImage="C:\\Windows\\System32\\services.exe" Image="C:\\Windows\\System32\\cmd.exe" (CommandLine="*echo*" AND CommandLine="*\\pipe\\*"))
OR (Image="C:\\Windows\\System32\\rundll32.exe" CommandLine="*,a /p:*")
```
```Splunk Search - Empire and PoshC2 (Splunk, Sysmon native)
index=__your_sysmon_index__ (Image="C:\\Windows\\System32\\cmd.exe" OR CommandLine="*%COMSPEC%*") (CommandLine="*echo*" AND CommandLine="*\pipe\*")
```
```
Get-EventLog -List | %<Limit-EventLog -OverflowAction DoNotOverwrite -MaximumSize 64KB -LogName $_.log>
Get-EventLog -List | ForEach-Object { Limit-EventLog -LogName $_.Log -OverflowAction DoNotOverwrite -MaximumSize 64KB }
Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Security
```

##### Forensic with no event_viewer

```
get-content C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

>[!Note]- PowerShell-Script-history-allusers
>```Copy
>$Users = (Gci C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt).FullName;
>$Pasts = @($Users);
>
>foreach ($Past in $Pasts) {
>    write-host "`n----User Pwsh History Path $Past---" -ForegroundColor Magenta; 
>    get-content $Past
>}
>```

```List-prefetch
dir 'C:\Windows\Prefetch' | sort LastWriteTime -desc
```

```PECmd-prefetch
# I’d advise picking the -f flag, and picking on one of the prefetch files you see in the directory
.\PECmd .exe -f 'C:\Windows\prefetch\MIMIKATZ.EXE-599C44B5.pf' 

#get granular timestamps by adding -mp flag
.\PECmd .exe -f 'C:\Windows\prefetch\MIMIKATZ.EXE-599C44B5.pf' -mp

# If you don’t know what file you want to process, get the whole directory. Will be noisy though and I wouldn’t recommend
.\PECmd .exe -d 'C:\Windows\Prefetch' --csv . #dot at the end means write in current directory
```

```enable-prefetch-recording
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnablePrefetcher /t REG_DWORD /d 3 /f;
 
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Prefetcher" /v MaxPrefetchFiles /t REG_DWORD /d 8192 /f;
 
Enable-MMAgent –OperationAPI;
 
net start sysmain
```

```Shimcache
.\AppCompatCacheParser.exe -t --csv . --csvf shimcache.csv
import-csv .\shimcache.csv | sort lastmodified -Descending | fl path,last*
```


```SafeDllSearchMode
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\SafeDllSearchMode
```




>[!attention]- EID Security
>```
>4624: Logon  
>4663: File Creation
>4672: Special Logon  
>4673: Sensitive Privilege Use  
>4674: Sensitive Privilege Use  
>4688: Process Creation  
>4689: Process Termination
>5140: File Share  
>5156: Network Connection 
>**10003**: LAPS policy processing is now starting.
>**10004**: LAPS policy processing succeeded.
>**10005**: LAPS policy processing failed with an error code.
>
>Service Creation events  
>4697: A service was installed in the system. (security.evtx)  
>7045: A service was installed in the system. (system.evtx)  
>7034: A service terminated unexpectedly
>```
>
>7036: Windows Protection Service has entered the stopped state.
>7040: The start type of Windows Protection Service was changed from autostart to demand start/auto start to disabled 


>[!attention]- Named pipe impersonation
>```
>-   \postex_*
>-   \postex_ssh_*
>-   \status_*
>-   \msagent_*
>-   \MSSE-*
>-   \*-server
>```

>[!attention]- Sysmon
>-   11 – File Creation
>-   7 – Image Loaded
>-   1 – Process Creation
>-   3 – Network Connection
>-   10 – Process accessed
>-   8 – CreateRemoteThread detected
>-   3/22 – Network query/DNS query
>-   25 – Process tampering
>-   12 & 13 – Registry value set

```Pass-the-Hash
C:\Windows\system32\cmd.exe /c echo 0291f1e69dd > \\.\pipe\82afc1
Windows EID 4624  
Logon Type = 9  
Authentication Package = Negotiate  
Logon Process = seclogo
```



```
Note: To track events 4688 and 5156, Process Creation and Windows Filtering Connection auditing should be enabled on the system via Local Security Policy. To do this, type Local Security Policy on Windows Start Menu search and select Local Policies under Security Settings in the pop-up window that appears. Select Audit Policy and go to Audit Process Tracking, configure audit attempts by ticking both Success and Failure, and click OK. Auditing process tracking is now enabled.
Now, go to Advanced Audit Policy Configuration on the left-side menu and select System Audit Policies-Local Group Policy Object. Here, you will see an option called Object Access, which will have Audit Filtering Platform Connection in its submenu. Configure audit attempts by ticking both Success and Failure and click OK. Windows Filtering Connection auditing is now enabled.


Note: To monitor file and folder deletion via Event Viewer, Object Access auditing should be enabled via Group Policy Management Editor. Auditing should also be enabled on specific files and folders that need to be monitored. To do this, select the file/folder that need to be audited, right-click on it, and select Properties → Security → Advanced Security Settings → Auditing. Select the Add button, select the users you want to audit in Enter the object name box, and click OK. Select This folder, subfolder, and files in the Applies to field, choose the access types, and click OK. Click OK again to close the Properties dialog-box. 
```



![[Pasted image 20230509050916.png]]
**Infection chain of fileless malware**
![[Pasted image 20230509053452.png]]
**How fileless attack happens via websites**
![[Pasted image 20230509104721.png]]
**How fileless attack happens via documents**
![[Pasted image 20230510174900.png]]
**Android boot process**


```
The init.rc script located at <android source>/system/core/rootdir/init.rc
```


```js
function is_admin() {
	var k = 'HKEY_CLASSES_ROOT\\WinNT\\test'; 
	try {
		wscript_shell.RegWrite(k, 1);
		if (wscript_shell.RegRead(k) == '1') { 
			wscript_shell.RegDelete(k); 
			return true;
		} else return false;
	} catch (e) {
		return false;
	}
}
```


>[!attention]- Named pipe impersonation
>```
>```
