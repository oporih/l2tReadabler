# l2tReadabler

l2tReadabler make log2timeline output more readable.
'readable' column is added to l2t output csv.

Input l2t csv format:

```
datetime,timestamp_desc,source,source_long,message,parser,display_name
```

compared with message column:

original(message column)
```
[1149 / 0x047d] Source Name: Microsoft-Windows-TerminalServices-RemoteConnectionManager Strings: ['spsql'  'SHIELDBASE'  '172.16.6.14'] Computer Name: base-rd-04.shieldbase.lan Record Number: 17 Event Level: 4
```

readable
```
RDP established from 172.16.6.14 with SHIELDBASE\spsql
```


## Sample readable columns
### Logon event

* 4624: `!!! Logon(3) from 172.16.6.14 with spsql`
    * `!!!` means first logon observation with (sourceIP, username) pair.
* 4648: `Explicit logon to base-hunt.shieldbase.lan from 172.16.5.25 with SHIELDBASE.LAN\spsql`

### RDP event
* `RDP established from 172.16.6.14 with SHIELDBASE\spsql`

### ShellBag
* `Last Accessed(Shellbag): <Computers and Devices> <UNKNOWN: 0x00>\\172.16.6.12\c$\Windows\Temp`

### UserAssist
* `Last Executed: {1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\mspaint.exe - run count 7`

## Supportted events
### Event Log
* 4624: user Logon
* 4648: explicitly used logon credential
* 106: task created
* 201: task finished
* 1149: RDP established to subject host
* 21: RDP established from other host
* 25: RDP reconnected from other host
* 24: RDP disconnected by other host
* 1102: RDP attempted to other host
* 1027: RDP success to other host
* 1029: RDP attempt to other host with username
* 4778: RDP reconnected from other host
* 4779: RDP disconnected by other host
* 7045: service installed
* 7036: service status changed
* 4720: Account created
* 12: system shudown
* 200: schedule task executed
* 1102: Security Event deleted
* 104: Event log deleted
* 5860: WMI consumer event
* 5861: WMI consumer event
* 800: powershell scriptblock
* 4104: powershell scriptblock
* 40961: powershell console activated
* 40962: powershell console activated
* 6: winrm connection attemped to other host
* 91: winrm connection attemped from other host
* 168: winrm service activity

### MSIE 
* MSIE WebCache container recode, Creation Time
* MSIE WebCache container recode, not Creation Time


### Program Execution
* AppCompatCache
* UserAssist
* WinPrefetch
* Amcache(with sha1 vt result)
* RecentApps(Win10 only)

### Service 
* Service registry modified time


### File Access
* Shellbag


### Suspicious File Exist
* .rar(MFT)
* .rar(FileExts registry)

### Persistence
* WMI Persistence(OBJECT.DATA modified)

