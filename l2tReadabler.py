# ToDo: Task log(EventID:4698) on Security.evtx (need other objects audit)
# ToDo: renew WMI event 5860,5861
# ToDo: renew WinRm event 6, 91, 168

import sys
import os
import re
import csv
import traceback
import ipdb
import time
from vtScanMD5 import scanVT
import pandas as pd


charCode = 'utf-8'
csv.field_size_limit(1000000)


def convertEVTX(row):
    global beLoggedOn
    global logonTo
    reEvtx = "Strings: \[(.*)\]"
    strings = re.search(reEvtx, row['message']).group(1)[1:-1].split("'  '")
    if row['message'].startswith("[4624 /"):
        if strings[8] not in ["2","5"] \
          and strings[18].lower() not in ["-","localhost","127.0.0.1","::1"]:
            if strings[8] == "3":
                row['readable'] = "Network logon(type {}) success".format(strings[8])
            elif strings[8] == "10":
                row['readable'] = "RDP logon(type {}) success".format(strings[8])
            else:
                row['readable'] = "Logon(type {}) success".format(strings[8])
            row['readable'] += " from {}({})".format(strings[11],strings[18])
            row['readable'] += " with {}\{}".format(strings[6],strings[5])

            if len(beLoggedOn[(beLoggedOn.source==strings[18]) & (beLoggedOn.Acc==strings[5])]) == 0:
                row['readable'] = "!!! " + row['readable']
            beLoggedOn = beLoggedOn.append([{"datetime":row['datetime'], \
                            "source":strings[18], "Acc":strings[5]}])
        elif strings[8] == "10" and strings[18].lower() in ["localhost","127.0.0.1","::1"]:
            row['readable'] = "RDP logon(type {}) success".format(strings[8])
            row['readable'] += " from {}({})(indicate use of frp)".format(strings[11], strings[18])
            row['readable'] += " with {}\{}".format(strings[6], strings[5])

        row['message'] = "[4624]LogonType: {}".format(strings[8])
        row['message'] += " | NewLogon{" 
        row['message'] += "'SID':{} + ".format(strings[4])
        row['message'] += "'Acc':{} + ".format(strings[5])
        row['message'] += "'AccDomain':{} + ".format(strings[6])
        row['message'] += "'LogonID':{} + ".format(strings[7])
        row['message'] += "'LogonGUID':{}".format(strings[12])
        row['message'] += "}"
        row['message'] += " | NetworkInfo{" 
        row['message'] += "'WorkstationName':{} + ".format(strings[11])
        row['message'] += "'SrcIP':{} + ".format(strings[18])
        row['message'] += "'SrcPort':{}".format(strings[19])
        row['message'] += "}"
        row['message'] += " | Process{" 
        row['message'] += "'PID':{} + ".format(strings[16])
        row['message'] += "'ProcessName':{}".format(strings[17])
        row['message'] += "}"
        row['message'] += " | Subject{" 
        row['message'] += "'SID':{} + ".format(strings[0])
        row['message'] += "'Acc':{} + ".format(strings[1])
        row['message'] += "'AccDomain':{} + ".format(strings[2])
        row['message'] += "'LogonID':{}".format(strings[3])
        row['message'] += "}"
        row['message'] += " | Detail{" 
        row['message'] += "'LogonProc':{} + ".format(strings[9])
        row['message'] += "'AuthPack':{} + ".format(strings[10])
        row['message'] += "'TransSvc':{} + ".format(strings[13])
        row['message'] += "'PackName':{} + ".format(strings[14])
        row['message'] += "'KeyLen':{}".format(strings[15])
        row['message'] += "}"

    elif row['message'].startswith("[4625 /"):
        if strings[12] == "3":
            row['readable'] = "Network logon(type {}) failed".format(strings[10])
        elif strings[8] == "10":
            row['readable'] = "RDP logon(type {}) failed".format(strings[10])
        else:
            row['readable'] = "Logon(type {}) failed".format(strings[10])
        row['readable'] += " from {}({})".format(strings[13],strings[19])
        row['readable'] += " with {}\{}".format(strings[6],strings[5])

        row['message'] = "[4625]LogonType: {}".format(strings[10])
        row['message'] += " | FailedLogon{" 
        row['message'] += "'SID':{} + ".format(strings[4])
        row['message'] += "'Acc':{} + ".format(strings[5])
        row['message'] += "'AccDomain':{} + ".format(strings[6])
        row['message'] += "'Status':{} + ".format(strings[7])
        row['message'] += "'FailureReason':{} + ".format(strings[8])
        row['message'] += "'Substatus':{}".format(strings[9])
        row['message'] += "}"
        row['message'] += " | NetworkInfo{" 
        row['message'] += "'WorkstationName':{} + ".format(strings[13])
        row['message'] += "'SrcIP':{} + ".format(strings[19])
        row['message'] += "'SrcPort':{}".format(strings[20])
        row['message'] += "}"
        row['message'] += " | Process{" 
        row['message'] += "'PID':{} + ".format(strings[17])
        row['message'] += "'ProcessName':{}".format(strings[18])
        row['message'] += "}"
        row['message'] += " | Subject{" 
        row['message'] += "'SID':{} + ".format(strings[0])
        row['message'] += "'Acc':{} + ".format(strings[1])
        row['message'] += "'AccDomain':{} + ".format(strings[2])
        row['message'] += "'LogonID':{}".format(strings[3])
        row['message'] += "}"
        row['message'] += " | Detail{" 
        row['message'] += "'LogonProc':{} + ".format(strings[11])
        row['message'] += "'AuthPack':{} + ".format(strings[12])
        row['message'] += "'TransSvc':{} + ".format(strings[13])
        row['message'] += "'PackName':{} + ".format(strings[14])
        row['message'] += "'KeyLen':{}".format(strings[15])
        row['message'] += "}"
        
    elif row['message'].startswith("[4648 /"):
        row['readable'] = "Explicit logon to {} from {} with {}\{}".format(strings[8] ,strings[12],strings[6],strings[5])
        try:
            row['message'] = "[4648]Explicit logon{"
            row['message'] += "'Acc':{} + ".format(strings[5])
            row['message'] += "'AccDomain':{} + ".format(strings[6])
            row['message'] += "'AccGUID':{}".format(strings[7])
            row['message'] += "}"
            row['message'] += " | Target Server{" 
            row['message'] += "'Name':{} + ".format(strings[8])
            row['message'] += "'Info':{}".format(strings[9])
            row['message'] += "}"
            row['message'] += " | Proc Info{" 
            row['message'] += "'PID':{} + ".format(strings[10])
            row['message'] += "'ProcName':{}".format(strings[11])
            row['message'] += "}"
            row['message'] += " | Network Info{" 
            row['message'] += "'NetAddr':{} + ".format(strings[12])
            row['message'] += "'Port':{}".format(strings[13])
            row['message'] += "}"
            row['message'] += " | Subject{" 
            row['message'] += "'SID':{} + ".format(strings[0])
            row['message'] += "'Acc':{} + ".format(strings[1])
            row['message'] += "'AccDomain':{} + ".format(strings[2])
            row['message'] += "'LogonID':{} + ".format(strings[3])
            row['message'] += "'LogonGUID':{}".format(strings[4])
            row['message'] += "}"

        except:
            row['message'] = "[4648]Explicit logon{"
            row['message'] += "'Acc':{} + ".format(strings[5])
            row['message'] += "'AccDomain':{} + ".format(strings[6])
            row['message'] += "'AccGUID':{}".format(strings[7])
            row['message'] += "}"
            row['message'] += " | Target Server{" 
            row['message'] += "'Name':{} + ".format(strings[8])
            row['message'] += "'Info':{}".format(strings[9])
            row['message'] += "}"
            row['message'] += " | Proc Info{" 
            row['message'] += "'PID':{} + ".format(strings[10])
            row['message'] += "'ProcName':-"
            row['message'] += "}"
            row['message'] += " | Network Info{" 
            row['message'] += "'NetAddr':{} + ".format(strings[11])
            row['message'] += "'Port':{}".format(strings[12])
            row['message'] += "}"
            row['message'] += " | Subject{" 
            row['message'] += "'SID':{} + ".format(strings[0])
            row['message'] += "'Acc':{} + ".format(strings[1])
            row['message'] += "'AccDomain':{} + ".format(strings[2])
            row['message'] += "'LogonID':{} + ".format(strings[3])
            row['message'] += "'LogonGUID':{}".format(strings[4])
            row['message'] += "}"
        # 4648 sometimes records RDP logon to subject host
        if strings[12].lower() not in ["-","localhost","127.0.0.1","::1"] \
            and strings[11].lower() == "winlogon.exe" \
            and strings[8].lower() == "localhost":
            row['readable'] = "(RDP) " + row['readable']
    elif row['message'].startswith("[4724 /"):
        row['readable'] = "Account {}\{}".format(strings[1] ,strings[0])
        row['readable'] += " password changed by {}\{}".format(strings[5],strings[4])

        row['message'] = "[4724]Account password changed{"
        row['message'] += "'Acc':{} + ".format(strings[0])
        row['message'] += "'AccDomain':{} + ".format(strings[1])
        row['message'] += "'AccSID':{} + ".format(strings[2])
        row['message'] += "'SrcAcc':{} + ".format(strings[4])
        row['message'] += "'SrcAccDomain':{} + ".format(strings[5])
        row['message'] += "'SrcAccSID':{} + ".format(strings[3])
        row['message'] += "'LogonSessionId':{} + ".format(strings[6])
        row['message'] += "}"
    elif row['message'].startswith("[4726 /"):
        row['readable'] = "Account {}\{}".format(strings[1],strings[0])
        row['readable'] += " deleted by {}\{}".format(strings[5],strings[4])

        row['message'] = "[4726]Account deleted{"
        row['message'] += "'Acc':{} + ".format(strings[0])
        row['message'] += "'AccDomain':{} + ".format(strings[1])
        row['message'] += "'AccSID':{} + ".format(strings[2])
        row['message'] += "'SrcAcc':{} + ".format(strings[4])
        row['message'] += "'SrcAccDomain':{} + ".format(strings[5])
        row['message'] += "'SrcAccSID':{} + ".format(strings[3])
        row['message'] += "'LogonSessionId':{} + ".format(strings[6])
        row['message'] += "'PrivList':{} + ".format(strings[7])
        row['message'] += "}"
    elif row['message'].startswith("[4732 /"):
        row['readable'] = "Account {}({})".format(strings[0], strings[1])
        row['readable'] += " is added to group {}\{}".format(strings[3], strings[2])
        row['readable'] += " by {}\{}".format(strings[7], strings[6])

        row['message'] = "[4732]Account added to group{"
        row['message'] += "'Acc':{} + ".format(strings[0])
        row['message'] += "'AccSID':{} + ".format(strings[1])
        row['message'] += "'TargetGroup':{} + ".format(strings[2])
        row['message'] += "'TargetDomain':{} + ".format(strings[3])
        row['message'] += "'TargetSID':{} + ".format(strings[4])
        row['message'] += "'SubjectSID':{} + ".format(strings[5])
        row['message'] += "'SubjectAcc':{} + ".format(strings[6])
        row['message'] += "'SubjectDomain':{} + ".format(strings[7])
        row['message'] += "'SubjectLogonSessionId':{} + ".format(strings[8])
        row['message'] += "'PrivList':{} + ".format(strings[9])
        row['message'] += "}"
    elif row['message'].startswith("[106 /") and "Microsoft-Windows-TaskScheduler" in row['message']:
        row['readable'] = "Task created by {}; taskname: {}".format(strings[2], strings[0])
    elif row['message'].startswith("[201 /"):
        if len(strings) >= 4:
            row['readable'] = "Task finished; taskname: {}({}) (resultCode:{})".format(strings[0], strings[2], strings[3])
        else:
            row['readable'] = "Task finished; taskname: {}(-) (resultCode:{})".format(strings[0], strings[2])
    elif row['message'].startswith("[1149 /"):
        row['readable'] = "RDP established from {} with {}\\{}".format(strings[2], strings[1], strings[0])
    elif row['message'].startswith("[21 /") and "Microsoft-Windows-TerminalServices-LocalSessionManager" in row['message']:
        if strings[2].lower() != "local":
            row['readable'] = "RDP established from {} with {} (ID:{})".format(strings[2], strings[0], strings[1])
    elif row['message'].startswith("[25 /") and "Microsoft-Windows-TerminalServices-LocalSessionManager" in row['message']:
        if strings[2].lower() != "local":
            row['readable'] = "RDP reconnected from {} with {} (ID:{})".format(strings[2], strings[0], strings[1])
    elif row['message'].startswith("[24 /") and "Microsoft-Windows-TerminalServices-LocalSessionManager" in row['message']:
        if strings[2].lower() != "local":
            row['readable'] = "RDP disconnected from {} with {} (ID:{})".format(strings[2], strings[0], strings[1])
    elif row['message'].startswith("[1102 /") and "Microsoft-Windows-TerminalServices-ClientActiveXCore" in row['message']:
        row['readable'] = "RDP attempt to {}".format(strings[1])
    elif row['message'].startswith("[1027 /") and "Microsoft-Windows-TerminalServices-ClientActiveXCore" in row['message']:
        row['readable'] = "RDP success to {}".format(strings[0])
    elif row['message'].startswith("[1024 /") and "Microsoft-Windows-TerminalServices-ClientActiveXCore" in row['message']:
        row['readable'] = "RDP attempt from {}".format(strings[1])
    elif row['message'].startswith("[1029 /") and "Microsoft-Windows-TerminalServices-ClientActiveXCore" in row['message']:
        if strings[0] == "UmTGMgTFbA35+PSgMOoZ2ToPpAK+awC010ZOYWQQIfc=-" or strings[0] == "WAlZ81aqzLQmoWEfQivmPQwJxIm/XQcDjplQdjznr5E=-":
            row['readable'] = "RDP attempt with username Administrator".format(strings[0])
        else:
            row['readable'] = "RDP attempt with username {}".format(strings[0])
    elif row['message'].startswith("[4778 /"):
        if strings[5].lower() != "local":
            row['readable'] = "RDP reconnected from {} with {}\\{}".format(strings[5], strings[1], strings[0])
    elif row['message'].startswith("[4779 /"):
        if strings[5].lower() != "local":
            row['readable'] = "RDP disconnected from {} with {}\\{}".format(strings[5], strings[1], strings[0])
    elif row['message'].startswith("[7045 /"):
        row['readable'] = "Service installed: {}".format(strings[1])
    elif row['message'].startswith("[7036 /"):
        row['readable'] = "Service state change: {} {}".format(strings[1], strings[0])
    elif row['message'].startswith("[4720 /"):
        row['readable'] = "Account {}\\{} created by {}\\{}".format(strings[1], strings[0], strings[5], strings[4])
    elif row['message'].startswith("[12 /") and "Microsoft-Windows-Kernel-General" in row['message']:
        row['readable'] = "System Shutdown"
    elif row['message'].startswith("[200 /") and 'Microsoft-Windows-TaskScheduler' in row['display_name']:
        row['readable'] = "Executed: {}({})".format(strings[1], strings[0])
    elif row['message'].startswith("[1102 /") and 'Microsoft-Windows-Eventlog' in row['message']:
        row['readable'] = "Security event log deleted by {}\\{}".format(strings[2],strings[1])
    elif row['message'].startswith("[104 /") and 'Microsoft-Windows-Eventlog' in row['message']:
        row['readable'] = "{} event log deleted by {}\\{}".format(strings[2], strings[1], strings[0])
    elif row['message'].startswith("[5860 /") and 'Microsoft-Windows-WMI-Activity' in row['message']:
        row['readable'] = "WMI consumer event detected"
    elif row['message'].startswith("[5861 /") and 'Microsoft-Windows-WMI-Activity' in row['message']:
        row['readable'] = "WMI consumer event detected"
    elif row['message'].startswith("[400 /") and 'powershell' in row['message'].lower():
        row['readable'] = "Powershell executed: {}".format(strings[2].split("HostApplication=")[1].split("EngineVersion=")[0])
    elif row['message'].startswith("[403 /") and 'powershell' in row['message'].lower():
        row['readable'] = "Powershell stopped: {}".format(strings[2].split("HostApplication=")[1].split("EngineVersion=")[0])
    elif row['message'].startswith("[800 /") and 'powershell' in row['message'].lower():
        row['readable'] = "Powershell Scriptblock Logged"
    elif row['message'].startswith("[4104 /") and 'Microsoft-Windows-PowerShell' in row['message']:
        row['readable'] = "Powershell Scriptblock Logged"
    elif row['message'].startswith("[40961 /") and 'Microsoft-Windows-PowerShell' in row['message']:
        row['readable'] = "Powershell Console Activated"
    elif row['message'].startswith("[40962 /") and 'Microsoft-Windows-PowerShell' in row['message']:
        row['readable'] = "Powershell Console Activated"
    elif row['message'].startswith("[6 /") and 'winrm' in row['message'].lower():
        row['readable'] = "WinRM connection attempted to other hosts"
    elif row['message'].startswith("[91 /") and 'winrm' in row['message'].lower():
        row['readable'] = "WinRM connection attempted from other hosts"
    elif row['message'].startswith("[168 /") and 'winrm' in row['message'].lower():
        row['readable'] = "WinRM service activity"
    elif row['message'].startswith("[4616 /") and 'security' in row['message'].lower():
        row['readable'] = "System time changed by {}: from {} {} to {} {}".format(strings[1], strings[4], strings[5], strings[6], strings[7])
    else:
        pass
    return row

fout = open("edit-" + os.path.basename(sys.argv[1]),"w")

beLoggedOn = pd.DataFrame()
beLoggedOn = beLoggedOn.append([{"datetime":"-", "source":"-", "Acc":"-"}])
logonTo = pd.DataFrame()
logonTo = logonTo.append([{"datetime":"-", "dest":"-", "Acc":"-"}])

fobj =  open(sys.argv[1],"r",encoding="utf_8", errors="ignore", newline='' )
fcsv = csv.DictReader(fobj, delimiter=",")
fieldnames = fcsv.fieldnames
fieldnames.append("readable")
writer = csv.DictWriter(fout, fieldnames)
writer.writeheader()
for row in fcsv:
    #print(row)
    row['readable'] = "-"
    try:
        if row['source_long'].lower()=="winevtx":
            row = convertEVTX(row)
        elif row['source'].lower()=='reg':
            if re.search(r"^\[HKEY_LOCAL_MACHINE\\System\\ControlSet00.\\Services\\[^\\\]]+\]", row['message']):
                reService = r"\\Services\\([^\]]+).+ImagePath: (.+) ObjectName"
                res = re.search(reService, row['message'])
                row['readable'] = "Service Reg/Modified: {}({})".format(res.group(1), res.group(2))
            elif re.search(r"^\[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Search\\RecentApps\\", row['message']):
                res = re.search(r".+AppPath: \[REG_SZ\] (.+) LastAccessedTime: .+ LaunchCount: \[REG_DWORD_LE\] ([0-9]+)", row['message'])
                row['readable'] = "Last Executed: {} - run count {}".format(res.group(1), res.group(2))
            elif re.search(r"^\[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\\.rar[\\\]]", row['message']):
                row['readable'] = "Exfiltlation: RAR file first opened on this user"
            elif row['source_long'].lower() == 'amcache':
                res = re.search(r"^filename: (.+) & sha1: (.+) & .+$", row['message'])
                vtRes = scanVT([res.group(2)])
                row['readable'] = "First Executed: {} - vtScore: {}".format(res.group(1), int(vtRes.iloc[0]["POSITIVES"]))
            elif row['source_long'].lower()=='registry key: userassist':
                res = re.search(r".+Value name: (.+) Count: ([0-9]+) ", row['message'])
                row['readable'] = "Last Executed: {} - run count {}".format(res.group(1),res.group(2))
            elif row['parser'].lower() == 'winreg/bagmru':
                res = re.search(r"^.+ Index: 1 \[MRU Value [0-9]+\]: Shell item path: (.+)$", row['message'])
                res = res.group(1).split("Index")[0]
                row['readable'] = "Last Accessed(Shellbag): {}".format(res)
            else:
                pass
        elif row['timestamp_desc'].lower() == 'execution time':
                res = re.search(r"^filename: (.+) & sha1: (.+) & .+$", row['message'])
                #vtRes = scanVT([res.group(2)])
                #row['readable'] = "First Executed: {} - vtScore: {}".format(res.group(1), int(vtRes.iloc[0]["POSITIVES"]))
        elif re.search(r"^[macb\.]{4}$", row['timestamp_desc']):
            if re.search(r"(.+\.rar) \(\$FILE_NAME\)$", row['message']):
                res = re.search(r"(.+\.rar) \(\$FILE_NAME\)$", row['message'])
                row['readable'] = "Exfiltrate: RAR file exists {}".format(res.group(1))
            elif re.search(r"^m[acb\.]{3}$", row['timestamp_desc']) \
                and "Windows/System32/wbem/Repository/OBJECTS.DATA ($FILE_NAME)" in row['message']:
                row['readable'] = "Persistence: WMI persistence might be created"
        elif row['source_long'].lower()=="msie webcache container record":
            if(row['timestamp_desc'].lower()=='creation time'):
                reWebCacheCrtime = "URL: ([^ ]+) Access count"
                url = re.search(reWebCacheCrtime, unicode(row['message'], charCode)).group(1)
                url = url.replace('http','hxxp')
                url = re.sub(r'\.([^\.]+/)',r'[.]\1',url)
                row['readable'] = "IE Access: {}".format(url)
            else:
                reWebCache = "@([^ ]+) Access count"
                url = re.search(reWebCache, unicode(row['message'], charCode)).group(1)
                url = url.replace('http','hxxp')
                url = re.sub(r'\.([^\.]+/)',r'[.]\1',url)
                row['readable'] = "IE Access: {}".format(url)
        elif row['source_long'].lower()=='appcompatcache registry entry':
            reAppCompat = "Path: (.+)"
            row['readable'] = "Last Executed: {}".format(re.search(reAppCompat, row['message']).group(1))
        elif row['source_long'].lower() == 'winprefetch':
            res = re.search(r"^.+ was executed - (run count [0-9]+) path: (.+) hash:.+$", row['message'])
            row['readable'] = "Executed: {} - {}".format(res.group(2), res.group(1))
        else:
            pass
        row.pop(None)
        writer.writerow(row)
    except:
        #ipdb.set_trace()
        writer.writerow(row)

fout.close()
fobj.close()

