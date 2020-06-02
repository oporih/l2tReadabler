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
        row['message'] = "[4624]LogonType:" + strings[8] \
         + " | NewLogon{'SID':" + strings[4] + " + 'Acc':" + strings[5] \
         + " + 'AccDomain':" + strings[6] + " + 'LogonID':" + strings[7] \
         + " + 'LogonGUID':" \
         + strings[12] + "} | NetworkInfo{'WorkstationName': " + strings[11] \
         + " + 'SIP':" + strings[18] + " + 'SPort':" + strings[19] \
         + "} | Process: {'PID':" \
         + strings[16] + " + 'ProcName': " + strings[17] + "} | Subject{'SID':" \
         + strings[0] + " + 'Acc':" + strings[1] + " + 'AccDomain':" \
         + strings[2] \
         + " + 'LogonID':" + strings[3] + "} | Detail{'LogonProc': " \
         + strings[9] + " + 'AuthPack': " + strings[10] \
         + " + 'TransSvc': " + strings[13] + " + 'PackName': " \
         + strings[14] + " + 'KeyLen': " + strings[15] + "}"
        if strings[8] not in ["2","5"] \
            and strings[18].lower() not in ["-","localhost","127.0.0.1","::1"]:
            row['readable'] = "Logon({}) from {}({}) with {}".format(strings[8],strings[11],strings[18],strings[5])
            if len(beLoggedOn[(beLoggedOn.source==strings[18]) & (beLoggedOn.Acc==strings[5])]) == 0:
                row['readable'] = "!!! " + row['readable']
            beLoggedOn = beLoggedOn.append([{"datetime":row['datetime'], \
                            "source":strings[18], "Acc":strings[5]}])
    elif row['message'].startswith("[4648 /"):
        row['message'] =  "[4648]Acc Cred Used{'Acc':" + strings[5] + " + 'AccDomain':" \
         + strings[6] \
         + " + 'AccGUID':" + strings[7] + "} | Target Server{'Name':" \
         + strings[8] + " + 'Info':" + strings[9] \
         + "} | ProcInfo{'PID': " + strings[10] \
         + " + 'ProcName':" + strings[11] + "} | Network Info{'NetAddr':" \
         + strings[12] + " + 'Port:" + strings[13] + "} | Subject{'SID':" \
         + strings[0] + " + 'Acc':" + strings[1] + " + 'AccDomain':" \
         + strings[2] + " + 'LogonID':" + strings[3] + " + 'LogonGUID':" \
         + strings[4] + "}"
        row['readable'] = "Explicit logon to {} from {} with {}\{}".format(strings[8] ,strings[12],strings[6],strings[5])
        # 4648 sometimes records RDP logon to subject host
        if strings[12].lower() not in ["-","localhost","127.0.0.1","::1"] \
            and strings[11].lower() == "winlogon.exe" \
            and strings[8].lower() == "localhost":
            row['readable'] = "(RDP) " + row['readable']
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
        row['readable'] = "Service state change: {} {}".format(strings[1], strings[2])
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

