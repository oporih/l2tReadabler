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
from vtScanHash import scanVT
import pandas as pd


charCode = 'utf-8'
csv.field_size_limit(1000000)
beLoggedOn = pd.DataFrame()
beLoggedOn = beLoggedOn.append([{"datetime":"-", "source":"-", "Acc":"-"}])
logonTo = pd.DataFrame()
logonTo = logonTo.append([{"datetime":"-", "dest":"-", "Acc":"-"}])

def decodeIPfromHex(encodedIP):
    decodedIP = str(int(encodedIP[8:10],16))
    decodedIP += "." + str(int(encodedIP[10:12],16))
    decodedIP += "." + str(int(encodedIP[12:14],16))
    decodedIP += "." + str(int(encodedIP[14:16],16))
    return decodedIP

def readableEVTX(row):
    global beLoggedOn
    global logonTo
    reEvtx = "Strings: \[(.*)\]"
    strings = re.search(reEvtx, row['message']).group(1)[1:-1].split("'  '")
    if row['message'].startswith("[4624 /") and "Security-Auditing" in row['message']:
        if strings[8] not in ["2","5"] \
          and strings[18].lower() not in ["-","localhost","127.0.0.1","::1"]:
            row['readable'] = "eventlog 4624 hit"
            if strings[8] == "3":
                row['tag'] = "Network Logon"
                row['readable'] = "Network logon(type {}) success".format(strings[8])
            elif strings[8] == "10":
                row['tag'] = "RDP Logon"
                row['readable'] = "RDP logon(type {}) success".format(strings[8])
            else:
                row['tag'] = "Logon"
                row['readable'] = "Logon(type {}) success".format(strings[8])
            row['readable'] += " from {}({})".format(strings[11],strings[18])
            row['readable'] += " with {}\{}".format(strings[6],strings[5])

            if len(beLoggedOn[(beLoggedOn.source==strings[18]) & (beLoggedOn.Acc==strings[5])]) == 0:
                row['readable'] = "!!! " + row['readable']
            beLoggedOn = beLoggedOn.append([{"datetime":row['datetime'], \
                            "source":strings[18], "Acc":strings[5]}])
        elif strings[8] == "10" and strings[18].lower() in ["localhost","127.0.0.1","::1"]:
            row['readable'] = "eventlog 4624 hit"
            row['tag'] = "RDP Logon"
            row['readable'] = "RDP logon(type {}) success".format(strings[8])
            row['readable'] += " from {}({})(indicate use of frp)".format(strings[11], strings[18])
            row['readable'] += " with {}\{}".format(strings[6], strings[5])
        else:
            pass

        #row['message'] = "[4623]LogonType: {}".format(strings[8])
        #row['message'] += " | NewLogon{" 
        #row['message'] += "'SID':{} + ".format(strings[3])
        #row['message'] += "'Acc':{} + ".format(strings[4])
        #row['message'] += "'AccDomain':{} + ".format(strings[5])
        #row['message'] += "'LogonID':{} + ".format(strings[6])
        #row['message'] += "'LogonGUID':{}".format(strings[11])
        #row['message'] += "}"
        #row['message'] += " | NetworkInfo{" 
        #row['message'] += "'WorkstationName':{} + ".format(strings[10])
        #row['message'] += "'SrcIP':{} + ".format(strings[17])
        #row['message'] += "'SrcPort':{}".format(strings[18])
        #row['message'] += "}"
        #row['message'] += " | Process{" 
        #row['message'] += "'PID':{} + ".format(strings[15])
        #row['message'] += "'ProcessName':{}".format(strings[16])
        #row['message'] += "}"
        #row['message'] += " | Subject{" 
        #row['message'] += "'SID':{} + ".format(strings[-1])
        #row['message'] += "'Acc':{} + ".format(strings[0])
        #row['message'] += "'AccDomain':{} + ".format(strings[1])
        #row['message'] += "'LogonID':{}".format(strings[2])
        #row['message'] += "}"
        #row['message'] += " | Detail{" 
        #row['message'] += "'LogonProc':{} + ".format(strings[8])
        #row['message'] += "'AuthPack':{} + ".format(strings[9])
        #row['message'] += "'TransSvc':{} + ".format(strings[12])
        #row['message'] += "'PackName':{} + ".format(strings[13])
        #row['message'] += "'KeyLen':{}".format(strings[14])
        #row['message'] += "}"

    elif row['message'].startswith("[4625 /") and "Security-Auditing" in row['message']:
        if strings[10] == "3":
            row['readable'] = "eventlog 4625 hit"
            row['tag'] = "Network Logon Failed"
            row['readable'] = "Network logon(type {}) failed".format(strings[10])
            row['readable'] += " from {}".format(strings[18])
            row['readable'] += " with {}\{}".format(strings[6],strings[5])
        elif strings[7] == "10":
            row['readable'] = "eventlog 4625 hit"
            row['tag'] = "RDP Failed"
            row['readable'] = "RDP logon(type {}) failed".format(strings[7])
            row['readable'] += " from {}".format(strings[18])
            row['readable'] += " with {}\{}".format(strings[6],strings[5])
        else:
            pass

        #row['message'] = "[4624]LogonType: {}".format(strings[10])
        #row['message'] += " | FailedLogon{" 
        #row['message'] += "'SID':{} + ".format(strings[3])
        #row['message'] += "'Acc':{} + ".format(strings[4])
        #row['message'] += "'AccDomain':{} + ".format(strings[5])
        #row['message'] += "'Status':{} + ".format(strings[6])
        #row['message'] += "'FailureReason':{} + ".format(strings[7])
        #row['message'] += "'Substatus':{}".format(strings[8])
        #row['message'] += "}"
        #row['message'] += " | NetworkInfo{" 
        #row['message'] += "'WorkstationName':{} + ".format(strings[12])
        #row['message'] += "'SrcIP':{} + ".format(strings[18])
        #row['message'] += "'SrcPort':{}".format(strings[19])
        #row['message'] += "}"
        #row['message'] += " | Process{" 
        #row['message'] += "'PID':{} + ".format(strings[16])
        #row['message'] += "'ProcessName':{}".format(strings[17])
        #row['message'] += "}"
        #row['message'] += " | Subject{" 
        #row['message'] += "'SID':{} + ".format(strings[-1])
        #row['message'] += "'Acc':{} + ".format(strings[0])
        #row['message'] += "'AccDomain':{} + ".format(strings[1])
        #row['message'] += "'LogonID':{}".format(strings[2])
        #row['message'] += "}"
        #row['message'] += " | Detail{" 
        #row['message'] += "'LogonProc':{} + ".format(strings[10])
        #row['message'] += "'AuthPack':{} + ".format(strings[11])
        #row['message'] += "'TransSvc':{} + ".format(strings[12])
        #row['message'] += "'PackName':{} + ".format(strings[13])
        #row['message'] += "'KeyLen':{}".format(strings[14])
        #row['message'] += "}"
        
    elif row['message'].startswith("[4648 /") and "Security-Auditing" in row['message']:
        if len(strings) == 14:
            row['readable'] = "eventlog 4648 hit"
            row['tag'] = "Lateral Move"
            row['readable'] = "Explicit logon to {}({}) with {}\{}".format(strings[8] ,strings[12],strings[6],strings[5])
            # 4648 sometimes records RDP logon to subject host
            if strings[12].lower() not in ["-","localhost","127.0.0.1","::1"] \
                and strings[11].lower() == "winlogon.exe" \
                and strings[8].lower() == "localhost":
                row['readable'] = "(RDP) " + row['readable']
                row['tag'] = "RDP Success"
        elif len(strings) == 13:
            row['readable'] = "eventlog 4648 hit"
            row['tag'] = "Lateral Move"
            # the case of TargetDomainName field is null
            if re.search(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", strings[6]):
                row['readable'] = "Explicit logon to {}({}) with {-}\{}".format(strings[7] ,strings[11],strings[5])
                # 4648 sometimes records RDP logon to subject host
                if strings[11].lower() not in ["-","localhost","127.0.0.1","::1"] \
                    and strings[10].lower() == "winlogon.exe" \
                    and strings[7].lower() == "localhost":
                    row['readable'] = "(RDP) " + row['readable']
                    row['tag'] = "RDP Success"
            # the case of ProcessName field is null
            else:
                row['readable'] = "Explicit logon to {}({}) with {}\{}".format(strings[8] ,strings[11],strings[6],strings[5])
        # the case of both of TargetDomainName and ProcessName are null
        elif len(strings) == 12:
            row['readable'] = "eventlog 4648 hit"
            row['tag'] = "Lateral Move"
            row['readable'] = "Explicit logon to {}({}) with {{-}}\{}".format(strings[7] ,strings[10],strings[5])
        else:
            row['readable'] = "Explicit logon to (unknown format)"
        #try:
            #row['message'] = "[4648]Explicit logon{"
            #row['message'] += "'Acc':{} + ".format(strings[4])
            #row['message'] += "'AccDomain':{} + ".format(strings[5])
            #row['message'] += "'AccGUID':{}".format(strings[6])
            #row['message'] += "}"
            #row['message'] += " | Target Server{" 
            #row['message'] += "'Name':{} + ".format(strings[7])
            #row['message'] += "'Info':{}".format(strings[8])
            #row['message'] += "}"
            #row['message'] += " | Proc Info{" 
            #row['message'] += "'PID':{} + ".format(strings[9])
            #row['message'] += "'ProcName':{}".format(strings[10])
            #row['message'] += "}"
            #row['message'] += " | Network Info{" 
            #row['message'] += "'NetAddr':{} + ".format(strings[11])
            #row['message'] += "'Port':{}".format(strings[12])
            #row['message'] += "}"
            #row['message'] += " | Subject{" 
            #row['message'] += "'SID':{} + ".format(strings[-1])
            #row['message'] += "'Acc':{} + ".format(strings[0])
            #row['message'] += "'AccDomain':{} + ".format(strings[1])
            #row['message'] += "'LogonID':{} + ".format(strings[2])
            #row['message'] += "'LogonGUID':{}".format(strings[3])
            #row['message'] += "}"

        #except:
            #row['message'] = "[4648]Explicit logon{"
            #row['message'] += "'Acc':{} + ".format(strings[4])
            #row['message'] += "'AccDomain':{} + ".format(strings[5])
            #row['message'] += "'AccGUID':{}".format(strings[6])
            #row['message'] += "}"
            #row['message'] += " | Target Server{" 
            #row['message'] += "'Name':{} + ".format(strings[7])
            #row['message'] += "'Info':{}".format(strings[8])
            #row['message'] += "}"
            #row['message'] += " | Proc Info{" 
            #row['message'] += "'PID':{} + ".format(strings[9])
            #row['message'] += "'ProcName':-"
            #row['message'] += "}"
            #row['message'] += " | Network Info{" 
            #row['message'] += "'NetAddr':{} + ".format(strings[10])
            #row['message'] += "'Port':{}".format(strings[11])
            #row['message'] += "}"
            #row['message'] += " | Subject{" 
            #row['message'] += "'SID':{} + ".format(strings[-1])
            #row['message'] += "'Acc':{} + ".format(strings[0])
            #row['message'] += "'AccDomain':{} + ".format(strings[1])
            #row['message'] += "'LogonID':{} + ".format(strings[2])
            #row['message'] += "'LogonGUID':{}".format(strings[3])
            #row['message'] += "}"
    elif row['message'].startswith("[4724 /") and "Security-Auditing" in row['message']:
        row['tag'] = "Password Reset"
        row['readable'] = "eventlog 4724 hit"
        row['readable'] = "Account {}\{}".format(strings[0] ,strings[0])
        row['readable'] += " password reset by {}\{}".format(strings[4],strings[4])

        #row['message'] = "[4723]Account password changed{"
        #row['message'] += "'Acc':{} + ".format(strings[-1])
        #row['message'] += "'AccDomain':{} + ".format(strings[0])
        #row['message'] += "'AccSID':{} + ".format(strings[1])
        #row['message'] += "'SrcAcc':{} + ".format(strings[3])
        #row['message'] += "'SrcAccDomain':{} + ".format(strings[4])
        #row['message'] += "'SrcAccSID':{} + ".format(strings[2])
        #row['message'] += "'LogonSessionId':{} + ".format(strings[5])
        #row['message'] += "}"
    elif row['message'].startswith("[4725 /") and "Security-Auditing" in row['message']:
        row['tag'] = "Account Deleted"
        row['readable'] = "eventlog 4725 hit"
        row['readable'] = "Account {}\{}".format(strings[0],strings[0])
        row['readable'] += " deleted by {}\{}".format(strings[4],strings[4])

        #row['message'] = "[4725]Account deleted{"
        #row['message'] += "'Acc':{} + ".format(strings[-1])
        #row['message'] += "'AccDomain':{} + ".format(strings[0])
        #row['message'] += "'AccSID':{} + ".format(strings[1])
        #row['message'] += "'SrcAcc':{} + ".format(strings[3])
        #row['message'] += "'SrcAccDomain':{} + ".format(strings[4])
        #row['message'] += "'SrcAccSID':{} + ".format(strings[2])
        #row['message'] += "'LogonSessionId':{} + ".format(strings[5])
        #row['message'] += "'PrivList':{} + ".format(strings[6])
        #row['message'] += "}"
    elif row['message'].startswith("[4731 /") and "Security-Auditing" in row['message']:
        row['tag'] = "Group Add"
        row['readable'] = "eventlog 4731 hit"
        row['readable'] = "Account {}({})".format(strings[-1], strings[1])
        row['readable'] += " is added to group {}\{}".format(strings[2], strings[2])
        row['readable'] += " by {}\{}".format(strings[6], strings[6])

        #row['message'] = "[4731]Account added to group{"
        #row['message'] += "'Acc':{} + ".format(strings[-1])
        #row['message'] += "'AccSID':{} + ".format(strings[0])
        #row['message'] += "'TargetGroup':{} + ".format(strings[1])
        #row['message'] += "'TargetDomain':{} + ".format(strings[2])
        #row['message'] += "'TargetSID':{} + ".format(strings[3])
        #row['message'] += "'SubjectSID':{} + ".format(strings[4])
        #row['message'] += "'SubjectAcc':{} + ".format(strings[5])
        #row['message'] += "'SubjectDomain':{} + ".format(strings[6])
        #row['message'] += "'SubjectLogonSessionId':{} + ".format(strings[8])
        #row['message'] += "'PrivList':{} + ".format(strings[9])
        #row['message'] += "}"
    elif row['message'].startswith("[4741 /") and "Security-Auditing" in row['message']:
        row['tag'] = "Account Created"
        row['readable'] = "eventlog 4741 hit"
        row['readable'] = "Computer Account {}\{}({}) is created by {}\{}({})".format(strings[1], strings[0], strings[2], strings[4], strings[3], strings[5])
    elif row['message'].startswith("[106 /") and "Microsoft-Windows-TaskScheduler" in row['message']:
        row['tag'] = "Task Created"
        row['readable'] = "eventlog 106 hit"
        row['readable'] = "Task created by {}; taskname: {}".format(strings[1], strings[0])
    elif row['message'].startswith("[141 /") and "Microsoft-Windows-TaskScheduler" in row['message']:
        row['tag'] = "Task Deleted"
        row['readable'] = "eventlog 141 hit"
        row['readable'] = "Task deleted by {}; taskname: {}".format(strings[1], strings[0])
    elif row['message'].startswith("[200 /") and 'Microsoft-Windows-TaskScheduler' in row['message']:
        row['tag'] = "Task Executed"
        row['readable'] = "eventlog 200 hit"
        row['readable'] = "Task executed: {}({})".format(strings[1], strings[0])
    elif row['message'].startswith("[201 /") and 'Microsoft-Windows-TaskScheduler' in row['message']:
        row['tag'] = "Task Finished"
        row['readable'] = "eventlog 201 hit"
        if len(strings) >= 4:
            row['readable'] = "Task finished; taskname: {}({}) (resultCode:{})".format(strings[0], strings[2], strings[3])
        else:
            row['readable'] = "Task finished; taskname: {}(-) (resultCode:{})".format(strings[0], strings[2])
    elif row['message'].startswith("[1149 /"):
        row['tag'] = "RDP Success"
        row['readable'] = "eventlog 1149 hit"
        if len(strings)==3:
            row['readable'] = "RDP established from {} with {}\\{}".format(strings[2], strings[1], strings[0])
        if len(strings)==2:
            row['readable'] = "RDP established from {} with {}".format(strings[1], strings[0])
        if len(strings)==1:
            row['readable'] = "RDP established from {}".format(strings[0])
    elif row['message'].startswith("[21 /") and "Microsoft-Windows-TerminalServices-LocalSessionManager" in row['message']:
        if strings[2].lower() != "local":
            row['readable'] = "eventlog 21 hit"
            row['readable'] = "RDP established from {} with {} (ID:{})".format(strings[2], strings[0], strings[1])
            row['tag'] = "RDP Success"
    elif row['message'].startswith("[22 /") and "Microsoft-Windows-TerminalServices-LocalSessionManager" in row['message']:
        if strings[2].lower() != "local":
            row['readable'] = "eventlog 22 hit"
            row['tag'] = "RDP Success"
            row['readable'] = "RDP shell start from {} with {} (ID:{})".format(strings[2], strings[0], strings[1])
    elif row['message'].startswith("[25 /") and "Microsoft-Windows-TerminalServices-LocalSessionManager" in row['message']:
        if strings[2].lower() != "local":
            row['readable'] = "eventlog 25 hit"
            row['tag'] = "RDP Success"
            row['readable'] = "RDP reconnected from {} with {} (ID:{})".format(strings[2], strings[0], strings[1])
    elif row['message'].startswith("[24 /") and "Microsoft-Windows-TerminalServices-LocalSessionManager" in row['message']:
        if strings[2].lower() != "local":
            row['readable'] = "eventlog 24 hit"
            row['readable'] = "RDP disconnected from {} with {} (ID:{})".format(strings[2], strings[0], strings[1])
            row['tag'] = "RDP End"
    elif row['message'].startswith("[1102 /") and "Microsoft-Windows-TerminalServices-ClientActiveXCore" in row['message']:
        row['readable'] = "eventlog 1102 hit"
        row['readable'] = "RDP attempt to {}".format(strings[1])
        row['tag'] = "Lateral Move(RDP Attempt)"
    elif row['message'].startswith("[1027 /") and "Microsoft-Windows-TerminalServices-ClientActiveXCore" in row['message']:
        row['readable'] = "eventlog 1027 hit"
        row['readable'] = "RDP success to {}".format(strings[0])
        row['tag'] = "Lateral Move(RDP Success)"
    elif row['message'].startswith("[1024 /") and "Microsoft-Windows-TerminalServices-ClientActiveXCore" in row['message']:
        row['readable'] = "eventlog 1024 hit"
        row['readable'] = "RDP attempt to {}".format(strings[1])
        row['tag'] = "Lateral Move(RDP Attempt)"
    elif row['message'].startswith("[1029 /") and "Microsoft-Windows-TerminalServices-ClientActiveXCore" in row['message']:
        row['readable'] = "eventlog 1029 hit"
        if strings[0] == "UmTGMgTFbA35+PSgMOoZ2ToPpAK+awC010ZOYWQQIfc=-" or strings[0] == "WAlZ81aqzLQmoWEfQivmPQwJxIm/XQcDjplQdjznr5E=-":
            row['readable'] = "RDP attempt with username Administrator".format(strings[0])
        else:
            row['readable'] = "RDP attempt with username {}".format(strings[0])
        row['tag'] = "Lateral Move(RDP Attempt)"
    elif row['message'].startswith("[20499 /") and "Microsoft-Windows-TerminalServices-RemoteConnectionManager" in row['message']:
        row['readable'] = "eventlog 20499 hit"
        row['readable'] = "RDP logon with username: {}".format(strings[1])
        row['tag'] = "RDP Success"
    elif row['message'].startswith("[4778 /"):
        row['readable'] = "eventlog 4778 hit"
        if strings[5].lower() != "local":
            row['readable'] = "RDP reconnected from {} with {}\\{}".format(strings[5], strings[1], strings[0])
            row['tag'] = "RDP Success"
    elif row['message'].startswith("[4779 /"):
        row['readable'] = "eventlog 4779 hit"
        if strings[5].lower() != "local":
            row['readable'] = "RDP disconnected from {} with {}\\{}".format(strings[5], strings[1], strings[0])
            row['tag'] = "RDP End"
    elif row['message'].startswith("[7045 /"):
        row['readable'] = "eventlog 7045 hit"
        row['readable'] = "Service installed: {}".format(strings[1])
        row['tag'] = "Persistence"
    elif row['message'].startswith("[7036 /"):
        #row['readable'] = "eventlog 7036 hit"
        #row['readable'] = "Service state change: {} {}".format(strings[1], strings[0])
        #row['tag'] = "Persistence"
        pass
    elif row['message'].startswith("[4720 /"):
        row['readable'] = "eventlog 4720 hit"
        row['readable'] = "Account {}\\{} created by {}\\{}".format(strings[1], strings[0], strings[5], strings[4])
        row['tag'] = "Account Created"
    elif row['message'].startswith("[12 /") and "Microsoft-Windows-Kernel-General" in row['message']:
        row['readable'] = "eventlog 12 hit"
        row['readable'] = "System Shutdown"
        row['tag'] = "System Shutdown"
    elif row['message'].startswith("[1102 /") and 'Microsoft-Windows-Eventlog' in row['message']:
        row['readable'] = "eventlog 1102 hit"
        row['readable'] = "Security event log deleted by {}\\{}".format(strings[2],strings[1])
        row['tag'] = "Log Deleted"
    elif row['message'].startswith("[104 /") and 'Microsoft-Windows-Eventlog' in row['message']:
        row['readable'] = "eventlog 104 hit"
        row['readable'] = "{} event log deleted by {}\\{}".format(strings[2], strings[1], strings[0])
        row['tag'] = "Log Deleted"
    elif row['message'].startswith("[5860 /") and 'Microsoft-Windows-WMI-Activity' in row['message']:
        row['readable'] = "eventlog 5860 hit"
        row['readable'] = "WMI consumer event detected"
        row['tag'] = "Persistence"
    elif row['message'].startswith("[5861 /") and 'Microsoft-Windows-WMI-Activity' in row['message']:
        row['readable'] = "eventlog 5861 hit"
        row['readable'] = "WMI consumer event detected"
        row['tag'] = "Persistence"
    elif row['message'].startswith("[400 /") and 'powershell' in row['message'].lower():
        row['readable'] = "eventlog 400 hit"
        row['readable'] = "Powershell executed: {}".format(strings[2].split("HostApplication=")[1].split("EngineVersion=")[0])
        row['tag'] = "Execution"
    elif row['message'].startswith("[403 /") and 'powershell' in row['message'].lower():
        row['readable'] = "eventlog 403 hit"
        row['readable'] = "Powershell stopped: {}".format(strings[2].split("HostApplication=")[1].split("EngineVersion=")[0])
        row['tag'] = "Execution"
    elif row['message'].startswith("[800 /") and 'powershell' in row['message'].lower():
        row['readable'] = "eventlog 800 hit"
        row['readable'] = "Powershell Scriptblock Logged"
        row['tag'] = "Execution"
    elif row['message'].startswith("[4104 /") and 'Microsoft-Windows-PowerShell' in row['message']:
        row['readable'] = "eventlog 4103 hit"
        row['readable'] = "Powershell Scriptblock Logged"
        row['tag'] = "Execution"
    elif row['message'].startswith("[40961 /") and 'Microsoft-Windows-PowerShell' in row['message']:
        row['readable'] = "eventlog 40961 hit"
        row['readable'] = "Powershell Console Activated"
        row['tag'] = "Execution"
    elif row['message'].startswith("[40962 /") and 'Microsoft-Windows-PowerShell' in row['message']:
        row['readable'] = "eventlog 40962 hit"
        row['readable'] = "Powershell Console Activated"
        row['tag'] = "Execution"
    elif row['message'].startswith("[6 /") and 'winrm' in row['message'].lower():
        row['readable'] = "eventlog 6 hit"
        row['readable'] = "WinRM connection attempted to other hosts"
        row['tag'] = "Lateral Move(WinRM)"
    elif row['message'].startswith("[91 /") and 'winrm' in row['message'].lower():
        row['readable'] = "eventlog 91 hit"
        row['readable'] = "WinRM connection attempted from other hosts"
        row['tag'] = "Lateral Move(WinRM)"
    elif row['message'].startswith("[168 /") and 'winrm' in row['message'].lower():
        row['readable'] = "eventlog 168 hit"
        row['readable'] = "WinRM service activity"
        row['tag'] = "Execution"
    elif row['message'].startswith("[4616 /") and 'security' in row['message'].lower():
        row['readable'] = "eventlog 4616 hit"
        row['readable'] = "System time changed by {}: from {} {} to {} {}".format(strings[1], strings[4], strings[5], strings[6], strings[7])
        row['tag'] = "Time Changed"
    elif row['message'].startswith("[31001 /") and "Microsoft-Windows-SMBClient" in row['message']:
        row['readable'] = "eventlog 31001 hit"
        if len(strings)>10:
            row['readable'] = "SMB authentication failed to {} with username: {}".format(strings[5], strings[9])
        else:
            row['readable'] = "SMB authentication failed to {}".format(strings[5])
        row['tag'] = "Lateral Move(SMB)"
    elif row['message'].startswith("[30800 /") and "Microsoft-Windows-SMBClient" in row['message']:
        row['readable'] = "eventlog 30800 hit"
        row['readable'] = "SMB connection servername lookup failed on {}".format(strings[3])
        row['tag'] = "Lateral Move(SMB)"
    elif row['message'].startswith("[30803 /") and "Microsoft-Windows-SMBClient" in row['message']:
        row['readable'] = "eventlog 30803 hit"
        decodedIP = decodeIPfromHex(strings[5])
        row['readable'] = "SMB connection to {}({}) is failed".format(strings[3], decodedIP)
        row['tag'] = "Lateral Move(SMB)"
    elif row['message'].startswith("[30804 /") and "Microsoft-Windows-SMBClient" in row['message']:
        row['readable'] = "eventlog 30804 hit"
        decodedIP = decodeIPfromHex(strings[5])
        row['readable'] = "SMB connection to {}({}) is disconnected".format(strings[3], decodedIP)
        row['tag'] = "Lateral Move(SMB)"
    elif row['message'].startswith("[30805 /") and "Microsoft-Windows-SMBClient" in row['message']:
        row['readable'] = "eventlog 30805 hit"
        row['readable'] = "SMB session to {} is terminated".format(strings[4])
        row['tag'] = "Lateral Move(SMB)"
    elif row['message'].startswith("[30807 /") and "Microsoft-Windows-SMBClient" in row['message']:
        row['readable'] = "eventlog 30807 hit"
        row['readable'] = "SMB connection to {} is disconnectioned".format(strings[4])
        row['tag'] = "Lateral Move(SMB)"
    elif row['message'].startswith("[31010 /") and "Microsoft-Windows-SMBClient" in row['message']:
        row['readable'] = "eventlog 31010 hit"
        row['readable'] = "SMB share connection to {} is failed".format(strings[3])
        row['tag'] = "Lateral Move(SMB)"
    else:
        pass
    return row


def readableREG(row):
    if re.search(r"^\[HKEY_LOCAL_MACHINE\\System\\ControlSet00.\\Services\\[^\\\]]+\] .+ Image path", row['message']):
        row['readable'] = "reg service hit"
        reService = r"\\Services\\([^\]]+).+Image path: (.+) (ObjectName:|Error control:)"
        res = re.search(reService, row['message'])
        row['readable'] = "Service Reg/Modified: {}({})".format(res.group(1), res.group(2))
        row['tag'] = "Persistence"
    elif re.search(r"^\[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Search\\RecentApps\\", row['message']):
        row['readable'] = "reg recentapps hit"
        res = re.search(r".+AppPath: \[REG_SZ\] (.+) LastAccessedTime: .+ LaunchCount: \[REG_DWORD_LE\] ([0-9]+)", row['message'])
        row['readable'] = "Last Executed: {} - run count {}".format(res.group(1), res.group(2))
        row['tag'] = "Execution"
    elif re.search(r"^\[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\\.rar[\\\]]", row['message']):
        row['readable'] = "reg rarfileopen hit"
        row['readable'] = "Exfiltlation: RAR file first opened on this user"
        row['tag'] = "Collection"
    elif re.search(r"^\[HKEY_CURRENT_USER\\Software\\Microsoft\\Terminal Server Client\\Servers\\[0-9]+", row['message']):
        row['readable'] = "reg terminalserverclient hit"
        res = re.search(r"^\[HKEY_CURRENT_USER\\Software\\Microsoft\\Terminal Server Client\\Servers\\([0-9\.]+)\] Username hint: (.+)", row['message'])
        row['readable'] = "RDP first connection to {} with {}".format(res.group(1),res.group(2))
        row['tag'] = "Lateral Move(RDP)"
    elif row['source_long'].lower()=='registry key: userassist':
        row['readable'] = "reg userassist hit"
        res = re.search(r".+Value name: (.+) Count: ([0-9]+) ", row['message'])
        row['readable'] = "Last Executed: {} - run count {}".format(res.group(1),res.group(2))
        row['tag'] = "Execution"
    elif row['parser'].lower() == 'winreg/bagmru' and "[MRU Value 0]" in row['message']:
        row['readable'] = "reg bagmru hit"
        tmp = row['message'][row['message'].find("[MRU Value 0]"):]
        idx = tmp.find(" Index: ")
        if idx != -1:
           tmp = tmp[:idx] 
        res = re.search(r"^\[MRU Value 0\]: Shell item path: (.+)$", tmp)
        row['readable'] = "Last Accessed(Shellbag): {}".format(res.group(1))
        row['tag'] = "File Access"
    elif row['parser'].lower() == 'winreg/mrulistex_string_and_shell_item' and "[MRU Value 0]" in row['message']:
        row['readable'] = "reg mrulistex_string_and_shell_item hit"
        tmp = row['message'][row['message'].find("[MRU Value 0]"):]
        idx = tmp.find(" Index: ")
        if idx != -1:        # if there is 'index' string in tmp, delete strings after 'index' strings.
           tmp = tmp[:idx] 
        res = re.search(r".+\[MRU Value 0\]: Path: (.+) Shell item: \[(.+)\]", row['message'])
        row['readable'] = "Last Accessed: {}(lnk:{})".format(res.group(1), res.group(2))
        row['tag'] = "File Access"
    elif re.search(r"^\[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\\.rar[\\\]]", row['message']):
        row['readable'] = "Exfiltlation: RAR file first opened on this user"
        row['tag'] = "Collection"
    elif row['source_long'].lower()=='appcompatcache registry entry':
        row['readable'] = "reg appcompatcache hit"
        res = re.search(r"Path: (.+)", row['message'])
        row['readable'] = "Last Executed: {}".format(res.group(1))
        row['tag'] = "Execution"
    else:
        pass
    return row

def readableFILE(row):
    if row['source_long'].lower() == 'amcache':
        row['readable'] = "execution time(amcache) hit"
        res = re.search(r"^filename: (.+) & sha1: (.+) & .+$", row['message'])
        vtRes = scanVT([res.group(2)])
        row['readable'] = "First Executed: {} - vtScore: {}".format(res.group(1), int(vtRes.iloc[0]["POSITIVES"]))
        row['tag'] = "Execution"
    elif row['source_long'].lower() == 'mft':
        if re.search(r"^[mac\.]{3}b", row['timestamp_desc']):
            if re.search(r"(.+\.rar)$", row['message']):
                row['readable'] = ".rar timestamp hit"
                row['readable'] = row["message"] + " is created"
                row['tag'] = "Collection"
            else:
                row['message'] += " の作成"
                row['tag'] = "File Created"
        elif re.search(r"^m[acb\.]{3}", row['timestamp_desc']) \
            and "Windows/System32/wbem/Repository/OBJECTS.DATA" in row['message']:
            row['readable'] = "Persistence: WMI persistence might be created"
            row['tag'] = "Persistence"
    elif row['source_long'].lower()=="msie webcache container record":
        if(row['timestamp_desc'].lower()=='creation time'):
            reWebCacheCrtime = "URL: ([^ ]+) Access count"
            url = re.search(reWebCacheCrtime, unicode(row['message'], charCode)).group(1)
            url = url.replace('http','hxxp')
            url = re.sub(r'\.([^\.]+/)',r'[.]\1',url)
            row['readable'] = "IE Access: {}".format(url)
            row['tag'] = "Web Access"
        else:
            reWebCache = "@([^ ]+) Access count"
            url = re.search(reWebCache, unicode(row['message'], charCode)).group(1)
            url = url.replace('http','hxxp')
            url = re.sub(r'\.([^\.]+/)',r'[.]\1',url)
            row['readable'] = "IE Access: {}".format(url)
            row['tag'] = "Web Access"
    elif row['source_long'].lower() == 'winprefetch':
        res = re.search(r"^.+ was executed - (run count [0-9]+) path: (.+) hash:.+$", row['message'])
        row['readable'] = "Executed: {} - {}".format(res.group(2), res.group(1))
        row['tag'] = "Execution"
    else:
        pass

    return row

def l2tReadable():
    fout = open("edit-" + os.path.basename(sys.argv[1]),"w")


    fobj =  open(sys.argv[1],"r",encoding="utf_8", errors="ignore", newline='' )
    fcsv = csv.DictReader(fobj, delimiter=",")
    fieldnames = fcsv.fieldnames
    fieldnames.remove("username")
    fieldnames = fieldnames[0:1] + ["event","username","readable"] + fieldnames[1:]
    writer = csv.DictWriter(fout, fieldnames)
    writer.writeheader()
    for row in fcsv:
        #print(row)
        row['readable'] = "-"
        try:
            if row['parser'].lower()=="winevtx":
                row = readableEVTX(row)
            elif "winreg" in row['parser'].lower():
                row = readableREG(row)
            elif row['parser'].lower()=="filestat" or row['parser'].lower()=="analyzemft.py":
                row = readableFILE(row)
            else:
                pass
            #row.pop(None)
            row.move_to_end('readable',last=False)
            row.move_to_end('username',last=False)
            row.move_to_end('event',last=False)
            row.move_to_end('datetime',last=False)

            writer.writerow(row)
        except Exception as e:
            print(e)
            row['readable'] += "(parse error)"
            row.move_to_end('readable',last=False)
            row.move_to_end('username',last=False)
            row.move_to_end('event',last=False)
            row.move_to_end('datetime',last=False)
            #ipdb.set_trace()
            writer.writerow(row)

    fout.close()
    fobj.close()

def main():
    l2tReadable()

if __name__ == '__main__':
    main()