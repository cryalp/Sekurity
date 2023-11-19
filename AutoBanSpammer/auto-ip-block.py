import datetime
from datetime import date
import os
import subprocess
import ipaddress
import re

blockedIpList = {}
newBlockedIpList = {}
ignoredIpList = ["::1", "91.151.88.110", "46.31.77.212"]

reportedDir = "reportedDir\\"
if not os.path.exists(reportedDir):
    os.makedirs(reportedDir)

reportedDirFileList = os.listdir(reportedDir)
reportedDirFileList.sort()

reportedFilePostFix = "_reportedIpList.csv"

now = datetime.datetime.now()
today = now.strftime("%Y-%m-%d")


def mergeToUpperFile(upperDay, upperMonth):
    reportedDayFileStr = upperDay + reportedFilePostFix
    reportedMonthFileStr = upperMonth + reportedFilePostFix
    for reportedFileStr in reportedDirFileList:
        if (
            reportedFileStr.startswith(upperDay)
            and reportedFileStr != reportedDayFileStr
        ):
            reportedDayFile = open(reportedDir + reportedDayFileStr, "a+")
            reportedFile = os.path.abspath(reportedDir + reportedFileStr)
            if not os.path.exists(reportedFile):
                continue
            with open(reportedFile) as file:
                for line in file:
                    reportedDayFile.write(line)
            if os.path.exists(reportedFile):
                print("Merged:" + reportedFileStr + " into " + reportedDayFileStr)
                os.remove(reportedFile)
            reportedDayFile.close()

        if (
            reportedFileStr.startswith(upperMonth)
            and reportedFileStr != reportedMonthFileStr
            and not reportedFileStr.startswith(today)
        ):
            reportedMonthFile = open(reportedDir + reportedMonthFileStr, "a+")
            reportedFile = os.path.abspath(reportedDir + reportedFileStr)
            if not os.path.exists(reportedFile):
                continue
            with open(reportedFile) as file:
                for line in file:
                    reportedMonthFile.write(line)
            if os.path.exists(reportedFile):
                print("Merged: " + reportedFileStr + " into " + reportedMonthFileStr)
                os.remove(reportedFile)
            reportedMonthFile.close()


for month in range(1, 13):
    daysInMonth = (
        date(
            now.year + 1 if month == 12 else now.year,
            1 if month == 12 else month + 1,
            1,
        )
        - date(now.year, month, 1)
    ).days
    for day in range(1, daysInMonth + 1):
        newDate = date(now.year, month, day)
        mergeToUpperFile(newDate.strftime("%Y-%m-%d"), newDate.strftime("%Y-%m"))

reportedDirFileList = os.listdir(reportedDir)

for reportedFile in reportedDirFileList:
    reportedFile = os.path.abspath(reportedDir + reportedFile)
    print("Reported file: " + reportedFile)
    with open(reportedFile) as file:
        for num, line in enumerate(file, 1):
            ip = line.split(",")[0].strip()
            if ip in ignoredIpList:
                continue
            if blockedIpList.get(ip) is None:
                blockedIpList[ip] = set()

searchDir = "C:\\Program Files (x86)\\Mail Enable\\Logging\\SMTP\\"
dir_list = [
    searchDir + f for f in os.listdir(searchDir) if os.path.isfile(searchDir + f)
]

unwantedLogList = [
    "Invalid Username or Password",
    "AUTH LOGIN	500 Syntax error",
    "503 This mail server requires authentication when attempting to send to a non-local e-mail address",
    "503 Bad sequence of commands",
    "503 Too many invalid commands were received",
]
unwantedEhloList = [r"EHLO.*alex.*\.ru"]
newReportedEhloDomainList = []

print("Files and directories:")
for dir in dir_list:
    if ".log" not in dir or dir == os.path.basename(__file__):
        continue
    print(dir)
    with open(dir) as file:
        for num, line in enumerate(file, 1):
            if any(unwantedLog in line for unwantedLog in unwantedLogList):
                separator = " " if "ex" in dir else "\t"
                splittedLine = line.split(separator)
                ip = splittedLine[2 if "ex" in dir else 4].strip()
                if ip in ignoredIpList:
                    continue
                data = ip + "," + ",".join(splittedLine)
                if blockedIpList.get(ip) is not None:
                    continue
                if newBlockedIpList.get(ip) is None:
                    newBlockedIpList[ip] = set()
                newBlockedIpList[ip].add(data)
            for unwantedEhlo in unwantedEhloList:
                if re.search(unwantedEhlo, line):
                    splittedLine = line.split(" " if "ex" in dir else "\t")
                    ehlo = (
                        splittedLine[8 if "ex" in dir else 6]
                        .strip()
                        .split("+" if "ex" in dir else " ")[1]
                        .split(".")
                    )
                    ehlo = ".".join(ehlo[1:3] if len(ehlo) > 2 else ehlo[0:2])
                    if ehlo not in newReportedEhloDomainList:
                        newReportedEhloDomainList.append("*" + ehlo)

reportedIpFile = reportedDir + now.strftime("%Y-%m-%d-%H-%M-%S") + reportedFilePostFix

blockedIpStr = ""
for blockedIp in blockedIpList:
    blockedIpStr += blockedIp + ","

if len(newBlockedIpList) > 0:
    reportedNewFile = open(reportedIpFile, "a+")

    for blockedIp in newBlockedIpList:
        blockedIpStr += blockedIp + ","
        for blockedIpDetail in newBlockedIpList[blockedIp]:
            reportedNewFile.write(blockedIpDetail)

    reportedNewFile.close()

blockedIpStr = blockedIpStr[:-1]
blockedIpList = sorted(blockedIpStr.split(","), key=ipaddress.IPv4Address)

ruleName = "Automated banned IPs"

command = f'netsh advfirewall firewall delete rule "{ruleName}"'
ruleCountCommand = f'(netsh advfirewall firewall show rule name=all | find "Rule Name:" | find "{ruleName}").Count'
# print(command + ";" + secondCommand)

if len(blockedIpList) > 0:
    # subprocess.call(command, shell=True)

    blockedIpStrList = []
    tempBlockedIpStr = ""
    for blockedIp in blockedIpList:
        if len(tempBlockedIpStr + blockedIp) >= 8000:
            blockedIpStrList.append(tempBlockedIpStr[:-1])
            tempBlockedIpStr = ""
        tempBlockedIpStr += blockedIp + ","

    blockedIpStrList.append(tempBlockedIpStr[:-1])

    ruleCount = int(
        str(
            subprocess.run(
                ["powershell", "-Command", ruleCountCommand],
                capture_output=True,
                text=True,
            ).stdout
        ).replace("\n", "")
    )

    print("Blocked: " + str(len(blockedIpList)))

    for counter in range(ruleCount):
        secondCommand = f'netsh advfirewall firewall set rule name="{ruleName + " " + str(counter)}" new remoteip="{blockedIpStrList[counter]}"'
        subprocess.call(secondCommand, shell=True)
        # print(secondCommand)

    if ruleCount < len(blockedIpStrList):
        for counter in range(ruleCount, len(blockedIpStrList)):
            secondCommand = f'netsh advfirewall firewall add rule name="{ruleName + " " + str(counter)}" dir=in action=block protocol=ANY remoteip="{blockedIpStrList[counter]}"'
            subprocess.call(secondCommand, shell=True)
            # print(secondCommand)

unwantedEHLORegeditParentPath = "HKLM"
unwantedEHLORegeditPath = (
    r"SOFTWARE\WOW6432Node\Mail Enable\Mail Enable\Connectors\SMTP"
)
unwantedEHLORegeditName = r"Blocked HELO"
unwantedEHLORegeditKey = (
    unwantedEHLORegeditParentPath
    + os.sep
    + unwantedEHLORegeditPath
    + os.sep
    + unwantedEHLORegeditName
)
unwantedEHLORegeditReadKeyCommand = (
    r'(New-Object -ComObject WScript.Shell).RegRead("' + unwantedEHLORegeditKey + '")'
)

unwantedEHLORegeditKeyValueListStr = str(
    subprocess.run(
        ["powershell", "-Command", unwantedEHLORegeditReadKeyCommand],
        capture_output=True,
        text=True,
    ).stdout
)

if len(unwantedEHLORegeditKeyValueListStr) > 0:
    unwantedEHLORegeditKeyValueList = unwantedEHLORegeditKeyValueListStr.split("\n")[
        0
    ].split(",")
else:
    unwantedEHLORegeditKeyValueList = []

for newReportedEhloDomain in newReportedEhloDomainList:
    if newReportedEhloDomain in unwantedEHLORegeditKeyValueList:
        continue
    unwantedEHLORegeditKeyValueList.append(newReportedEhloDomain)

unwantedEHLORegeditKeyValue = ",".join(unwantedEHLORegeditKeyValueList)

unwantedEHLORegeditWriteKeyCommand = (
    r"Set-ItemProperty"
    + (
        ' -Path "'
        + unwantedEHLORegeditParentPath
        + ":"
        + os.sep
        + unwantedEHLORegeditPath
        + '"'
    )
    + (' -Name "' + unwantedEHLORegeditName + '"')
    + (' -Value "' + unwantedEHLORegeditKeyValue + '"')
)
print("Reported EHLO Domains: \n" + unwantedEHLORegeditWriteKeyCommand)

subprocess.run(
    ["powershell", "-Command", unwantedEHLORegeditWriteKeyCommand],
    capture_output=True,
    text=True,
)
