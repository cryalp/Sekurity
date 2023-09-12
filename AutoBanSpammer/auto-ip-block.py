import datetime
import os
import subprocess

blockedIpList = {}
newBlockedIpList = {}
ignoredIpList = ["91.151.88.110"]

reportedDir = "reportedDir\\"
if not os.path.exists(reportedDir):
    os.makedirs(reportedDir)

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

searchDir = "C:\\DIRECTORY_TO_BE_LISTED\\"
dir_list = [
    searchDir + f for f in os.listdir(searchDir) if os.path.isfile(searchDir + f)
]
print("Files and directories:")
for dir in dir_list:
    if ".log" not in dir or dir == os.path.basename(__file__):
        continue
    print(dir)
    with open(dir) as file:
        for num, line in enumerate(file, 1):
            if "Invalid" in line:
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

now = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
reportedIpFile = reportedDir + now + "_reportedIpList.csv"

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

ruleName = "Automated banned IPs"
command = f'netsh advfirewall firewall delete rule "{ruleName}"'
secondCommand = f'netsh advfirewall firewall add rule name="{ruleName}" dir=in action=block protocol=ANY remoteip="{",".join(blockedIpList)}"'
print(command + ";" + secondCommand)

if len(blockedIpStr) > 0:
    subprocess.call(command, shell=True)
    subprocess.call(secondCommand, shell=True)
