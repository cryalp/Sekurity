import datetime
import os
import subprocess
import ipaddress

blockedIpList = {}
newBlockedIpList = {}
ignoredIpList = ["::1", "91.151.88.110"]

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

searchDir = "C:\\Program Files (x86)\\Mail Enable\\Logging\\SMTP\\"
dir_list = [
    searchDir + f for f in os.listdir(searchDir) if os.path.isfile(searchDir + f)
]

unwantedLogList = ["Invalid Username or Password", "AUTH LOGIN	500 Syntax error"]
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
