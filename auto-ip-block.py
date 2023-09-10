import os
import subprocess

blockedIpList = {}
ignoredIpList = ["91.151.88.110"]
reportedIpFile = "_reportedIpList.csv"

if not os.path.isfile(reportedIpFile):
    file = open(reportedIpFile, "a+")
    file.close()


with open(reportedIpFile) as file:
    for num, line in enumerate(file, 1):
        ip = line.split(",")[0].strip()
        if blockedIpList.get(ip) is None:
            blockedIpList[ip] = set()

searchDir = "C:\\DIRECTORY_TO_BE_LISTED\\"
dir_list = os.listdir(searchDir)
print("Files and directories:")
for dir in dir_list:
    if (".log" not in dir or dir == os.path.basename(__file__) or dir == reportedIpFile):
        continue
    currentDir = searchDir + dir
    print(currentDir)
    with open(currentDir) as file:
        for num, line in enumerate(file, 1):
            if "Invalid" in line:
                separator = " " if "ex" in dir else "\t"
                splittedLine = line.split(separator)
                ip = splittedLine[2 if "ex" in dir else 4].strip()
                if ip in ignoredIpList:
                    continue
                data = ip + "," + ",".join(splittedLine)
                if blockedIpList.get(ip) is None:
                    blockedIpList[ip] = set()
                blockedIpList[ip].add(data)

file = open(reportedIpFile, "a+")

blockedIpStr = ""
for blockedIp in blockedIpList:
    blockedIpStr += blockedIp + ","
    for blockedIpDetail in blockedIpList[blockedIp]:
        file.write(blockedIpDetail)

file.close()

ruleName = "Automated banned IPs"
command = f'netsh advfirewall firewall delete rule "{ruleName}"'
secondCommand = f'netsh advfirewall firewall add rule name="{ruleName}" dir=in action=block protocol=ANY remoteip="{",".join(blockedIpList)}"'
print(command+";"+secondCommand)

subprocess.call(command, shell=True)
subprocess.call(secondCommand, shell=True)
