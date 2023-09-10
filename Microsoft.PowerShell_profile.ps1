function Send-CustomMail {
	$secpasswd = ConvertTo-SecureString "BEST_PASSWORD_HERE" -AsPlainText -Force;
	$cred = New-Object System.Management.Automation.PSCredential ("BEST_MAIL_HERE", $secpasswd);
	Send-MailMessage -SmtpServer BEST_SMTP_SERVER_ADDRESS_HERE -Credential $cred -UseSsl -From 'BEST_MAIL_HERE' -To 'ADMIN_LOG_MAIL' -Subject 'CRYALP.com Login' -Body $($(netstat -ano -p tcp | findstr 3389 | out-string) + $(quser | out-string) + $("`n" | out-string) + $(qwinsta | out-string) | out-string)
}

function AutoBanSpammer {
	cd "C:\DIRECTORY_TO_BE_LISTED";python auto-ip-block.py
}