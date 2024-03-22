$PROGNAME="astroReport"

function logwrite
{
	Param ([string]$logstring)
	
	$aux="[ "+$(get-date -format "dd-MM-yyyy HH:mm:ss")+" ] "+$logstring
	write-host $aux
}

logwrite("Starting "+$PROGNAME+" installer")

$dest=$(join-path $($Env:public) -childpath "astroReport")
if (-not (test-path -path $dest)){
	logwrite("creating directory: "+$dest)
	new-item -path $dest -itemtype directory
}

logwrite("downloading "+$PROGNAME+" files to "+$dest)
Invoke-WebRequest "https://raw.githubusercontent.com/mgutierrezp/astroReport/main/binaries/astroReport.exe" -OutFile $(join-path $dest -childpath "astroReport.exe")
Invoke-WebRequest "https://raw.githubusercontent.com/mgutierrezp/astroReport/main/astroReport.config.xml" -OutFile $(join-path $dest -childpath "astroReport.config.xml")
Invoke-WebRequest "https://raw.githubusercontent.com/mgutierrezp/astroReport/main/astroReport.reg" -OutFile $(join-path $dest -childpath "astroReport.reg")
logwrite("importing registry file")
&(get-command reg) import $(join-path $dest -childpath "astroReport.reg")
logwrite("FINISHED.")
read-host -prompt "Press ENTER to exit"