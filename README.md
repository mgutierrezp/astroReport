QUICK START
==============

*** precompiled binaries available for linux and windows ***

*** just copy the corresponding binary from 'binaries' folder ***

*** copy the conf file 'astroReport.config.xml' alongside the executable or specify the location with --config ***




*** manual installation below: ***

- Install Python >= 3.6

- Create a new virtual environment and activate it (ensure you are executing python v3 and not v2!):
	$ python -m venv myVirtualEnv
	# linux users:
		$ source myVirtualEnv/bin/activate
	# windows users:
		# if using powershell
			$ myVirtualEnv\Scripts\Activate.ps1
		# if using a regular command prompt
			$ myVirtualEnv\Scripts\activate.bat

- Install python libraries within your new virtual environment
	$ pip install -r requirements.txt

- Rename astroReportProjectInfo.xml.example to astroReportProjectInfo.xml and customize if needed. Copy it alongside the executable location or specify with --config


USAGE
==============
- Choose a directory you want to analyze, and run
	
	$ python astroReport.py /some/dir/of/your/choice

- Additionally, move astroReportProjectInfo.xml.example to /some/dir/of/your/choice/astroReportProjectInfo.xml and customize it. Then, launch the same command again
