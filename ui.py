#! /usr/bin/env python3

import os, sys
import webbrowser
import platform

if platform.system() == "Windows":
	webbrowser.open("http://localhost:3134")
	import uib
else:
	if os.geteuid(): # not root
		webbrowser.open("http://localhost:3134")
		os.execlp("sudo", "sudo", sys.executable, *sys.argv)
	else:
		import uib
