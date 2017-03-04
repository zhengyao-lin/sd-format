import datetime
import time
import hashlib

def to_hex(cmd):
	return " ".join([ hex(c)[2:].zfill(2) for c in cmd ])

def to_hex_mat(cmd, maxr = 6, indent = "   "):
	"""Return the hexadecimal version of a serial command.

	Keyword arguments:
	cmd -- the serial command

	"""

	bt = [ hex(c)[2:].zfill(2) for c in cmd ]
	cont = [ indent + " ".join(bt[i:i + maxr]) for i in range(0, len(bt), maxr) ]

	return "\n".join(cont)

def md5(str, maxb = 16):
	m = hashlib.md5()
	m.update(str)
	return m.digest()[:maxb]

def timestamp():
	return int(time.mktime(datetime.datetime.now().timetuple()))

def bytec(str):
	return str.encode("latin1")

def strc(bytes):
	return str(bytes, "latin1")

def byte(num):
	return chr(num).encode("latin1")
