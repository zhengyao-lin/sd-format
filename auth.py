import struct
from util import *

with open("km0.1") as fp:
	keymap = eval(fp.read())

def keygen(uid, ofs, serial): # serial: a byte string
	return md5(struct.pack("<II", uid, ofs) + serial +
			   keymap[struct.unpack("<I", serial)[0] % 64], 6)
