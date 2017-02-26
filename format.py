import struct, time
import argparse
import auth
import math
import os

from util import *
from yhy523u import *

DEF_KEY = "\xff" * 6
DEF_DATASIZE = 8 # sectors
DEF_MAXOFS = int((64 - 1) / DEF_DATASIZE)

ALLOW_VALUE = (1, 2, 5)
STRUCT_BLOCK = struct.Struct("<IIII")

class SDEngine:
	def __init__(self, port, pub = None, priv = None):
		self.device = YHY523U(port)
		self.enc = auth.SDEnc()
		self.muted = False
		self.tlog = {};

		if pub != None:
			self.enc.loadPub(pub)

		if priv != None:
			self.enc.loadPriv(priv)

	def initCard(self, uid, value, version = 1, ofs = 0):
		card_type, serial = self.device.select()

		assert ofs <= DEF_MAXOFS
		ofs *= DEF_DATASIZE

		self.device.write_block(1, DEF_KEY, 0, STRUCT_BLOCK.pack(ofs, 0, 0, 0))

		self.device.write_block(ofs + 2, DEF_KEY, 0, STRUCT_BLOCK.pack(uid, 0, timestamp(), 0)) # uid, ref, timestamp, pad
		self.device.write_block(ofs + 2, DEF_KEY, 1, STRUCT_BLOCK.pack(0, 0, 0, 0)) # key[4]

		self.device.write_block(ofs + 3, DEF_KEY, 0, STRUCT_BLOCK.pack(value, version, 0, 0)) # value, version, pad, pad

		sign = self.enc.sign(uid, ofs, serial, value)

		assert len(sign) == 128

		self.device.write_block(ofs + 3, DEF_KEY, 1, sign[:16])
		self.device.write_block(ofs + 3, DEF_KEY, 2, sign[16:32])
		self.device.write_block(ofs + 4, DEF_KEY, 0, sign[32:48])
		self.device.write_block(ofs + 4, DEF_KEY, 1, sign[48:64])
		self.device.write_block(ofs + 4, DEF_KEY, 2, sign[64:80])
		self.device.write_block(ofs + 5, DEF_KEY, 0, sign[80:96])
		self.device.write_block(ofs + 5, DEF_KEY, 1, sign[96:112])
		self.device.write_block(ofs + 5, DEF_KEY, 2, sign[112:128])

		key = auth.keygen(uid, ofs, serial)
		
		self.device.set_key(ofs + 3, DEF_KEY, key, key)
		self.device.set_key(ofs + 4, DEF_KEY, key, key)
		self.device.set_key(ofs + 5, DEF_KEY, key, key)

		# print(to_hex(key))
		return key

	def checkTimestamp(self, serial, stamp):
		now = timestamp()
		if (serial in self.tlog and stamp < self.tlog[serial]) \
		   or stamp > now:
			return 0 # fake?

		self.tlog[serial] = now

		return now

	def verify(self):
		suc = 0
		value = None
		vers = None
		ref = None
		uid = None
		msg = None
		stamp = None

		try:
			card_type, serial = self.device.select()

			# get offset
			ofs = STRUCT_BLOCK.unpack(self.device.read_block(1, DEF_KEY, 0))[0]
			assert ofs <= DEF_MAXOFS
			ofs *= DEF_DATASIZE

			b20 = list(STRUCT_BLOCK.unpack(self.device.read_block(ofs + 2, DEF_KEY, 0)))
			uid = b20[0]

			key = auth.keygen(uid, ofs, serial)
			b30 = STRUCT_BLOCK.unpack(self.device.read_block(ofs + 3, key, 0))

			value = b30[0]
			vers = b30[1]

			if not value in ALLOW_VALUE:
				raise Exception, "illegal value"

			sign = (
				self.device.read_block(ofs + 3, key, 1) +
				self.device.read_block(ofs + 3, key, 2) +
				self.device.read_block(ofs + 4, key, 0) +
				self.device.read_block(ofs + 4, key, 1) +
				self.device.read_block(ofs + 4, key, 2) +
				self.device.read_block(ofs + 5, key, 0) +
				self.device.read_block(ofs + 5, key, 1) +
				self.device.read_block(ofs + 5, key, 2)
			)

			if not self.enc.verify(sign, uid, ofs, serial, value):
				raise Exception, "auth failed"

			stamp = self.checkTimestamp(serial, b20[2])

			if stamp == 0:
				raise Exception, "potential fake card"

			# add ref
			b20[1] += 1
			b20[2] = stamp
			ref = b20[1]

			self.device.write_block(ofs + 2, DEF_KEY, 0, STRUCT_BLOCK.pack(*b20))

			suc = 1
		except KeyboardInterrupt:
			raise KeyboardInterrupt
		except Exception, e:
			msg = e.message

		return {
			"suc": suc,
			"val": value,
			"ver": vers,
			"ref": ref,
			"uid": uid,
			"stamp": stamp,
			"msg": msg
		}

	def validLoop(self, debug):
		res = None

		if self.hasCard():
			res = self.verify()

			if debug:
				print(res)
			else:
				print(
					("auth suc: %d dollar%s" % (res["val"], "" if res["val"] == 1 else "s"))
					if res["suc"]
					else ("auth failed: " + res["msg"])
				)

			if res["suc"]:
				self.beep("suc")
			else:
				self.beep("failed")

			while self.hasCard(): pass

		return res

	# success 1b 6f 74 c0 8b 2d
	# success 35 12 44 5c dd c6
	def initLoop(self, uid, value, version):
		key = None

		if self.hasCard():
			try:
				key = self.initCard(uid, value, version)
				time.sleep(0.5)
				print("success uid: %d key: %s" % (uid, to_hex(key)))
				self.beep("suc")
			except KeyboardInterrupt:
				raise KeyboardInterrupt
			except:
				print("failed")
				self.beep("failed")

			while self.hasCard(): pass
		
		return key

	def wipeout(self):
		card_type, serial = self.device.select()

		ofs = STRUCT_BLOCK.unpack(self.device.read_block(1, DEF_KEY, 0))[0]
		assert ofs <= DEF_MAXOFS
		ofs *= DEF_DATASIZE

		self.device.write_block(1, DEF_KEY, 0, "\x00" * 16)

		b20 = STRUCT_BLOCK.unpack(self.device.read_block(ofs + 2, DEF_KEY, 0))

		self.device.write_block(ofs + 2, DEF_KEY, 0, "\x00" * 16) # uid, ref, pad, pad
		self.device.write_block(ofs + 2, DEF_KEY, 1, "\x00" * 16) # key[4]

		key = auth.keygen(b20[0], ofs, serial)

		self.device.set_key(ofs + 3, key, DEF_KEY, DEF_KEY)
		self.device.write_block(ofs + 3, DEF_KEY, 0, "\x00" * 16)
		self.device.write_block(ofs + 3, DEF_KEY, 1, "\x00" * 16)
		self.device.write_block(ofs + 3, DEF_KEY, 2, "\x00" * 16)

		self.device.set_key(ofs + 4, key, DEF_KEY, DEF_KEY)
		self.device.write_block(ofs + 4, DEF_KEY, 0, "\x00" * 16)
		self.device.write_block(ofs + 4, DEF_KEY, 1, "\x00" * 16)
		self.device.write_block(ofs + 4, DEF_KEY, 2, "\x00" * 16)

		self.device.set_key(ofs + 5, key, DEF_KEY, DEF_KEY)
		self.device.write_block(ofs + 5, DEF_KEY, 0, "\x00" * 16)
		self.device.write_block(ofs + 5, DEF_KEY, 1, "\x00" * 16)
		self.device.write_block(ofs + 5, DEF_KEY, 2, "\x00" * 16)

	def hasCard(self):
		return self.device.has_card()

	def mute(self):
		self.muted = True

	def beep(self, t):
		try:
			if t == "suc":
				self.device.set_led("blue")
				if not self.muted: self.device.beep(20)
				time.sleep(0.5)
				self.device.set_led("off")
			elif t == "failed":
				self.device.set_led("red")
				if not self.muted: self.device.beep(10)
				time.sleep(0.1)
				self.device.set_led("off")

				time.sleep(0.1)

				self.device.set_led("red")
				if not self.muted: self.device.beep(10)
				time.sleep(0.1)
				self.device.set_led("off")

				time.sleep(0.1)

				self.device.set_led("red")
				if not self.muted: self.device.beep(10)
				time.sleep(0.1)
				self.device.set_led("off")

		except KeyboardInterrupt:
			raise KeyboardInterrupt
		except: pass

def errmsg(msg, code = 1):
	print("error: " + msg)
	exit(code)

if __name__ == "__main__":
	parser = argparse.ArgumentParser()

	parser.add_argument("-d", "--debug", help = "debug mode", action = "store_true")
	parser.add_argument("--wipe", help = "wipe out the current card", action = "store_true")
	parser.add_argument("-q", "--mute", help = "don't beep", action = "store_true")

	parser.add_argument("--batch", help = "batch initialization", action = "store_true")
	parser.add_argument("--value", help = "value of the card", type = int)
	parser.add_argument("--uid", help = "starting uid", type = int)
	parser.add_argument("--version", help = "version", type = int, default = 1)

	parser.add_argument("--pub", help = "public key", type = str, default = "sdenc.pub")
	parser.add_argument("--priv", help = "private key", type = str, default = "sdenc.priv")

	argv = parser.parse_args()

	pub = None
	priv = None

	if os.path.isfile(argv.pub):
		pub = argv.pub

	if os.path.isfile(argv.priv):
		priv = argv.priv

	eng = SDEngine("/dev/ttyUSB0", pub, priv)

	if argv.mute:
		eng.mute()

	if argv.wipe:
		if raw_input("Are you sure to wipe out the card? [N/y]: ").lower() == "y":
			eng.wipeout()
			print("success")
		exit(0)

	if argv.batch:
		if argv.value == None or not argv.value in ALLOW_VALUE:
			errmsg("invalid value")

		if argv.uid == None:
			errmsg("no uid specified")

		uid = argv.uid

		while 1:
			if eng.initLoop(uid, argv.value, argv.version):
				uid += 1
			time.sleep(0.1)

		exit(0)

	if argv.debug:
		print("debug mode")

	# 49 44 dc 38 2c 33
	# 21 6b 10 3c ac 4f
	# e8 0b 65 f8 d4 ca
	# eng.initCard(2, 5)

	while 1:
		eng.validLoop(argv.debug == True)
		time.sleep(0.1)

	exit(0)
