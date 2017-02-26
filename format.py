import struct, time
import argparse
import getpass
import base64
import auth
import math
import os

from util import *
from yhy523u import *

DEF_KEY = "\xff" * 6
DEF_DATASIZE = 8 # sectors
DEF_MAXOFS = int((64 - 1) / DEF_DATASIZE)
DEF_MAXKEYBLOCK = 13

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

	def waitCard(self):
		while not self.hasCard(): time.sleep(0.1)

	def waitCardLeave(self):
		while self.hasCard(): time.sleep(0.1)

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

			self.waitCardLeave()

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
			except Exception, e:
				print("failed: " + e.message)
				self.beep("failed")

			self.waitCardLeave()
		
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

	# card type(ctp): 1 for pub key, 2 for priv key
	def initAdminCard(self, ctp, b64key, passwd):
		card_type, serial = self.device.select()
		key = base64.b64decode(b64key)
		
		assert len(key) <= DEF_MAXKEYBLOCK * 3 * 16

		self.device.write_block(1, DEF_KEY, 0, STRUCT_BLOCK.pack(ctp, len(key), 0, 0)) # type, len

		if len(key) % 16:
			key += "\x00" * (16 - len(key) % 16)

		sec = 2 # sector
		block = 0

		for i in range(0, len(key), 16):
			if block == 2:
				sec += 1
				block = 0
			else:
				block += 1

			self.device.write_block(sec, DEF_KEY, block, key[i:i + 16])

		passwd = md5(passwd, 6)

		for i in range(1, 16):
			self.device.set_key(i, DEF_KEY, passwd, passwd)

	def readAdminCard(self, passwd):
		ctp = None
		klen = None
		key = None
		msg = None
		suc = 0

		try:
			card_type, serial = self.device.select()

			passwd = md5(passwd, 6)

			b10 = STRUCT_BLOCK.unpack(self.device.read_block(1, passwd, 0))

			ctp = b10[0]
			klen = b10[1]

			if klen % 16:
				klen += 16 - klen % 16

			sec = 2 # sector
			block = 0
			key = ""

			for i in range(0, klen, 16):
				if block == 2:
					sec += 1
					block = 0
				else:
					block += 1

				key += self.device.read_block(sec, passwd, block)

			klen = b10[1]
			key = key[:klen]
			suc = 1

		except KeyboardInterrupt:
			raise KeyboardInterrupt
		except Exception, e:
			msg = e.message

		return {
			"suc": suc,
			"type": ctp,
			"key": key,
			"msg": msg
		}

	def applyAdminCard(self, ctp, key):
		if ctp == 1:
			# pub key
			pkcs = "-----BEGIN RSA PUBLIC KEY-----\n" + base64.b64encode(key) + "\n-----END RSA PUBLIC KEY-----"
			self.enc.loadPubKey(pkcs)
			return "public"
		elif ctp == 2:
			# priv key
			pkcs = "-----BEGIN RSA PRIVATE KEY-----\n" + base64.b64encode(key) + "\n-----END RSA PRIVATE KEY-----"
			self.enc.loadPrivKey(pkcs)
			return "private"
		else:
			raise Exception, "unrecognized admin card type " + str(ctp)

	def wipeAdmin(self, passwd):
		card_type, serial = self.device.select()

		passwd = md5(passwd, 6)

		for i in range(1, 16):
			self.device.write_block(i, passwd, 0, "\x00" * 16)
			self.device.write_block(i, passwd, 1, "\x00" * 16)
			self.device.write_block(i, passwd, 2, "\x00" * 16)
			self.device.set_key(i, passwd, DEF_KEY, DEF_KEY)

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

	parser.add_argument("--admin", help = "load an admin card", action = "store_true")
	parser.add_argument("--write-pub", help = "initialize an admin card with public key", action = "store_true")
	parser.add_argument("--write-priv", help = "initialize an admin card with private key", action = "store_true")
	parser.add_argument("--wipe-admin", help = "wipe out an admin card", action = "store_true")

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

	if argv.admin:
		# eng.initAdminCard(2, "MIICYAIBAAKBgQCTCKuIZuVzMaZebKIC7eVacqElXFEDiPe8Xjt3KnF2wocutJJLImYx0dUwiZeSAJAp/fL3z49LNkQ1N/vpNml9B7pVeiYow+Lv8V2RV06CD9N6M5mJ4qNYg4uqLRU41RajQcGs9Pu4J/SnMxoacRlhB1Komp56HjoaVPlxzTN/tQIDAQABAoGAPjjPDlwtAYCjXRYvwXmXM52K4Fqe1hYicI6YL6fAeHd96Z/0wOL/yFl6FJ5FjD28xGh5Z7FofHWsi7DzHtwf1Wn8h2Fr3u8I1YZ8xqTP/NAXxQ958eFMKcG8jeASbOizIbrnOxbhw4PQ5hZLmjf1yUUSE/v/45FQPf3l6/MjngECRQCjh2T895yixUxPewxajoGxsYK943nkLMv2lYlP94Q+mhJBVmXtfdvaDHre3Jxfkvl/ANCsO4uJplNdq+qYU5BCH5HOdQI9AOYtcLdhDiNc7a15oGjTArIE2AocNX+8GIT6raLvH58/RhfbXaeIvsaRU3KeuiKRQ8BJpYq4DuzaKBtEQQJEOWeoHd1WURVtimEpnwhzossrmDkoat8G4pLv1vCOreMsEV+g/FO4P70tzNoo0qwnhVvl5PAqNbH7heB5w+thsrSeXJkCPFHHCyjbvp4pwffEIo2binWc6vSMmSVMuplkRpSAyIdXf5uyQE/pcX4y26b5ZcAqRBvpDnt+cS8NQvqNAQJFAIk2IW7j7MHdzRVmhj2KvO+14v744GpHaRTMHC2Tw8fIuvJKpcCWeW44sSctslljFpWIJ8VY/eDu4wfYrKMRWrHeoW97", "116879")
		print("waiting for admin card")
		eng.waitCard()

		passwd = getpass.getpass("password: ")
		ret = eng.readAdminCard(passwd)

		if not ret["suc"]:
			errmsg("failed to load admin card: " + ret["msg"])

		ctp = eng.applyAdminCard(ret["type"], ret["key"])
		print("a %s key is loaded" % ctp)

		eng.waitCardLeave()

	elif argv.write_pub:
		if not pub:
			errmsg("no public key found")
		with open(pub) as fp:
			print("waiting for empty card")
			eng.waitCard()
			
			key = "".join(fp.read().strip("\r\n").split("\n")[1:-1])
			# print(key)

			passwd = getpass.getpass("set password: ")
			repeat = getpass.getpass("repeat: ")
			if passwd != repeat:
				errmsg("different passwords")

			eng.initAdminCard(1, key, passwd)
			print("success")

		exit(0)

	elif argv.write_priv:
		if not priv:
			errmsg("no private key found")
		with open(priv) as fp:
			print("waiting for empty card")
			eng.waitCard()

			key = "".join(fp.read().strip("\r\n").split("\n")[1:-1])

			passwd = getpass.getpass("set password: ")
			repeat = getpass.getpass("repeat: ")
			if passwd != repeat:
				errmsg("different passwords")

			eng.initAdminCard(2, key, passwd)
			print("success")

		exit(0)

	elif argv.wipe_admin:
		print("waiting for admin card")
		eng.waitCard()
		if raw_input("Are you sure to wipe out the admin card? [N/y]: ").lower() == "y":
			passwd = getpass.getpass("password: ")
			eng.wipeAdmin(passwd)
			print("success")
		exit(0)

	if argv.wipe:
		print("waiting for card")
		eng.waitCard()
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
