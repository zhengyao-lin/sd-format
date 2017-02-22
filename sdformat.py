import struct, time
from util import *
from yhy523u import *

DEF_KEY = "\xff" * 6

ALLOW_VALUE = (0, 20, 50, 100)

with open("km0.1") as fp:
	keymap = eval(fp.read())

def serial2num(serial):
	b = [ ord(c) for c in serial ]
	return b[3] << 24 | b[2] << 16 | b[1] << 8 | b[0]

def keygen01(ref, serial):
	return md5(keymap[ref % 64] + serial + str(ref), 6)

def keygen02(uid, serial): # serial: a byte string
	return md5(str(uid) + serial + keymap[serial2num(serial) % 64], 6)

class SDFormat:
	def __init__(self, port):
		self.device = YHY523U(port)

	def initCard01(self, uid = 1, value = 0, version = 1): # all required blocks must has a key of "\xff" * 6
		card_type, serial = self.device.select()

		self.device.write_block(1, DEF_KEY, 0, struct.pack("<IIII", 0, timestamp(), 0, 0))
		self.device.write_block(2, DEF_KEY, 0, struct.pack("<IIII", uid, value, version, 0))
		self.device.write_block(2, DEF_KEY, 1, "\x00" * 16)

		key = keygen01(0, serial)
		self.device.set_key(2, DEF_KEY, key, key)

		print(to_hex(key))

	def initCard02(self, uid = 1, value = 0, version = 1):
		card_type, serial = self.device.select()

		ofs = 0
		self.device.init_balance(1, DEF_KEY, 0, ofs) # offset

		self.device.write_block(ofs + 2, DEF_KEY, 0, struct.pack("<IIII", uid, 0, 0, 0)) # uid
		self.device.init_balance(ofs + 2, DEF_KEY, 1, 0) # ref
		self.device.write_block(ofs + 2, DEF_KEY, 2, "\x00" * 16) # key

		key = keygen02(uid, serial)
		self.device.write_block(ofs + 3, DEF_KEY, 0, struct.pack("<IIII", value, version, 0, 0))
		self.device.set_key(ofs + 3, DEF_KEY, key, key)

		print(to_hex(key))

	def has_card(self):
		return self.device.has_card()

	# return: value
	def validate01(self):
		suc = 0
		value = -1
		ref = -1

		try:
			card_type, serial = self.device.select()
			
			b10 = list(struct.unpack("<IIII", self.device.read_block(1, DEF_KEY, 0)))

			key = keygen01(b10[0], serial)

			if not self.device.auth_block(2, key):
				# probably corrupted, try last three ref
				print "corrupted"
				for i in range(3):
					key = keygen01(b10[0] - i - 1, serial)
					if self.device.auth_block(2, key):
						print "suc"

			b10[0] += 1 # ref++
			b10[1] = timestamp()

			nkey = keygen01(b10[0], serial)

			b20 = struct.unpack("<IIII", self.device.read_block(2, key, 0))
			if not b20[1] in ALLOW_VALUE:
				raise Exception, "illegal value"

			self.device.write_block(1, DEF_KEY, 0, struct.pack("<IIII", *b10))
			self.device.set_key(2, key, nkey, nkey)

			suc = 1
			value = b20[1]
			ref = b10[0]
		except: pass
		# finally: pass

		return (suc, value, ref)

	def validate02(self):
		try:
			card_type, serial = self.device.select()
			# print to_hex(self.device.read_balance(1, DEF_KEY, 0))
			self.device.increase_balance(1, DEF_KEY, 0, 100)
			ofs = struct.unpack("<I", self.device.read_balance(1, DEF_KEY, 0))[0]
			print ofs

		# except: pass
		finally: pass

# print(timestamp())
# print to_hex(keygen(123, "123"))

sd = SDFormat("/dev/ttyUSB0")

# 2f6b6fff5c35
# 8d 0b e2 9e 45 3a

# sd.initCard02(2, 20)

# print sd.validate()

while 1:
	if sd.has_card():
		print sd.validate02()
	time.sleep(0.1)
