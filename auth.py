import rsa
import struct
from util import *

keymap = [
	b"e787a360289446eb", b"7a592de8cc39020e", b"b86dc740a760f2e5", b"9ee4b1a1b364050e",
	b"f44ad3f218438afd", b"98bbac6b89060f71", b"58d3be3ea90ab87d", b"cece3a46e37be125",
	b"8051bac2235ece40", b"0f566aaff18d7976", b"7dfb35abf0d94c83", b"b5b8ef687f79a49f",
	b"69e2e0b5a96929f8", b"9442c17251ed112b", b"97da9ef5f9c1e450", b"9aba4145d2a222ca",
	b"53ccd3cffe2ae2ff", b"bab69b76720b0237", b"98c8c2e3b75bfadf", b"b9bf056b3c10008d",
	b"def9aff3699f18b9", b"b107aa5ee856a574", b"d6fe7a9010439b39", b"d24f273d35cdef8b",
	b"7232a820fb85f0b5", b"92aa2e1165d0d93d", b"7fcf62bf5c86de43", b"bbee2e7504ca13ec",
	b"36bd8afd3141a5f3", b"f4d0eba594ef5f92", b"fc8a914e3426eb13", b"0e0f176c611bec35",
	b"80cc3a2a52795143", b"0486ec528ca679e5", b"f760eb19c5163834", b"7991373e04a0728f",
	b"4fb0dcfcdb421bf9", b"a648b39b7638b029", b"822d04c3b62278d2", b"e59f4feefdbe847f",
	b"a768264c18296a97", b"162ff5f1867ad99e", b"c0afafcd7ed7597d", b"38fd53363158a7d1",
	b"8e8eadb05a1cc4da", b"32a6f0acedf3b6ec", b"99f0d09a65ecfeb9", b"6e242eecc41a562b",
	b"070c4cf0972c7539", b"7f7a06edd40bda6d", b"ffe24ebf336186a4", b"3ee43a47048bb37f",
	b"1006dbe0fc243885", b"04465c675c819b04", b"e32a5f16e37417f4", b"18c5b2a0d920ff45",
	b"3a1e62d6e3094411", b"6f604c09dc3d7ef1", b"ca39a1adf440adc6", b"5ab777b8d9a7896c",
	b"3891cfe06673bf09", b"952d98845ac97bc0", b"226dd8f7b26c6db6", b"dfb862b6a635ccb2"
]

def pack(uid, ofs, serial, value = 0):
	return (struct.pack("<III", uid, ofs, value) + serial +
			keymap[struct.unpack("<I", serial)[0] % 64])

class SDEnc:
	def __init__(self):
		self.pub = None
		self.priv = None

	def loadPub(self, path):
		with open(path) as fp:
			self.pub = rsa.PublicKey.load_pkcs1(fp.read())

	def loadPriv(self, path):
		with open(path) as fp:
			self.priv = rsa.PrivateKey.load_pkcs1(fp.read())

	def loadPubKey(self, key):
		self.pub = rsa.PublicKey.load_pkcs1(key)

	def loadPrivKey(self, key):
		self.priv = rsa.PrivateKey.load_pkcs1(key)

	def sign(self, uid, ofs, serial, value):
		if self.priv == None:
			raise Exception("require a private key")

		msg = pack(uid, ofs, serial, value)
		enc = rsa.sign(msg, self.priv, "SHA-1")

		return enc

	def verify(self, sign, uid, ofs, serial, value):
		if self.pub == None:
			raise Exception("require a public key")

		msg = pack(uid, ofs, serial, value)
		try:
			rsa.verify(msg, sign, self.pub)
		except:
			return False

		return True

	def hasPub(self):
		return self.pub != None

	def hasPriv(self):
		return self.priv != None

	@staticmethod
	def genKey(pub = "sdenc.pub", priv = "sdenc.priv"):
		(pubk, privk) = rsa.newkeys(1024)

		with open(pub, "w") as fp:
			fp.write(pubk.save_pkcs1())

		with open(priv, "w") as fp:
			fp.write(privk.save_pkcs1())

def keygen(uid, ofs, serial): # serial: a byte string
	return md5(pack(uid, ofs, serial), 6)

# SDEnc.genKey()

"""
enc = SDEnc()

enc.loadPriv("sdenc.priv")
enc.loadPub("sdenc.pub")
sign = enc.sign(1, 0, b"\xff\xee\xff\xee", 5)

print(to_hex(sign))

print(enc.verify(sign, 1, 0, b"\xff\xee\xff\xee", 2))
"""
