#! /usr/bin/env python3

import os, sys, struct, serial
from functools import reduce

from util import *

# Command header
HEADER = b"\xAA\xBB"
# \x00\x00 according to API reference but only works with YHY632
# \xFF\xFF works for both.
RESERVED = b"\xFF\xFF"

# Serial commands
CMD_SET_BAUDRATE = 0x0101
CMD_SET_NODE_NUMBER = 0x0102
CMD_READ_NODE_NUMBER = 0x0103
CMD_READ_FW_VERSION = 0x0104
CMD_BEEP = 0x0106
CMD_LED = 0x0107
CMD_RFU = 0x0108 # Unused according to API reference
CMD_WORKING_STATUS = 0x0108 # Unused according to API reference
CMD_ANTENNA_POWER = 0x010C
# Request a type of card
#     data = 0x52: request all Type A card In field,
#     data = 0x26: request idle card
CMD_MIFARE_REQUEST = 0x0201
CMD_MIFARE_ANTICOLISION = 0x0202 # 0x04 -> <NUL> (00)     [4cd90080]-cardnumber
CMD_MIFARE_SELECT = 0x0203 # [4cd90080] -> 0008
CMD_MIFARE_HALT = 0x0204
CMD_MIFARE_AUTH2 = 0x0207 # 60[sector*4][key]
CMD_MIFARE_READ_BLOCK = 0x0208 #[block_number]
CMD_MIFARE_WRITE_BLOCK = 0x0209
CMD_MIFARE_INITVAL = 0x020A
CMD_MIFARE_READ_BALANCE = 0x020B
CMD_MIFARE_DECREMENT = 0x020C
CMD_MIFARE_INCREMENT = 0x020D
CMD_MIFARE_UL_SELECT = 0x0212

# Default keys
DEFAULT_KEYS = (
	b"\x00\x00\x00\x00\x00\x00",
	b"\xa0\xa1\xa2\xa3\xa4\xa5",
	b"\xb0\xb1\xb2\xb3\xb4\xb5",
	b"\x4d\x3a\x99\xc3\x51\xdd",
	b"\x1a\x98\x2c\x7e\x45\x9a",
	b"\xFF" * 6,
	b"\xd3\xf7\xd3\xf7\xd3\xf7",
	b"\xaa\xbb\xcc\xdd\xee\xff"
)

# Error codes
ERR_BAUD_RATE = 1
ERR_PORT_OR_DISCONNECT = 2
ERR_GENERAL = 10
ERR_UNDEFINED = 11
ERR_COMMAND_PARAMETER = 12
ERR_NO_CARD = 13
ERR_REQUEST_FAILURE = 20
ERR_RESET_FAILURE = 21
ERR_AUTHENTICATE_FAILURE = 22
ERR_READ_BLOCK_FAILURE = 23
ERR_WRITE_BLOCK_FAILURE = 24
ERR_READ_ADDRESS_FAILURE = 25
ERR_WRITE_ADDRESS_FAILURE = 26

# Mifare types
TYPE_MIFARE_UL = 0x4400
TYPE_MIFARE_1K = 0x0400
TYPE_MIFARE_4K = 0x0200
TYPE_MIFARE_DESFIRE = 0x4403
TYPE_MIFARE_PRO = 0x0800

class YHY523U:
	"""Driver for Ehuoyan"s YHY523U module"""

	def __init__(self, port = "/dev/ttyUSB0", baudrate = 115200, timeout = 3):
		self.port = port
		self.baudrate = baudrate
		self.ser = serial.Serial(self.port, baudrate = self.baudrate, timeout = timeout)

	def build_command(self, cmd, data):
		"""Build a serial command.

		Keyword arguments:
		cmd -- the serial command
		data -- the argument of the command

		"""
		length = 2 + 2 + 1 + len(data)

		body_raw = RESERVED + struct.pack("<H", cmd) + data
		body = b""

		for b in body_raw:
			# print(type(data))
			body += byte(b)
			if b == 0xAA:
				body += b"\x00"

		body_int = list(body)
		checksum = reduce(lambda x, y:  x ^ y, body_int)

		return HEADER + struct.pack("<H", length) + body + struct.pack("B", checksum)

	def get_n_bytes(self, n, handle_AA = False):
		"""Read n bytes from the device.

		Keyword arguments:
		n -- the number of bytes to read
		handle_AA -- True to handle \xAA byte differently, False otherwise

		"""
		buffer = b""
		# print(n)
		while 1:
			received = self.ser.read()

			if len(received) == 0:
				raise Exception("read timeout")

			if handle_AA:
				if received.find(b"\xAA\x00") >= 0:
					received = received.replace(b"\xAA\x00", b"\xAA")
				if received[0] == 0x00 and buffer[-1] == 0xAA:
					received = received[1:]
			buffer += received

			# print(buffer)
			# print("y " + str(len(buffer)))

			if len(buffer) >= n:
				return buffer

	def send_command(self, cmd, data):
		"""Send a serial command to the device.

		Keyword arguments:
		cmd -- the serial command
		data -- the argument of the command

		"""
		buffer = self.build_command(cmd, data)
		self.ser.write(buffer)
		self.ser.flush()

	def receive_data(self):
		"""Receive data from the device."""
		buffer = b""

		# Receive junk bytes
		prev_byte = b"\x00"
		while 1:
			cur_byte = self.ser.read(1)
			if prev_byte + cur_byte == HEADER:
				# Header found, breaking
				break
			prev_byte = cur_byte

		length = struct.unpack("<H", self.get_n_bytes(2))[0]
		packet = self.get_n_bytes(length, True)

		reserved, command = struct.unpack("<HH", packet[:4])
		data = packet[4:-1]
		checksum = packet[-1]

		packet_int = packet[:-1]
		checksum_calc = reduce(lambda x, y: x ^ y, packet_int)
		if data[0] == 0x00:
			if checksum != checksum_calc:
				raise Exception("bad checksum")
				
		return command, data

	def send_receive(self, cmd, data):
		"""Send a serial command to the device and receive the answer.

		Keyword arguments:
		cmd -- the serial command
		data -- the argument of the command

		"""
		self.send_command(cmd, data)
		cmd_received, data_received = self.receive_data()
		if cmd_received != cmd:
			raise Exception("the command in answer is bad!")
		else:
			return data_received[0], data_received[1:]

	def has_card(self):
		status, card_type = self.send_receive(CMD_MIFARE_REQUEST, b"\x52")
		return status == 0

	def select(self):
		"""Select a Mifare card. (Needed before any reading/writing operation)
		Return the type and the serial of a Mifare card.

		"""
		status, card_type = self.send_receive(CMD_MIFARE_REQUEST, b"\x52")
		if status != 0:
			raise Exception("no card found")

		status, serial = self.send_receive(CMD_MIFARE_ANTICOLISION, b"\x04")
		if status != 0:
			raise Exception("error in anticollision")

		card_type = struct.unpack(">H", card_type)[0]
		if card_type == TYPE_MIFARE_UL:
			status, serial = self.send_receive(CMD_MIFARE_UL_SELECT, b"")
		else:
			self.send_receive(CMD_MIFARE_SELECT, serial)

		return card_type, serial

	def halt(self):
		"""Halt the device."""
		status, data = self.send_receive(CMD_MIFARE_HALT, "")
		return status, data

	def read_sector(self, sector = 0, keya = b"\xff" * 6, blocks = (0, 1, 2,)):
		"""Read a sector of a Mifare card.

		Keyword arguments:
		sector -- the sector index (default: 0)
		keya -- the key A
		blocks -- the blocks to read in the sector

		"""

		self.send_receive(CMD_MIFARE_AUTH2, b"\x60" + byte(sector * 4) + keya)
		results = b""
		
		for block in blocks:
			status, data = self.send_receive(CMD_MIFARE_READ_BLOCK, byte(sector * 4 + block))
			if status != 0:
				raise Exception("errno: %d" % status)
			results += data

		return results

	def read_block(self, sector, keya, block):
		self.send_receive(CMD_MIFARE_AUTH2, b"\x60" + byte(sector * 4) + keya)
		
		status, data = self.send_receive(CMD_MIFARE_READ_BLOCK, byte(sector * 4 + block))
		if status != 0:
			raise Exception("errno: %d" % status)

		return data

	def auth_block(self, sector, keya):
		suc = 0

		try:
			self.read_block(sector, keya, 0)
			suc = 1
		except: pass

		return suc

	def write_block(self, sector = 0, keya = b"\xff" * 6, block = 0, data = b"\x00" * 16):
		"""Write in a block of a Mifare card.

		Keyword arguments:
		sector -- the sector index (default: 0)
		keya -- the key A
		block -- the block to write on in the sector (default: 0)
		data -- the data string to be written

		"""
		self.send_receive(CMD_MIFARE_AUTH2, b"\x60" + byte(sector * 4) + keya)
		
		status, result = self.send_receive(CMD_MIFARE_WRITE_BLOCK, byte(sector * 4 + block) + data)
		if status != 0:
			raise Exception("errno: %d" % status)

		return result

	def set_key(self, sector, keya, nkeya, nkeyb):
		self.send_receive(CMD_MIFARE_AUTH2, b"\x60" + byte(sector * 4) + keya)

		data = nkeya + b"\xff\x07\x80\x69" + nkeyb

		status, result = self.send_receive(CMD_MIFARE_WRITE_BLOCK, byte(sector * 4 + 3) + data)
		if status != 0:
			raise Exception("errno: %d" % status)

		return result

	def dump(self, keya = b"\xff" * 6):
		"""Dump a Mifare card.

		Keyword arguments:
		keya -- the key A

		"""
		self.select()
		for sector in range(0, 16):
			# cont = "auth failed"

			try:
				cont = "\n" + to_hex_mat(self.read_sector(sector, keya))
			except:
				cont = "auth failed"

			print("sector %d: %s" % (sector, cont))

	def dump_access_conditions(self, keya = b"\xff" * 6):
		"""Dump the access conditions (AC) of a Mifare card.

		Keyword arguments:
		sector -- the sector index (default: 0)
		keya -- the key A

		"""
		self.select()
		for sector in range(0, 16):
			try:
				ac = buffer(self.read_sector(sector, keya, (3,)), 6, 3)
				print("ACs for sector %d:" % sector, to_hex(ac))
			except:
				print("Unable to read ACs for sector %d" % sector)

	def get_fw_version(self):
		"""Return the firmware version of the device."""
		status, data = self.send_receive(CMD_READ_FW_VERSION, "")
		return data

	def get_node_number(self):
		"""Return the node number of the device."""
		status, data = self.send_receive(CMD_READ_NODE_NUMBER, "")
		return data

	def set_node_number(self, number):
		"""Set the node number of the device.

		Keyword arguments:
		number -- the node number

		"""
		status, data = self.send_receive(CMD_SET_NODE_NUMBER, struct.pack("<H", number))
		return data

	def beep(self, delay=10):
		"""Make the device beeping.

		Keyword arguments:
		delay -- the beep duration in milliseconds (default: 10)

		"""
		status, data = self.send_receive(CMD_BEEP, byte(delay))
		if status == 0:
			return 1
		else:
			return 0

	def set_led(self, led = "off"):
		"""Light the LED of the device.

		Keyword arguments:
		led -- the LED to be lighted, can be: "red", "blue", "both" or "off" (default: "off")

		"""
		if led == "blue":
			data = b"\x01"
		elif led == "red":
			data = b"\x02"
		elif led == "both":
			data = b"\x03"
		else:
			data = b"\x00"

		return self.send_receive(CMD_LED, data)[0] == 0

	def set_baudrate(self, rate = 19200):
		"""Set the baud rate of the device.

		Keyword arguments:
		rate -- the baud rate (default: 19200)

		"""
		if rate == 19200:
			data = b"\x03"
		elif rate == 28800:
			data = b"\x04"
		elif rate == 38400:
			data = b"\x05"
		elif rate == 57600:
			data = b"\x06"
		elif rate == 115200:
			data = b"\x07"
		else:
			data = b"\x01"

		return self.send_receive(CMD_SET_BAUDRATE, data)[0] == 0

if __name__ == "__main__":
	import time

	device = YHY523U("/dev/ttyUSB0", 115200)
	last_serial = None

	device.select()

	# "\x35\x12\x44\x5c\xdd\xc6"
	# "\x1b\x6f\x74\xc0\x8b\x2d"
	# "\xde\xce\x8c\x29\x2d\xef"
	# "\x8d\x0b\xe2\x9e\x45\x3a"
	# "\x8d\x9f\xf6\x1a\x35\xe2"
	# device.set_key(3, "\x8d\x9f\xf6\x1a\x35\xe2", "\xff" * 6, "\xff" * 6)
	# device.write_block(3, "\xff" * 6, 0, "\x00" * 16)
	# device.write_block(2, "\xff" * 6, 0, "\x00" * 16)

	# device.init_balance(1, "\xff" * 6, 0, 10)
	# device.increase_balance(1, "\xff" * 6, 0, 2)

	while 1:
		try:
			while device.select()[1] == last_serial:
				time.sleep(0.1)
			
			card_type, serial = device.select()
			last_serial = serial

			print("find card:", card_type, "- serial:", to_hex(serial))

			device.dump()
			# device.dump_access_conditions()

			# print to_hex(device.read_sector(4, "\xe8\x0b\x65\xd4\xca"))
			# print to_hex(device.read_sector(2, "\x2f\x6b\x6f\xff\x5c\x35"))

			# device.write_block(13, "\xee" * 6, 0, "\x00" * 16)

			# device.set_key(13, "\xee" * 6, "\xee" * 6, "\xee" * 6)

			# device.test_keys(15)
		except KeyboardInterrupt:
			raise KeyboardInterrupt()
		# except: pass
		finally: pass

		time.sleep(0.1)
