import format
import urllib
import json

from util import *
from http.server import *

DEF_CONT_TYPE_MAP = {
	"js": "application/x-javascript",
	"css": "text/css",
	"html": "text/html"
}

port = format.SDEngine.searchCOM()

if port == None:
	raise Exception("unable to find device")

print("found device at " + port)

eng = format.SDEngine(port)

def INT_hascard(self, query):
	self.setHeader(status = 400)
	self.response(json.dumps({ "suc": True, "data": eng.hasCard() }))

def INT_check(self, query):
	res = eng.verify()
	self.setHeader(status = 400)
	self.response(json.dumps(res))

# wait and check
def INT_wcheck(self, query):
	eng.waitCard()
	res = eng.verify()
	self.setHeader(status = 400)
	self.response(json.dumps(res))

DEF_INT_MAP = {
	"hascard": INT_hascard,
	"check": INT_check,
	"wcheck": INT_wcheck
}

class UIHandler(BaseHTTPRequestHandler):
	def parseQuery(self):
		res = urllib.parse.urlparse(self.path)
		self.parse = {
			"path": res.path,
			"query": res.query
		}

		return self.parse

	def setHeader(self, head = {}, status = 200, version = b"HTTP/1.1"):
		self.protocal_version = version
		self.send_response(status)

		for key in head:
			self.send_header(key, head[key])
		
		self.end_headers()

	def response(self, cont):
		self.wfile.write(cont.encode("utf-8"))

	def routeStatic(self, pref):
		# print(self.parse)
		path = self.parse["path"]

		if path.find(pref) == 0:
			with open(path[1:]) as fp:
				suf = path.split(".")[-1]

				if suf in DEF_CONT_TYPE_MAP:
					self.setHeader({ "Content-Type": DEF_CONT_TYPE_MAP[suf] })

				self.response(fp.read())

			return True
		else:
			return False

	def do_GET(self):
		try:
			self.parseQuery()

			if self.routeStatic("/ui/"): return

			if self.parse["path"] == "/":
				# main page
				self.setHeader({
					"Content-Type": "text/html"
				})

				with open("ui/main.html") as fp:
					self.response(fp.read())
			else:
				cmd = self.parse["path"][1:].split("/")
				print(cmd)

				if cmd[0] == "int" and \
				   len(cmd) > 1 and \
				   cmd[1] in DEF_INT_MAP:
					DEF_INT_MAP[cmd[1]](self, self.parse["query"])
				else:
					self.setHeader(status = 404)
					self.response("page missing " + self.parse["path"])
		# except:
		#	self.setHeader(status = 500)
		#	self.response("something wrong inside")
		finally: pass

addr = "127.0.0.1", int(3134)
server = HTTPServer(addr, UIHandler)
server.serve_forever()
