import urllib

from util import *
from http.server import *

DEF_CONT_TYPE_MAP = {
	"js": "application/x-javascript",
	"css": "text/css",
	"html": "text/html"
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
			print(self.parseQuery())

			if self.routeStatic("/ui/"): return

			if self.parse["path"] == "/":
				# main page
				self.setHeader({
					"Content-Type": "text/html"
				})

				with open("ui/main.html") as fp:
					self.response(fp.read())
			else:
				self.setHeader(status = 404)
				self.response("page missing")
		# except:
		#	self.setHeader(status = 500)
		#	self.response("something wrong inside")
		finally: pass

addr = "127.0.0.1", int(3134)
server = HTTPServer(addr, UIHandler)
server.serve_forever()
