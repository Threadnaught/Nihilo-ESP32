from http import server

data = "\n"

class NihAddressHanlder(server.BaseHTTPRequestHandler):
	def do_GET(self):
		global data
		self.wfile.write(data.encode())
		self.send_response(200)
	def do_POST(self):
		global data
		data = data + self.rfile.read(int(self.headers['Content-Length'])).decode() + "\n"
		self.send_response(200)
		self.end_headers()
		

svr = server.HTTPServer(('',80), NihAddressHanlder)
svr.serve_forever()