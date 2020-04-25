from http import server

data = []


class NihAddressHanlder(server.BaseHTTPRequestHandler):
	def do_GET(self):
		global data
		tosend = data
		output_raw = str(len(tosend)) + '\n' + '\n'.join([x[0] + ':' + x[1] for x in tosend])
		self.wfile.write(output_raw.encode())
		self.send_response(200)
	def do_POST(self):
		global data
		input_raw = self.rfile.read(int(self.headers['Content-Length'])).decode()
		IP, ID = input_raw.split(':')
		data = [x for x in data if x[0] != IP and x[1] != ID] #remove duplicates
		data.append((IP,ID))
		self.send_response(200)
		self.end_headers()
		

svr = server.HTTPServer(('',80), NihAddressHanlder)
svr.serve_forever()