import http.server

import html
import http.client
import io
import mimetypes
import os
import posixpath
import select
import shutil
import socket # For gethostbyaddr()
import socketserver
import sys
import time
import urllib.parse
import copy
import argparse

proxied_server = "example.com"
proxy_address = "localhost:8080"
csp_value = "default-src 'none'"
csp_file_path = "csp-string"

class ProxyHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
	def handle_one_request(self):
		"""Handle a single HTTP request

		Modified version of standard libraries BaseHTTPRequestHandlers handle_one_request() to be used as a reverse proxy.
		"""
		try:
			self.raw_requestline = self.rfile.readline(65537)
			if len(self.raw_requestline) > 65536:
				self.requestLine = ''
				self.request_version = ''
				self.command = ''
				self.send_error(http.client.REQUEST_URI_TOO_LONG)
				return
			if not self.raw_requestline:
				self.close_connection = True
				return
			if not self.parse_request():
				return

			# Fetching the site from the server
			server_conn = http.client.HTTPConnection(proxied_server)
			# Copy the Headers directly
			server_conn.putrequest(self.command, self.path, skip_host = True, skip_accept_encoding = True);
			for header_field in self.headers:
				# print(header_field + ": " + self.headers.get(header_field))
				if not (header_field == "Host"):
					server_conn.putheader(header_field, self.headers.get(header_field))
				else:
					server_conn.putheader(header_field, proxied_server)
			server_conn.endheaders()

			r1 = server_conn.getresponse()
			
			# Forward the fetched message (including headers) to the client

			self.send_response(r1.status)
			for (hn, hv) in r1.getheaders():
				self.send_header(hn, hv)

			# Adding the CSP-Header
			csp_file = open(csp_file_path)
			csp_value = csp_file.readline()
			print(csp_value)
			csp_file.close()

			self.send_header("Content-Security-Policy", csp_value)
			self.end_headers()

			a = r1.read()
			self.wfile.write(a)
			server_conn.close()
			
		except socket.timeout as e:
			self.log_error("Request timed out: %r", e)
			self.close_connection = True
			return

	def send_response(self, code, message=None):
		"""Send the response header
		Modified version of the original send_response, with a simplified send_response_only included.
		"""
		self.log_request(code)
		#self.send_response_only(code, message)
		if not hasattr(self, '_headers_buffer'):
			self._headers_buffer = []
		self._headers_buffer.append(("%s %d %s\r\n" %(self.protocol_version, code, message)).encode('latin-1', 'strict'))

		#self.send_header('Server', self.version_string())
		#self.send_header('Date', self.date_time_string())
			


def run(server_class=http.server.HTTPServer, handler_class=http.server.BaseHTTPRequestHandler):
	server_address = ('', 8080)
	httpd = server_class(server_address, handler_class)
	httpd.serve_forever()

if len(sys.argv) >= 2:
	proxied_server = sys.argv[1]
	run(handler_class=ProxyHTTPRequestHandler)
