#!/usr/bin/env python
import base64, re, socket, socketserver, sys, threading, urllib.request, urllib.error, urllib.parse
from config import *

class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
	"""TCPServer with ThreadingMixIn added."""
	pass

class Handler(socketserver.BaseRequestHandler):
	"""Main request handler."""
	def handle(self):
		"""Handle a request."""
		global DATE
		
		# readline is pretty convenient
		f = self.request.makefile()
		
		# read request line
		reqline = line = f.readline()
		split = line.rstrip('\r\n').split(' ')
		http_version = len(split) > 2 and split[2] or 'HTTP/0.9'
		
		if split[0] != 'GET':
			# only GET is implemented
			return self.error_page(http_version, 501, 'Not Implemented')
		
		# parse the URL
		request_url = split[1]
		parsed = urllib.parse.urlparse(request_url)
		
		# make a path
		path = parsed.path
		if parsed.query != '': path += '?' + parsed.query
		if path == '': path == '/'
		
		# get the hostname for later
		host = parsed.netloc.split(':')
		hostname = host[0]
		
		# read out the headers, saving the PAC file host
		pac_host = '" + location.host + ":' + str(LISTEN_PORT) # may not actually work
		while line.rstrip('\r\n') != '':
			line = f.readline()
			if line[:6].lower() == 'host: ':
				pac_host = line[6:].rstrip('\r\n')
				if ':' not in pac_host: # who would run this on port 80 anyway?
					pac_host += ':80'
			elif line[:21].lower() == 'x-waybackproxy-date: ':
				# API for a personal project of mine
				new_date = line[21:].rstrip('\r\n')
				if DATE != new_date:
					DATE = new_date
					print('[-] Header requested date', DATE)
		
		try:
			if path == '/proxy.pac':
				# PAC file to bypass QUICK_IMAGES requests
				pac  = http_version.encode('ascii', 'ignore') + b''' 200 OK\r\n'''
				pac += b'''Content-Type: application/x-ns-proxy-autoconfig\r\n'''
				pac += b'''\r\n'''
				pac += b'''function FindProxyForURL(url, host)\r\n'''
				pac += b'''{\r\n'''
				pac += b'''	if (shExpMatch(url, "http://web.archive.org/web/*"))\r\n'''
				pac += b'''	{\r\n'''
				pac += b'''		return "DIRECT";\r\n'''
				pac += b'''	}\r\n'''
				pac += b'''	return "PROXY ''' + pac_host.encode('ascii', 'ignore') + b'''";\r\n'''
				pac += b'''}\r\n'''
				self.request.sendall(pac)
				return
			elif hostname == 'web.archive.org':
				if path[:5] != '/web/':
					# launch settings
					return self.handle_settings(parsed.query)
				else:
					# pass-through requests to web.archive.org
					# required for QUICK_IMAGES
					_print('[>] [QI] {0}'.format('/'.join(request_url.split('/')[5:])))
					conn = urllib.request.urlopen(request_url)
			elif GEOCITIES_FIX and hostname == 'www.geocities.com':
				# apply GEOCITIES_FIX and pass it through
				split = request_url.split('/')
				hostname = split[2] = 'www.oocities.org'
				request_url = '/'.join(split)
				
				_print('[>] {0}'.format(request_url))
				conn = urllib.request.urlopen(request_url)
			else:
				# get from Wayback
				_print('[>] {0}'.format(request_url))
				conn = urllib.request.urlopen('http://web.archive.org/web/{0}/{1}'.format(DATE, request_url))
		except urllib.error.HTTPError as e:
			# an error has been found

			# 403 or 404 => heuristically determine the static URL for some redirect scripts
			if e.code in (403, 404):
				match = re.search('''(?:\?|&)(?:target|trg|dest(?:ination)?|to)(?:url)?=(http[^&]+)''', request_url, re.IGNORECASE)
				if match:
					# we found it
					new_url = urllib.parse.unquote_plus(match.group(1))
					_print('[r]', new_url)
					return self.redirect_page(http_version, new_url)

			_print('[!] {0} {1}'.format(e.code, e.reason))
			return self.error_page(http_version, e.code, e.reason)
		
		# get content type
		content_type = conn.info().get('Content-Type')
		if not CONTENT_TYPE_ENCODING and content_type.find(';') > -1: content_type = content_type[:content_type.find(';')]
		
		# send headers		
		self.request.sendall(http_version.encode('ascii', 'ignore') + b' 200 OK\r\nContent-Type: ' + content_type.encode('ascii', 'ignore') + b'\r\n\r\n')
		
		# set the mode: [0]wayback [1]oocities
		mode = 0
		if GEOCITIES_FIX and hostname in ['www.oocities.org', 'www.oocities.com']: mode = 1
		
		if content_type[:9] == 'text/html' in content_type: # HTML
			toolbar = mode == 1 # oocities header starts without warning
			redirect_page = False
			for line in conn:
				line = line.rstrip(b'\r\n')
				
				if mode == 0:
					if toolbar:
						for delimiter in (b'<\!-- END WAYBACK TOOLBAR INSERT -->', b'<\!-- End Wayback Rewrite JS Include -->'):
							if re.search(delimiter, line):
								# toolbar is done - resume relaying on the next line
								toolbar = False
								line = re.sub(delimiter, b'', line)
								break
						if toolbar: continue
					elif redirect_page:
						# this is a really bad way to deal with Wayback's 302
						# pages, but necessary with the way this proxy works
						match = re.search(b'<p class="impatient"><a href="/web/(?:[^/]+)/([^"]+)">Impatient\\?</a></p>', line)
						if match:
							line  = b'<title>WaybackProxy Redirect</title><meta http-equiv="refresh" content="0;url='
							line += match.group(1)
							line += b'"></head><body>If you are not redirected, <a href="'
							line += match.group(1)
							line += b'">click here</a>.</body></html>'
							self.request.sendall(line)
							break
						continue
					
					if b'<base ' in line.lower():
						# fix base
						line = re.sub(b'(?:http://web\.archive\.org)?/web/([0-9]+)/', b'', line)
					elif line == b'\t\t<title>Internet Archive Wayback Machine</title>':
						# redirect 302s - see the redirect_page code above
						redirect_page = True
						continue
					else:
						for delimiter in (
							b'<\!-- BEGIN WAYBACK TOOLBAR INSERT -->',
							b'<script src="//archive\.org/([^"]+)" type="text/javascript"></script>'
						):
							if re.search(delimiter, line):
								# remove the toolbar - stop relaying from now on
								toolbar = True
								line = re.sub(delimiter, b'', line)
								break
					
					if QUICK_IMAGES:
						# QUICK_IMAGES works by intercepting asset URLs (those
						# with a date code ending in im_, js_...) and letting the
						# proxy pass them through. This may reduce load time
						# because Wayback doesn't have to hunt down the closest
						# copy of that asset to DATE, as those URLs have specific
						# date codes. The only side effect is tainting the HTML
						# with web.archive.org URLs.
						line = re.sub(b'(?:http://web.archive.org)?/web/([0-9]+)([a-z]+_)/',
							b'http://web.archive.org/web/\\1\\2/', line)
						line = re.sub(b'(?:http://web.archive.org)?/web/([0-9]+)/', b'', line)
					else:
						line = re.sub(b'(?:http://web.archive.org)?/web/([^/]+)/', b'', line)
				elif mode == 1:
					# remove the geocities/oocities-added code, which is
					# conveniently wrapped around comments
					if toolbar:
						if line in (
							b'<!-- text above generated by server. PLEASE REMOVE -->',
							b'<!-- preceding code added by server. PLEASE REMOVE -->'
						):
							toolbar = False
						continue
					elif line == b'<!-- following code added by server. PLEASE REMOVE -->' \
					or line[:54] == b'<!-- text below generated by server. PLEASE REMOVE -->':
						toolbar = True
						continue
					
					# taint? what taint?
					line = line.replace(b'http://oocities.com', b'http://geocities.com')
					line = line.replace(b'http://www.oocities.com', b'http://www.geocities.com')
				
				self.request.sendall(line)
				self.request.sendall(b'\r\n')
		else: # other data
			while True:
				data = conn.read(1024)
				if not data: break
				self.request.sendall(data)
		
		self.request.close()
	
	def error_page(self, http_version, code, reason):
		"""Generate an error page."""
		
		# make error page
		errorpage = '<html><head><title>{0} {1}</title></head><body><h1>{1}</h1><p>'.format(code, reason)
		
		# add code information
		if code == 404: # page not archived
			errorpage += 'This page may not be archived by the Wayback Machine.'
		elif code == 403: # not crawled due to robots.txt
			errorpage += 'This page was not archived due to a robots.txt block.'
		elif code == 501: # method not implemented
			errorpage += 'WaybackProxy only implements the GET method.'
		else: # another error
			errorpage += 'Unknown error. The Wayback Machine may be experiencing technical difficulties.'
		
		errorpage += '</p><hr><i>'
		errorpage += self.signature()
		errorpage += '</i></body></html>'
		
		# send error page and stop
		self.request.sendall('{0} {1} {2}\r\nContent-Type: text/html\r\nContent-Length: {3}\r\n\r\n{4}'.format(http_version, code, reason, len(errorpage), errorpage).encode('utf8', 'ignore'))
		self.request.close()

	def redirect_page(self, http_version, target, code=302):
		"""Generate a redirect page."""

		# make redirect page
		redirectpage  = '<html><head><title>Redirect</title><meta http-equiv="refresh" content="0;url='
		redirectpage += target
		redirectpage += '"></head><body><p>If you are not redirected, <a href="'
		redirectpage += target
		redirectpage += '">click here</a>.</p></body></html>'

		# send redirect page and stop
		self.request.sendall('{0} {1} Found\r\nLocation: {2}\r\nContent-Type: text/html\r\nContent-Length: {3}\r\n\r\n'.format(http_version, code, target, len(redirectpage), redirectpage).encode('utf8', 'ignore'))
		self.request.close()
	
	def handle_settings(self, query):
		"""Generate the settings page."""
	
		global DATE, GEOCITIES_FIX, QUICK_IMAGES, CONTENT_TYPE_ENCODING
		
		if query != '': # handle any parameters that may have been sent
			parsed = urllib.parse.parse_qs(query)
			
			if 'date' in parsed: DATE = parsed['date'][0]
			GEOCITIES_FIX = 'gcFix' in parsed
			QUICK_IMAGES = 'quickImages' in parsed
			CONTENT_TYPE_ENCODING = 'ctEncoding' in parsed
		
		# send the page and stop
		settingspage  = 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n'
		settingspage += '<html><head><title>WaybackProxy Settings</title></head><body><p><b>'
		settingspage += self.signature()
		settingspage += '</b></p><form method="get" action="/"><p>Date to get pages from: <input type="text" name="date" size="8" value="'
		settingspage += DATE
		settingspage += '"><br><input type="checkbox" name="gcFix"'
		if GEOCITIES_FIX: settingspage += ' checked'
		settingspage += '> Geocities Fix<br><input type="checkbox" name="quickImages"'
		if QUICK_IMAGES: settingspage += ' checked'
		settingspage += '> Quick images<br><input type="checkbox" name="ctEncoding"'
		if CONTENT_TYPE_ENCODING: settingspage += ' checked'
		settingspage += '> Encoding in Content-Type</p><p><input type="submit" value="Save"></p></form></body></html>'
		self.request.send(settingspage.encode('utf8', 'ignore'))
		self.request.close()
	
	def signature(self):
		"""Return the server signature."""
		return 'WaybackProxy on {0}'.format(socket.gethostname())

print_lock = threading.Lock()
def _print(*args, linebreak=True):
	"""Logging function."""
	s = ' '.join(args)
	print_lock.acquire()
	sys.stdout.write(linebreak and (s + '\n') or s)
	sys.stdout.flush()
	print_lock.release()

def main():
	"""Starts the server."""
	server = ThreadingTCPServer(('', LISTEN_PORT), Handler)
	_print('[-] Now listening on port {0}'.format(LISTEN_PORT))
	try:
		server.serve_forever()
	except KeyboardInterrupt: # Ctrl+C to stop
		pass

if __name__ == '__main__':
	main()