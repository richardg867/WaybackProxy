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
		request_url = archived_url = split[1]
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
		auth = None
		while line.rstrip('\r\n') != '':
			line = f.readline()
			ll = line.lower()
			if ll[:6] == 'host: ':
				pac_host = line[6:].rstrip('\r\n')
				if ':' not in pac_host: # who would run this on port 80 anyway?
					pac_host += ':80'
			elif ll[:21] == 'x-waybackproxy-date: ':
				# API for a personal project of mine
				new_date = line[21:].rstrip('\r\n')
				if DATE != new_date:
					DATE = new_date
					print('[-] Header requested date', DATE)
			elif ll[:21] == 'authorization: basic ':
				# asset date code passed as username:password
				auth = base64.b64decode(ll[21:])
		
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
			elif hostname == 'web.archive.org' or auth:
				if path[:5] != '/web/':
					# launch settings
					return self.handle_settings(parsed.query)
				else:
					# pass-through requests to web.archive.org
					# required for QUICK_IMAGES

					# did we get an username:password with an asset date code?
					if auth:
						request_url = 'http://web.archive.org/web/{0}/{1}'.format(auth.replace(':', ''), archived_url)
					else:
						archived_url = '/'.join(request_url.split('/')[5:])

					_print('[>] [QI] {0}'.format(archived_url))
					try:
						conn = urllib.request.urlopen(request_url)
					except urllib.error.HTTPError as e:
						if e.code == 404:
							# Try this file on another date, might be redundant
							return self.redirect_page(http_version, archived_url)
						else:
							raise e
			elif GEOCITIES_FIX and hostname == 'www.geocities.com':
				# apply GEOCITIES_FIX and pass it through
				_print('[>] {0}'.format(archived_url))

				split = archived_url.split('/')
				hostname = split[2] = 'www.oocities.org'
				request_url = '/'.join(split)
				
				conn = urllib.request.urlopen(request_url)
			else:
				# get from Wayback
				_print('[>] {0}'.format(archived_url))

				request_url = 'http://web.archive.org/web/{0}/{1}'.format(DATE, archived_url)

				conn = urllib.request.urlopen(request_url)
		except urllib.error.HTTPError as e:
			# an error has been found

			# 403 or 404 => heuristically determine the static URL for some redirect scripts
			if e.code in (403, 404):
				match = re.search('''(?:\?|&)(?:target|trg|dest(?:ination)?|to)?(?:url)?=(http[^&]+)''', archived_url, re.IGNORECASE)
				if match:
					# we found it
					new_url = urllib.parse.unquote_plus(match.group(1))
					_print('[r]', new_url)
					return self.redirect_page(http_version, new_url)

			_print('[!] {0} {1}'.format(e.code, e.reason))
			return self.error_page(http_version, e.code, e.reason)
		
		# get content type
		content_type = conn.info().get('Content-Type')
		if content_type == None: content_type = 'text/html'
		if not CONTENT_TYPE_ENCODING and content_type.find(';') > -1: content_type = content_type[:content_type.find(';')]
		
		# set the mode: [0]wayback [1]oocities
		mode = 0
		if GEOCITIES_FIX and hostname in ['www.oocities.org', 'www.oocities.com']: mode = 1
		
		if 'text/html' in content_type: # HTML
			# Some dynamically generated links may end up pointing to
			# web.archive.org. Correct that by redirecting the Wayback
			# portion of the URL away if it ends up being HTML consumed
			# through the QUICK_IMAGES interface.
			if hostname == 'web.archive.org':
				conn.close()
				return self.redirect_page(http_version, '/'.join(archived_url.split('/')[5:]), 301)

			# consume all data
			data = conn.read()

			# patch the page
			if mode == 0: # wayback
				if b'<title>Wayback Machine</title>' in data:
					match = re.search(b'<iframe id="playback" src="((?:(?:http(?:s)?:)?//web.archive.org)?/web/[^"]+)"', data)
					if match:
						# media playback iframe

						# Some websites (especially ones that use frames)
						# inexplicably render inside a media playback iframe.
						# In that case, a simple redirect would result in a
						# redirect loop. Download the URL and render it instead.
						request_url = match.group(1).decode('ascii', 'ignore')
						archived_url = '/'.join(request_url.split('/')[5:])
						print('[f]', archived_url)
						try:
							conn = urllib.request.urlopen(request_url)
						except urllib.error.HTTPError as e:
							_print('[!]', e.code, e.reason)
							return self.error_page(http_version, e.code, e.reason)

						content_type = conn.info().get('Content-Type')
						if not CONTENT_TYPE_ENCODING and content_type.find(';') > -1: content_type = content_type[:content_type.find(';')]
						data = conn.read()

				if b'<title></title>' in data and b'<h1><span>Internet Archive\'s Wayback Machine</span></h1>' in data:
					match = re.search(b'<p class="impatient"><a href="(?:(?:http(?:s)?:)?//web\.archive\.org)?/web/(?:[^/]+)/([^"]+)">Impatient\?</a></p>', data)
					if match:
						# wayback redirect page, follow it
						match2 = re.search(b'<p class="code shift red">Got an HTTP ([0-9]+)', data)
						try:
							redirect_code = int(match2.group(1))
						except:
							redirect_code = 302
						archived_url = match.group(1).decode('ascii', 'ignore')
						print('[r]', archived_url)
						return self.redirect_page(http_version, archived_url, redirect_code)

				# pre-toolbar scripts and CSS
				data = re.sub(b'<script src="//archive\.org/(?:.*)<!-- End Wayback Rewrite JS Include -->', b'', data, flags=re.S)
				# toolbar
				data = re.sub(b'<!-- BEGIN WAYBACK TOOLBAR INSERT -->(?:.*)<!-- END WAYBACK TOOLBAR INSERT -->', b'', data, flags=re.S)
				# comments on footer
				data = re.sub(b'\n<!--\n     FILE ARCHIVED (?:.*)$', b'', data, flags=re.S)
				# fix base tag
				data = re.sub(b'(<base (?:[^>]*)href=(?:["\'])?)(?:(?:http(?:s)?:)?//web.archive.org)?/web/(?:[^/]+)/', b'\\1', data, flags=re.I + re.S)

				# remove extraneous :80 from links
				data = re.sub(b'((?:(?:http(?:s)?:)?//web.archive.org)?/web/)([^/]+)/([^:]+)://([^:]+):80/', b'\\1\\2/\\3://\\4/', data)
				# fix links
				if QUICK_IMAGES:
					# QUICK_IMAGES works by intercepting asset URLs (those
					# with a date code ending in im_, js_...) and letting the
					# proxy pass them through. This may reduce load time
					# because Wayback doesn't have to hunt down the closest
					# copy of that asset to DATE, as those URLs have specific
					# date codes. This taints the HTML with web.archive.org
					# URLs. QUICK_IMAGES=2 uses the original URLs with an added
					# username:password, which taints less but is not supported
					# by all browsers - IE6 notably kills the whole page if it
					# sees an iframe pointing to an invalid URL.
					data = re.sub(b'(?:(?:http(?:s)?:)?//web.archive.org)?/web/([0-9]+)([a-z]+_)/([^:]+)://',
						QUICK_IMAGES == 2 and b'\\3://\\1:\\2@' or b'http://web.archive.org/web/\\1\\2/\\3://', data)
					data = re.sub(b'(?:(?:http(?:s)?:)?//web.archive.org)?/web/([0-9]+)/', b'', data)
				else:
					data = re.sub(b'(?:(?:http(?:s)?:)?//web.archive.org)?/web/([^/]+)/', b'', data)
			elif mode == 1: # oocities
				# viewport/cache-control/max-width code (header)
				data = re.sub(b'^(?:.*?)\n\n', b'', data, flags=re.S)
				# archive notice and tracking code (footer)
				data = re.sub(b'<style> \n.zoomout { -webkit-transition: (?:.*)$', b'', data, flags=re.S)
				# clearly labeled snippets from Geocities
				data = re.sub(b'^(?:.*)<\!-- text above generated by server\. PLEASE REMOVE -->', b'', data, flags=re.S)
				data = re.sub(b'<\!-- following code added by server\. PLEASE REMOVE -->(?:.*)<\!-- preceding code added by server\. PLEASE REMOVE -->', b'', data, flags=re.S)
				data = re.sub(b'<\!-- text below generated by server\. PLEASE REMOVE -->(?:.*)$', b'', data, flags=re.S)

				# fix links
				data = re.sub(b'//([^.]*)\.oocities\.com/', b'//\\1.geocities.com/', data, flags=re.S)

			self.request.sendall('{0} 200 OK\r\nContent-Type: {1}\r\nETag: "{2}"\r\n\r\n'.format(http_version, content_type, request_url.replace('"', '')).encode('ascii', 'ignore'))
			self.request.sendall(data)
		else: # other data
			self.request.sendall('{0} 200 OK\r\nContent-Type: {1}\r\nETag: "{2}"\r\n\r\n'.format(http_version, content_type, request_url.replace('"', '')).encode('ascii', 'ignore'))

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
		self.request.sendall('{0} {1} Found\r\nLocation: {2}\r\nContent-Type: text/html\r\nContent-Length: {3}\r\n\r\n{4}'.format(http_version, code, target, len(redirectpage), redirectpage).encode('utf8', 'ignore'))
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