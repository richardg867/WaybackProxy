#!/usr/bin/env python3
import base64, datetime, json, lrudict, re, socket, socketserver, sys, threading, urllib.request, urllib.error, urllib.parse
from config import *

# internal LRU dictionary for preserving URLs on redirect
date_cache = lrudict.LRUDict(maxduration=86400, maxsize=1024)

# internal LRU dictionary for date availability
availability_cache = lrudict.LRUDict(maxduration=86400, maxsize=1024) if WAYBACK_API else None

class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
	"""TCPServer with ThreadingMixIn added."""
	pass

class Handler(socketserver.BaseRequestHandler):
	"""Main request handler."""
	def handle(self):
		"""Handle a request."""
		global availability_cache
		
		# readline is pretty convenient
		f = self.request.makefile()
		
		# read request line
		reqline = line = f.readline()
		split = line.rstrip('\r\n').split(' ')
		http_version = len(split) > 2 and split[2] or 'HTTP/0.9'
		
		if split[0] != 'GET':
			# only GET is implemented
			return self.error_page(http_version, 501, 'Not Implemented')
		
		# read out the headers
		request_host = None
		pac_host = '" + location.host + ":' + str(LISTEN_PORT) # may not actually work
		effective_date = DATE
		auth = None
		while line.rstrip('\r\n') != '':
			line = f.readline()
			ll = line.lower()
			if ll[:6] == 'host: ':
				pac_host = request_host = line[6:].rstrip('\r\n')
				if ':' not in pac_host: # who would run this on port 80 anyway?
					pac_host += ':80'
			elif ll[:21] == 'x-waybackproxy-date: ':
				# API for a personal project of mine
				effective_date = line[21:].rstrip('\r\n')
			elif ll[:21] == 'authorization: basic ':
				# asset date code passed as username:password
				auth = base64.b64decode(ll[21:])

		# parse the URL
		pac_file_paths = ('/proxy.pac', '/wpad.dat', '/wpad.da')
		if split[1][0] == '/' and split[1] not in pac_file_paths:
			# just a path (not corresponding to a PAC file) => transparent proxy
			# Host header and therefore HTTP/1.1 are required
			if not request_host:
				return self.error_page(http_version, 400, 'Host header missing')
			archived_url = 'http://' + request_host + split[1]
		else:
			# full URL => explicit proxy
			archived_url = split[1]
		request_url = archived_url
		parsed = urllib.parse.urlparse(request_url)
		
		# make a path
		path = parsed.path
		if parsed.query != '': path += '?' + parsed.query
		if path == '': path == '/'
		
		# get the hostname for later
		host = parsed.netloc.split(':')
		hostname = host[0]

		# get cached date for redirects, if available
		original_date = effective_date
		effective_date = date_cache.get(effective_date + '\x00' + archived_url, effective_date)

		# get date from username:password, if available
		if auth:
			effective_date = auth.replace(':', '')

		# effectively handle the request
		try:
			if path in pac_file_paths:
				# PAC file to bypass QUICK_IMAGES requests
				pac  = http_version.encode('ascii', 'ignore') + b''' 200 OK\r\n'''
				pac += b'''Content-Type: application/x-ns-proxy-autoconfig\r\n'''
				pac += b'''\r\n'''
				pac += b'''function FindProxyForURL(url, host)\r\n'''
				pac += b'''{\r\n'''
				pac += b'''	if (shExpMatch(url, "http://web.archive.org/web/*") && !shExpMatch(url, "http://web.archive.org/web/??????????????if_/*"))\r\n'''
				pac += b'''	{\r\n'''
				pac += b'''		return "DIRECT";\r\n'''
				pac += b'''	}\r\n'''
				pac += b'''	return "PROXY ''' + pac_host.encode('ascii', 'ignore') + b'''";\r\n'''
				pac += b'''}\r\n'''
				self.request.sendall(pac)
				return
			elif hostname == 'web.archive.org':
				if path[:5] != '/web/':
					# launch settings if enabled
					if SETTINGS_PAGE:
						return self.handle_settings(parsed.query)
					else:
						return self.error_page(http_version, 404, 'Not Found')
				else:
					# pass-through requests to web.archive.org
					# required for QUICK_IMAGES
					archived_url = '/'.join(request_url.split('/')[5:])
					_print('[>] [QI] {0}'.format(archived_url))
			elif GEOCITIES_FIX and hostname == 'www.geocities.com':
				# apply GEOCITIES_FIX and pass it through
				_print('[>] {0}'.format(archived_url))

				split = archived_url.split('/')
				hostname = split[2] = 'www.oocities.org'
				request_url = '/'.join(split)
			else:
				# get from Wayback
				_print('[>] {0}'.format(archived_url))

				request_url = 'http://web.archive.org/web/{0}/{1}'.format(effective_date, archived_url)				

			if availability_cache is not None:
				# are we requesting from Wayback?
				split = request_url.split('/')

				# if so, get the closest available date from Wayback's API, to avoid archived 404 pages and other site errors
				if split[2] == 'web.archive.org':
					# remove extraneous :80 from URL
					if ':' in split[5]:
						if split[7][-3:] == ':80':
							split[7] = split[7][:-3]
					elif split[5][-3:] == ':80':
						split[5] = split[5][:-3]

					# check availability LRU cache
					availability_url = '/'.join(split[5:])
					new_url = availability_cache.get(availability_url, None)
					if new_url:
						# in cache => replace URL immediately
						request_url = new_url
					else:
						# not in cache => contact API
						try:
							availability = json.loads(urllib.request.urlopen('https://archive.org/wayback/available?url=' + urllib.parse.quote_plus(availability_url) + '&timestamp=' + effective_date[:14], timeout=10).read())
							closest = availability.get('archived_snapshots', {}).get('closest', {})
							new_date = closest.get('timestamp', None)
						except:
							_print('[!] Failed to fetch Wayback availability data')
							new_date = None

						if new_date and new_date != effective_date[:14]:
							# returned date is different
							new_url = closest['url']

							# add asset tag if one is present in the original URL
							if len(effective_date) > 14:
								split = new_url.split('/')
								split[4] += effective_date[14:]
								new_url = '/'.join(split)

							# replace URL and add it to the availability cache
							request_url = availability[availability_url] = new_url

			conn = urllib.request.urlopen(request_url)
		except urllib.error.HTTPError as e:
			# an error has been found

			if e.code in (403, 404, 412):
				# 403, 404 or tolerance exceeded => heuristically determine the static URL for some redirect scripts
				match = re.search('''[^/]/((?:http(?:%3A|:)(?:%2F|/)|www(?:[0-9]+)?\.(?:[^/%]+))(?:%2F|/).+)''', archived_url, re.I)
				if not match:
					match = re.search('''(?:\?|&)(?:[^=]+)=((?:http(?:%3A|:)(?:%2F|/)|www(?:[0-9]+)?\.(?:[^/%]+))?(?:%2F|/)[^&]+)''', archived_url, re.I)
				if match:
					# we found it
					new_url = urllib.parse.unquote_plus(match.group(1))
					# add protocol if the URL is absolute but missing a protocol
					if new_url[0] != '/' and '://' not in new_url:
						new_url = 'http://' + new_url
					_print('[r]', new_url)
					return self.redirect_page(http_version, new_url)
			elif e.code in (301, 302):
				# 301 or 302 => urllib-generated error about an infinite redirect loop
				_print('[!] Infinite redirect loop')
				return self.error_page(http_version, 508, 'Infinite Redirect Loop')

			if e.code != 412: # tolerance exceeded has its own error message above
				_print('[!] {0} {1}'.format(e.code, e.reason))

			# If the memento Link header is present, this is a website error
			# instead of a Wayback error. Pass it along if that's the case.
			if 'Link' in e.headers:
				conn = e
			else:
				return self.error_page(http_version, e.code, e.reason)
		
		# get content type
		content_type = conn.info().get('Content-Type')
		if content_type == None: content_type = 'text/html'
		if not CONTENT_TYPE_ENCODING and content_type.find(';') > -1: content_type = content_type[:content_type.find(';')]
		
		# set the mode: [0]wayback [1]oocities
		mode = 0
		if GEOCITIES_FIX and hostname in ['www.oocities.org', 'www.oocities.com']: mode = 1
		
		# Wayback will add its HTML to anything it thinks is HTML
		guessed_content_type = conn.info().get('X-Archive-Guessed-Content-Type')
		if not guessed_content_type:
			guessed_content_type = content_type
		if 'text/html' in guessed_content_type:
			# Some dynamically generated links may end up pointing to
			# web.archive.org. Correct that by redirecting the Wayback
			# portion of the URL away if it ends up being HTML consumed
			# through the QUICK_IMAGES interface.
			if hostname == 'web.archive.org':
				conn.close()
				archived_url = '/'.join(request_url.split('/')[5:])
				_print('[r] [QI]', archived_url)
				return self.redirect_page(http_version, archived_url, 301)

			# check if the date is within tolerance
			if DATE_TOLERANCE is not None:
				match = re.search('''//web\.archive\.org/web/([0-9]+)''', conn.geturl())
				if match:
					requested_date = match.group(1)
					if self.wayback_to_datetime(requested_date) > self.wayback_to_datetime(original_date) + datetime.timedelta(DATE_TOLERANCE):
						_print('[!]', requested_date, 'is outside the configured tolerance of', DATE_TOLERANCE, 'days')
						conn.close()
						return self.error_page(http_version, 412, 'Snapshot ' + requested_date + ' not available')

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
							
							# If the memento Link header is present, this is a website error
							# instead of a Wayback error. Pass it along if that's the case.
							if 'Link' in e.headers:
								conn = e
							else:
								return self.error_page(http_version, e.code, e.reason)

						content_type = conn.info().get('Content-Type')
						if not CONTENT_TYPE_ENCODING and content_type.find(';') > -1: content_type = content_type[:content_type.find(';')]
						data = conn.read()

				if b'<title></title>' in data and b'<h1><span>Internet Archive\'s Wayback Machine</span></h1>' in data:
					match = re.search(b'<p class="impatient"><a href="(?:(?:http(?:s)?:)?//web\.archive\.org)?/web/([^/]+)/([^"]+)">Impatient\?</a></p>', data)
					if match:
						# wayback redirect page, follow it
						match2 = re.search(b'<p class="code shift red">Got an HTTP ([0-9]+)', data)
						try:
							redirect_code = int(match2.group(1))
						except:
							redirect_code = 302
						archived_url = match.group(2).decode('ascii', 'ignore')
						date_cache[effective_date + '\x00' + archived_url] = match.group(1).decode('ascii', 'ignore')
						print('[r]', archived_url)
						return self.redirect_page(http_version, archived_url, redirect_code)

				# pre-toolbar scripts and CSS
				data = re.sub(b'<script src="//archive\.org/(?:.*)<!-- End Wayback Rewrite JS Include -->(?:\r)?\n', b'', data, flags=re.S)
				# toolbar
				data = re.sub(b'<!-- BEGIN WAYBACK TOOLBAR INSERT -->(?:.*)<!-- END WAYBACK TOOLBAR INSERT -->', b'', data, flags=re.S)
				# comments on footer
				data = re.sub(b'<!--(?:\r)?\n     FILE ARCHIVED (?:.*)$', b'', data, flags=re.S)
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
					# by all browsers - IE notably kills the whole page if it
					# sees an iframe pointing to an invalid URL.
					data = re.sub(b'(?:(?:http(?:s)?:)?//web.archive.org)?/web/([0-9]+)([a-z]+_)/([^:]+)://',
						QUICK_IMAGES == 2 and b'\\3://\\1:\\2@' or b'http://web.archive.org/web/\\1\\2/\\3://', data)
					data = re.sub(b'(?:(?:http(?:s)?:)?//web.archive.org)?/web/([0-9]+)/', b'', data)
				else:
					# Remove asset URLs while simultaneously adding them to the
					# LRU cache with their respective date.
					def add_to_date_cache(match):
						orig_url = match.group(2)
						date_cache[effective_date + '\x00' + orig_url.decode('ascii', 'ignore')] = match.group(1).decode('ascii', 'ignore')
						return orig_url
					data = re.sub(b'(?:(?:http(?:s)?:)?//web.archive.org)?/web/([^/]+)/([^"\'#<>]+)', add_to_date_cache, data)
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

			self.send_response_headers(conn, http_version, content_type, request_url)
			self.request.sendall(data)
		else: # other data
			self.send_response_headers(conn, http_version, content_type, request_url)

			while True:
				data = conn.read(1024)
				if not data: break
				self.request.sendall(data)
		
		self.request.close()

	def send_response_headers(self, conn, http_version, content_type, request_url):
		"""Generate and send the response headers."""

		response = http_version

		# pass the error code if there is one
		if isinstance(conn, urllib.error.HTTPError):
			response += '{0} {1}'.format(conn.code, conn.reason.replace('\n', ' '))
		else:
			response += '200 OK'

		# add content type, and the ETag for caching
		response += '\r\nContent-Type: ' + content_type + '\r\nETag: "' + request_url.replace('"', '') + '"\r\n'

		# add X-Archive-Orig-* headers
		headers = conn.info()
		for header in headers:
			if header.find('X-Archive-Orig-') == 0:
				orig_header = header[15:]
				# blacklist certain headers which may alter the client
				if orig_header.lower() not in ('connection', 'location', 'content-type', 'content-length', 'etag', 'authorization', 'set-cookie'):
					response += orig_header + ': ' + headers[header] + '\r\n'

		# finish and send the request
		response += '\r\n'
		self.request.sendall(response.encode('ascii', 'ignore'))
	
	def error_page(self, http_version, code, reason):
		"""Generate an error page."""
		
		# make error page
		errorpage  = '<html><head><title>{0} {1}</title>'.format(code, reason)
		# IE's same-origin policy throws "Access is denied." inside frames
		# loaded from a different origin. Use that to our advantage, even
		# though regular frames are also affected. IE also doesn't recognize
		# language="javascript1.4", so use 1.3 while blocking IE4 by detecting
		# the lack of screenLeft as IE4 is quite noisy with script errors.
		errorpage += '<script language="javascript1.3">if (window.screenLeft != null) { eval(\'try { var frameElement = window.frameElement; } catch (e) { document.location.href = "about:blank"; }\'); }</script>'
		errorpage += '<script language="javascript">if (window.self != window.top && !(window.frameElement && window.frameElement.tagName == "FRAME")) { document.location.href = "about:blank"; }</script>'
		errorpage += '</head><body><h1>{0}</h1><p>'.format(reason)
		
		# add code information
		if code in (404, 508): # page not archived or redirect loop
			errorpage += 'This page may not be archived by the Wayback Machine.'
		elif code == 403: # not crawled due to robots.txt
			errorpage += 'This page was not archived due to a robots.txt block.'
		elif code == 501: # method not implemented
			errorpage += 'WaybackProxy only implements the GET method.'
		elif code == 412: # outside of tolerance
			errorpage += 'The earliest snapshot for this page is outside of the configured tolerance interval.'
		elif code == 400 and reason == 'Host header missing': # no host header in transparent mode
			errorpage += 'WaybackProxy\'s transparent mode requires an HTTP/1.1 compliant client.'
		else: # another error
			errorpage += 'Unknown error. The Wayback Machine may be experiencing technical difficulties.'
		
		errorpage += '</p><hr><i>'
		errorpage += self.signature()
		errorpage += '</i></body></html>'

		# add padding for IE
		if len(errorpage) <= 512:
			padding = '\n<!-- This comment pads the HTML so Internet Explorer displays this error page instead of its own. '
			remainder = 510 - len(errorpage) - len(padding)
			if remainder > 0:
				padding += ' ' * remainder
			padding += '-->'
			errorpage += padding
		
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
			
			if 'date' in parsed and DATE != parsed['date'][0]:
				DATE = parsed['date'][0]
				date_cache.clear()
				availability_cache.clear()
			if 'dateTolerance' in parsed and DATE_TOLERANCE != parsed['dateTolerance'][0]:
				DATE_TOLERANCE = parsed['dateTolerance'][0]
			GEOCITIES_FIX = 'gcFix' in parsed
			QUICK_IMAGES = 'quickImages' in parsed
			CONTENT_TYPE_ENCODING = 'ctEncoding' in parsed
		
		# send the page and stop
		settingspage  = 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n'
		settingspage += '<html><head><title>WaybackProxy Settings</title></head><body><p><b>'
		settingspage += self.signature()
		settingspage += '</b></p><form method="get" action="/">'
		settingspage += '<p>Date to get pages from: <input type="text" name="date" size="8" value="'
		settingspage += DATE
		settingspage += '"><p>Date tolerance: <input type="text" name="dateTolerance" size="8" value="'
		settingspage += DATE_TOLERANCE
		settingspage += '"> days<br><input type="checkbox" name="gcFix"'
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

	def wayback_to_datetime(self, date):
		"""Convert a Wayback format date string to a datetime.datetime object."""

		# parse the string
		year = 1995
		month = 12
		day = 31
		hour = 0
		minute = 0
		second = 0
		if len(date) > 0:
			year = int(date[:4])
		if len(date) > 4:
			month = int(date[4:6])
		if len(date) > 6:
			day = int(date[6:8])
		if len(date) > 8:
			hour = int(date[8:10])
		if len(date) > 10:
			minute = int(date[10:12])
		if len(date) > 12:
			second = int(date[12:14])

		# sanitize the numbers
		if month < 1:
			month = 1
		elif month > 12:
			month = 12
		if day < 1:
			day = 1
		elif day > 31:
			day = 31
		if hour > 23:
			hour = 23
		elif hour < 0:
			hour = 0
		if minute > 59:
			minute = 59
		elif minute < 0:
			minute = 0
		if second > 59:
			second = 59
		elif second < 0:
			second = 0

		# if the day is invalid for that month, work its way down
		try:
			dt = datetime.datetime(year, month, day, hour, minute, second) # max 31
		except:
			try:
				dt = datetime.datetime(year, month, day - 1, hour, minute, second) # max 30
			except:
				try:
					dt = datetime.datetime(year, month, day - 2, hour, minute, second) # max 29
				except:
					dt = datetime.datetime(year, month, day - 3, hour, minute, second) # max 28

		return dt

print_lock = threading.Lock()
def _print(*args, linebreak=True):
	"""Logging function."""
	if SILENT: return
	s = ' '.join([str(x) for x in args])
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