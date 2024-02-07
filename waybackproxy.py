#!/usr/bin/env python3
import base64, datetime, json, lrudict, re, socket, socketserver, string, sys, threading, time, traceback, urllib.parse
import argparse
import os

try:
	import urllib3
except ImportError:
	print('WaybackProxy now requires urllib3 to be installed. Follow setup step 3 on the readme to fix this.')
	sys.exit(1)
 
from config_handler import *

config = load_config()

class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
	"""TCPServer with ThreadingMixIn added."""
	allow_reuse_address = True  # Allow for address reuse (bind again)
	pass

class SharedState:
	"""Class for storing shared state across instances of Handler."""

	def __init__(self):
		# Create urllib3 connection pool.
		self.http = urllib3.PoolManager(maxsize=4, block=True)
		urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

		# Create internal LRU dictionary for preserving URLs on redirect.
		self.date_cache = lrudict.LRUDict(maxduration=86400, maxsize=1024)

		# Create internal LRU dictionary for date availability.
		self.availability_cache = lrudict.LRUDict(maxduration=86400, maxsize=1024)

		# Read domain whitelist file.
		try:
			dir_path = os.path.dirname(os.path.realpath(__file__))
			file_name = os.path.join(dir_path, 'whitelist.txt')
			with open(file_name, 'r') as f:
				self.whitelist = f.read().splitlines()
		except:
			self.whitelist = []

shared_state = SharedState()

class Handler(socketserver.BaseRequestHandler):
	"""Main request handler."""

	def setup(self, *args, **kwargs):
		"""Set up this instance of Handler."""
		super().setup(*args, **kwargs)

		# Store a local pointer to SharedState.
		self.shared_state = shared_state

	def handle(self):
		"""Handle a request."""

		# readline is pretty convenient
		f = self.request.makefile()
		
		# read request line
		reqline = line = f.readline()
		split = line.rstrip().split(' ')
		http_version = len(split) > 2 and split[2] or 'HTTP/0.9'

		if len(split) < 2 or split[0] != 'GET':
			# only GET is implemented
			return self.send_error_page(http_version, 501, 'Not Implemented')

		# read out the headers
		request_host = None
		pac_host = '" + location.host + ":' + str(config["LISTEN_PORT"]) # may not actually work
		effective_date = config["DATE"]
		auth = None
		while line.strip() != '':
			line = f.readline()
			ll = line.lower()
			if ll[:6] == 'host: ':
				pac_host = request_host = line[6:].rstrip()
				if ':' not in pac_host: # explicitly specify port if running on port 80
					pac_host += ':80'
			elif ll[:21] == 'x-waybackproxy-date: ':
				# API for a personal project of mine
				effective_date = line[21:].rstrip()
			elif ll[:21] == 'authorization: basic ':
				# asset date code passed as username:password
				auth = base64.b64decode(ll[21:])

		# parse the URL
		pac_file_paths = ('/proxy.pac', '/wpad.dat', '/wpad.da')
		if split[1][0] == '/' and split[1] not in pac_file_paths:
			# just a path (not corresponding to a PAC file) => transparent proxy
			# Host header and therefore HTTP/1.1 are required
			if not request_host:
				return self.send_error_page(http_version, 400, 'Host header missing')
			archived_url = 'http://' + request_host + split[1]
		else:
			# full URL => explicit proxy
			archived_url = split[1]
		request_url = archived_url
		parsed = urllib.parse.urlparse(request_url)

		# make a path
		path = parsed.path
		if parsed.query:
			path += '?' + parsed.query
		elif path == '':
			path == '/'

		# get the hostname for later
		host = parsed.netloc.split(':')
		hostname = host[0]

		# get cached date for redirects, if available
		original_date = effective_date
		effective_date = self.shared_state.date_cache.get(str(effective_date) + '\x00' + str(archived_url), effective_date)

		# get date from username:password, if available
		if auth:
			effective_date = auth.replace(':', '')

		# Effectively handle the request.
		try:
			if path in pac_file_paths:
				# PAC file to bypass QUICK_IMAGES requests if WAYBACK_API is not enabled.
				pac  = http_version + ''' 200 OK\r\n'''
				pac += '''Content-Type: application/x-ns-proxy-autoconfig\r\n'''
				pac += '''\r\n'''
				pac += '''function FindProxyForURL(url, host)\r\n'''
				pac += '''{\r\n'''
				if not config["WAYBACK_API"]:
					pac += '''	if (shExpMatch(url, "http://web.archive.org/web/*") && !shExpMatch(url, "http://web.archive.org/web/??????????????if_/*"))\r\n'''
					pac += '''	{\r\n'''
					pac += '''		return "DIRECT";\r\n'''
					pac += '''	}\r\n'''
				pac += '''	return "PROXY ''' + pac_host + '''";\r\n'''
				pac += '''}\r\n'''
				self.request.sendall(pac.encode('ascii', 'ignore'))
				return
			elif hostname in self.shared_state.whitelist:
				_print('[>] [byp]', archived_url)
			elif hostname == 'web.archive.org':
				if path[:5] != '/web/':
					# Launch settings if enabled.
					if config["SETTINGS_PAGE"]:
						return self.handle_settings(parsed.query)
					else:
						return self.send_error_page(http_version, 404, 'Not Found')
				else:
					# Pass requests through to web.archive.org. Required for QUICK_IMAGES.
					split = request_url.split('/')
					effective_date = split[4]
					archived_url = '/'.join(split[5:])
					_print('[>] [QI]', archived_url)
			elif config["GEOCITIES_FIX"] and hostname == 'www.geocities.com':
				# Apply GEOCITIES_FIX and pass it through.
				_print('[>]', archived_url)

				split = archived_url.split('/')
				hostname = split[2] = 'www.oocities.org'
				request_url = '/'.join(split)
			else:
				# Get from the Wayback Machine.
				_print('[>]', archived_url)

				request_url = 'https://web.archive.org/web/{0}if_/{1}'.format(effective_date, archived_url)

			# Check Wayback Machine Availability API where applicable, to avoid archived 404 pages and other site errors.
			split = request_url.split('/')
			if split[2] == 'web.archive.org':
				# Remove extraneous :80 from URL.
				if ':' in split[5]:
					if split[7][-3:] == ':80':
						split[7] = split[7][:-3]
				elif split[5][-3:] == ':80':
					split[5] = split[5][:-3]

				# Check availability LRU cache.
				availability_url = '/'.join(split[5:])
				new_url = self.shared_state.availability_cache.get(availability_url, None)
				if new_url:
					# In cache => replace URL immediately.
					request_url = new_url
				elif config["WAYBACK_API"]:
					# Not in cache => contact API.
					try:
						availability_endpoint = 'https://archive.org/wayback/available?url=' + urllib.parse.quote_plus(availability_url) + '&timestamp=' + effective_date[:14]
						availability = json.loads(self.shared_state.http.request('GET', availability_endpoint, timeout=10, retries=1).data)
						closest = availability.get('archived_snapshots', {}).get('closest', {})
						new_date = closest.get('timestamp', None)
					except:
						_print('[!] Failed to fetch Wayback availability data')
						new_date = None

					if new_date and new_date != effective_date[:14]:
						# Returned date is different.
						new_url = closest['url']

						# Add asset tag to the date.
						split = new_url.split('/')
						if len(effective_date) > 14:
							split[4] += effective_date[14:]
						else:
							split[4] += 'if_'
						new_url = '/'.join(split)

						# Replace URL and add it to the availability cache.
						request_url = self.shared_state.availability_cache[availability_url] = new_url

			# Start fetching the URL.
			retry = urllib3.util.retry.Retry(total=10, connect=10, read=5, redirect=0, backoff_factor=1)
			while True:
				try: #sometimes request_url is empty - to not throw error, just break
					conn = self.shared_state.http.urlopen('GET', request_url, redirect=False, retries=retry, preload_content=False)
				except:
					break
				# Check for redirects.
				destination = conn.get_redirect_location()
				if destination:
					conn.drain_conn()
					conn.release_conn()

					# Check if the redirect goes to a different Wayback URL.
					match = re.search('''(?:(?:https?:)?//web.archive.org)?/web/([^/]+/)(.+)''', destination)
					if match:
						archived_dest = match.group(2)

						# Add missing protocol, just in case.
						split = archived_dest.split('/')
						if split[0][-1:] != ':':
							split = ['http:', ''] + split

						# Remove extraneous :80 from URL.
						if split[2][-3:] == ':80':
							split[2] = split[2][:-3]

						# Check if the archived URL is different.
						if archived_dest != archived_url:
							# Add destination to availability cache and redirect the client.
							_print('[r]', archived_dest)
							new_url = '/'.join(split)
							self.shared_state.availability_cache[archived_dest] = 'http://web.archive.org/web/' + match.group(1) + archived_dest
							return self.send_redirect_page(http_version, archived_dest, conn.status)

					# Not an archived URL or same URL, redirect ourselves.
					request_url = destination
					continue

				# Wayback will add its JavaScript to anything it thinks is JavaScript.
				# If this is detected, redirect ourselves through the raw asset interface.
				content_type = conn.headers.get('Content-Type')
				guessed_content_type = conn.headers.get('X-Archive-Guessed-Content-Type')
				if not guessed_content_type:
					guessed_content_type = content_type
				if 'javascript' in guessed_content_type:
					match = re.match('''(https?://web\\.archive\\.org/web/[0-9]+)([^/]*)(.+)''', request_url)
					if match and match.group(2) != 'im_':
						conn.drain_conn()
						conn.release_conn()
						request_url = match.group(1) + 'im_' + match.group(3)
						continue

				# This request can proceed.
				break
		except urllib3.exceptions.MaxRetryError as e:
			_print('[!] Fetch retries exceeded:', e.reason)
			return self.send_error_page(http_version, 504, 'Gateway Timeout')
		except:
			# Some other fetch exception has occurred.
			_print('[!] Fetch exception:')
			traceback.print_exc()
			return self.send_error_page(http_version, 502, 'Bad Gateway')

		# Check for HTTP errors.
		if conn.status != 200:
			if conn.status in (403, 404): # not found
				if self.guess_and_send_redirect(http_version, archived_url):
					conn.drain_conn()
					conn.release_conn()
					return
			#elif conn.status in (301, 302): # redirect loop detection currently unused
			#	conn.drain_conn()
			#	conn.release_conn()
			#	return self.send_error_page(http_version, 508, 'Infinite Redirect Loop')

			if conn.status != 412: # tolerance exceeded has its own error message above
				_print('[!]', conn.status, conn.reason)

			# If the memento Link header is present, this is a website error
			# instead of a Wayback error. Pass it along if that's the case.
			if 'Link' not in conn.headers:
				conn.drain_conn()
				conn.release_conn()
				return self.send_error_page(http_version, conn.status, conn.reason)

		# Adjust content type.
		if content_type == None:
			content_type = 'text/html'
		elif not config["CONTENT_TYPE_ENCODING"]:
			idx = content_type.find(';')
			if idx > -1:
				content_type = content_type[:idx]

		# Set the archive mode.
		if config["GEOCITIES_FIX"] and hostname in ('www.oocities.org', 'www.oocities.com'):
			mode = 1 # oocities
		else:
			mode = 0 # Wayback Machine

		# Check content type to determine if this is HTML we need to patch.
		# Wayback will add its HTML to anything it thinks is HTML.
		if 'text/html' in guessed_content_type:
			# Some dynamically-generated links may end up pointing to
			# web.archive.org. Correct that by redirecting the Wayback
			# portion of the URL away if it ends up being HTML consumed
			# through the QUICK_IMAGES interface.
			if hostname == 'web.archive.org':
				conn.drain_conn()
				conn.release_conn()
				archived_url = '/'.join(request_url.split('/')[5:])
				_print('[r] [QI]', archived_url)
				return self.send_redirect_page(http_version, archived_url, 301)

			# Check if the date is within tolerance.
			if config["DATE_TOLERANCE"] != None:
				match = re.search('''(?://web\\.archive\\.org|^)/web/([0-9]+)''', conn.geturl() or '')
				if match:
					requested_date = match.group(1)
					if self.wayback_to_datetime(requested_date) > self.wayback_to_datetime(original_date) + datetime.timedelta(int(config["DATE_TOLERANCE"])):
						conn.drain_conn()
						conn.release_conn()
						_print('[!]', requested_date, 'is outside the configured tolerance of', config["DATE_TOLERANCE"], 'days')
						if not self.guess_and_send_redirect(http_version, archived_url):
							self.send_error_page(http_version, 412, 'Snapshot ' + requested_date + ' not available')
						return

			# Consume all data.
			data = conn.read()
			conn.release_conn()

			# Patch the page.
			if mode == 0: # Wayback Machine
				# Check if this is a Wayback Machine page.
				if b'<title>Wayback Machine</title>' in data:
					# Check if this is an exclusion (robots.txt?) error page.
					if b'<p>This URL has been excluded from the Wayback Machine.</p>' in data:
						return self.send_error_page(http_version, 403, 'URL excluded')

					# Check if this is a media playback iframe page.
					# Some websites (especially ones that use frames)
					# inexplicably render inside a media playback iframe.
					# In that case, a simple redirect would result in a
					# redirect loop, so fetch and render the URL instead.
					match = re.search(b'''<iframe id="playback" src="((?:(?:https?:)?//web.archive.org)?/web/[^"]+)"''', data)
					if match:
						# Extract the content URL.
						request_url = match.group(1).decode('ascii', 'ignore')
						archived_url = '/'.join(request_url.split('/')[5:])

						# Start fetching the URL.
						_print('[f]', archived_url)
						conn = self.shared_state.http.urlopen('GET', request_url, retries=retry, preload_content=False)
						
						if conn.status != 200:
							_print('[!]', conn.status, conn.reason)

							# If the memento Link header is present, this is a website error
							# instead of a Wayback error. Pass it along if that's the case.
							if 'Link' not in conn.headers:
								conn.drain_conn()
								conn.release_conn()
								return self.send_error_page(http_version, conn.status, conn.reason)

						# Identify content type so we don't modify non-HTML content.
						content_type = conn.headers.get('Content-Type')
						if not config["CONTENT_TYPE_ENCODING"]:
							idx = content_type.find(';')
							if idx > -1:
								content_type = content_type[:idx]
						if 'text/html' in content_type:
							# Consume all data and proceed with patching the page.
							data = conn.read()
							conn.release_conn()
						else:
							# Pass non-HTML data through.
							return self.send_passthrough(conn, http_version, content_type, request_url)

				# Check if this is a Wayback Machine redirect page.
				if b'<title></title>' in data and b'<span class="label style-scope media-button"><!---->Wayback Machine<!----></span>' in data:
					match = re.search(b'''<p class="impatient"><a href="(?:(?:https?:)?//web\\.archive\\.org)?/web/([^/]+)/([^"]+)">Impatient\\?</a></p>''', data)
					if match:
						# Sanitize the URL.
						archived_url = self.sanitize_redirect(match.group(2).decode('ascii', 'ignore'))

						# Add URL to the date LRU cache.
						self.shared_state.date_cache[str(effective_date) + '\x00' + archived_url] = match.group(1).decode('ascii', 'ignore')

						# Get the original HTTP redirect code.
						match = re.search(b'''<p class="code shift red">Got an HTTP ([0-9]+)''', data)
						try:
							redirect_code = int(match.group(1))
						except:
							redirect_code = 302

						# Redirect client to the URL.
						_print('[r]', archived_url)
						return self.send_redirect_page(http_version, archived_url, redirect_code)

				# Remove pre-toolbar scripts and CSS.
				data = re.sub(b'''<script (?:type="text/javascript" )?src="(?:https?:)?//(?:web-static\\.)?archive\\.org/_static/js/.*<!-- End Wayback Rewrite JS Include -->\\r?\\n''', b'', data, count=1, flags=re.S)
				# Remove toolbar. The if_ asset tag serves no toolbar, but we remove it just in case.
				data = re.sub(b'''<!-- BEGIN WAYBACK TOOLBAR INSERT -->.*<!-- END WAYBACK TOOLBAR INSERT -->''', b'', data, count=1, flags=re.S)
				# Remove comments on footer.
				data = re.sub(b'''<!--\\r?\\n     FILE ARCHIVED .*$''', b'', data, flags=re.S)
				# Fix base tag.
				data = re.sub(b'''(<base\\s+[^>]*href=["']?)(?:(?:https?:)?//web.archive.org)?/web/[^/]+/(?:[^:/]+://)?''', b'\\1http://', data, flags=re.I + re.S)

				# Remove extraneous :80 from links.
				data = re.sub(b'((?:(?:https?:)?//web.archive.org)?/web/)([^/]+)/([^/:]+)://([^/:]+):80/', b'\\1\\2/\\3://\\4/', data)
				# Fix links.
				if config["QUICK_IMAGES"]:
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
					def filter_asset(match):
						if match.group(2) in (None, b'if_', b'fw_'): # non-asset URL
							return match.group(3) == b'https://' and b'http://' or match.group(3) # convert secure non-asset URLs to regular HTTP
						asset_type = match.group(2)
						if asset_type == b'js_': # cut down on the JavaScript detector's second request
							asset_type = b'im_'
						if config["QUICK_IMAGES"] == 2:
							return b'http://' + match.group(1) + b':' + asset_type + b'@'
						else:
							return b'http://web.archive.org/web/' + match.group(1) + asset_type + b'/' + match.group(3)
					data = re.sub(b'(?:(?:https?:)?//web.archive.org)?/web/([0-9]+)([a-z]+_)?/([^:/]+:(?://)?)', filter_asset, data)
				else:
					# Remove asset URLs while simultaneously adding them to the date LRU cache
					# with their respective date and converting secure URLs to regular HTTP.
					def add_to_date_cache(match):
						orig_url = match.group(2)
						if orig_url[:8] == b'https://':
							orig_url = b'http://' + orig_url[8:]
						self.shared_state.date_cache[str(effective_date) + '\x00' + orig_url.decode('ascii', 'ignore')] = match.group(1).decode('ascii', 'ignore').replace('js_', 'im_')
						return orig_url
					data = re.sub(b'''(?:(?:https?:)?//web.archive.org)?/web/([^/]+)/([^"\\'#<>]+)''', add_to_date_cache, data)
			elif mode == 1: # oocities
				# Remove viewport/cache-control/max-width code from the header.
				data = re.sub(b'''^.*?\n\n''', b'', data, flags=re.S)
				# Remove archive notice and tracking code from the footer.
				data = re.sub(b'''<style> \n.zoomout { -webkit-transition: .*$''', b'', data, flags=re.S)
				# Remove clearly labeled snippets from Geocities.
				data = re.sub(b'''^.*<\\!-- text above generated by server\\. PLEASE REMOVE -->''', b'', data, flags=re.S)
				data = re.sub(b'''<\\!-- following code added by server\\. PLEASE REMOVE -->.*<\!-- preceding code added by server\. PLEASE REMOVE -->''', b'', data, flags=re.S)
				data = re.sub(b'''<\\!-- text below generated by server\\. PLEASE REMOVE -->.*$''', b'', data, flags=re.S)

				# Fix links.
				data = re.sub(b'''//([^\\.]*\\.)?oocities\\.com/''', b'//\\1geocities.com/', data, flags=re.S)

			# Send patched page.
			self.send_response_headers(conn, http_version, content_type, request_url, content_length=len(data))
			self.request.sendall(data)
			self.request.close()
		else:
			# Pass non-HTML data through.
			self.send_passthrough(conn, http_version, content_type, request_url)

	def send_passthrough(self, conn, http_version, content_type, request_url):
		"""Pass data through to the client unmodified (save for our headers)."""
		self.send_response_headers(conn, http_version, content_type, request_url, content_length=True)
		for data in conn.stream(1024):
			self.request.sendall(data)
		conn.release_conn()
		self.request.close()

	def send_response_headers(self, conn, http_version, content_type, request_url, content_length=False):
		"""Generate and send the response headers."""

		# Pass the HTTP version, and error code if there is one.
		response = '{0} {1} {2}'.format(http_version, conn.status, conn.reason.replace('\n', ' '))

		# Add Content-Type, Content-Length and the caching ETag.
		response += '\r\nContent-Type: ' + content_type
		if type(content_length) == int:
			response += '\r\nContent-Length: ' + str(content_length)
			content_length = False # don't pass the original length through
		response += '\r\nETag: "' + request_url.replace('"', '') + '"'
		response += '\r\nConnection: close' # helps with IE6 trying to use proxy keep alive and holding half-open connections

		# Pass X-Archive-Orig-* (and Content-Length if requested) headers through.
		for header in conn.headers:
			if header.find('X-Archive-Orig-') == 0:
				orig_header = header[15:]
				# Skip headers which may affect client behavior.
				if orig_header.lower() not in ('connection', 'location', 'content-type', 'content-length', 'etag', 'authorization', 'set-cookie'):
					response += '\r\n' + orig_header + ': ' + conn.headers[header]
			elif content_length and header.lower() == 'content-length':
				response += '\r\n' + header + ': ' + conn.headers[header]

		# Finish and send the request.
		response += '\r\n\r\n'
		self.request.sendall(response.encode('utf8', 'ignore'))
	
	def send_error_page(self, http_version, code, reason):
		"""Generate an error page."""

		# Get a description for this error code.
		if code in (404, 508): # page not archived or redirect loop
			description = 'This page may not be archived by the Wayback Machine.'
		elif code == 403: # not crawled due to exclusion
			description = 'This page was not archived due to a Wayback Machine exclusion.'
		elif code == 501: # method not implemented
			description = 'WaybackProxy only implements the GET method.'
		elif code == 502: # exception
			description = 'This page could not be fetched due to an unknown error.'
		elif code == 504: # timeout
			description = 'This page could not be fetched due to a Wayback Machine server error.'
		elif code == 412: # outside of tolerance
			description = 'The earliest snapshot for this page is outside of the configured tolerance interval.'
		elif code == 400 and reason == 'Host header missing': # no host header in transparent mode
			description = 'WaybackProxy\'s transparent mode requires an HTTP/1.1 compliant client.'
		else: # another error
			description = 'Unknown error. The Wayback Machine may be experiencing technical difficulties.'

		# Read error page file.
		try:
			with open('error.html', 'r', encoding='utf8', errors='ignore') as f:
				error_page = f.read()
		except:
			# Just send the code and reason as a backup.
			error_page = '${code} ${reason}'

		# Format error page template.
		signature = self.signature()
		error_page = string.Template(error_page).substitute(**locals())
		error_page_len = len(error_page)

		# Send formatted error page and stop.
		self.request.sendall(
			'{http_version} {code} {reason}\r\n'
			'Content-Type: text/html\r\n'
			'Content-Length: {error_page_len}\r\n'
			'\r\n'
			'{error_page}'
			.format(**locals()).encode('utf8', 'ignore')
		)
		self.request.close()

	def send_redirect_page(self, http_version, target, code=302):
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

	def guess_and_send_redirect(self, http_version, guess_url):
		# Heuristically determine the static URL for some redirect scripts.
		parsed = urllib.parse.urlparse(guess_url)
		match = re.search('''(?:^|&)[^=]+=((?:https?(?:%3A|:)(?:%2F|/)|www[0-9]*\\.[^/%]+)?(?:%2F|/)[^&]+)''', parsed.query, re.I) # URL in query parameters
		if not match:
			full_path = parsed.path
			if parsed.query:
				full_path += '?' + parsed.query
			match = re.search('''((?:https?(?:%3A|:)(?:%2F|/)|www[0-9]*\\.[^/%]+)(?:(?:%2F|/).+|$))''', full_path, re.I) # URL in path or full query
		if match: # found URL
			# Decode and sanitize the URL.
			new_url = self.sanitize_redirect(urllib.parse.unquote_plus(match.group(1)))

			# Redirect client to the URL.
			_print('[r] [g]', new_url)
			self.send_redirect_page(http_version, new_url)
			return True
		return False
	
	def handle_settings(self, query):
		"""Generate the settings page."""

		if query != '': # handle any parameters that may have been sent
			parsed = urllib.parse.parse_qs(query)

			if 'date' in parsed and 'dateTolerance' in parsed:
				if DATE != parsed['date'][0]:
					DATE = parsed['date'][0]
					self.shared_state.date_cache.clear()
					self.shared_state.availability_cache.clear()
				if DATE_TOLERANCE != parsed['dateTolerance'][0]:
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
		settingspage += str(DATE)
		settingspage += '"><p>Date tolerance: <input type="text" name="dateTolerance" size="8" value="'
		settingspage += str(DATE_TOLERANCE)
		settingspage += '"> days<br><input type="checkbox" name="gcFix"'
		if GEOCITIES_FIX:
			settingspage += ' checked'
		settingspage += '> Geocities Fix<br><input type="checkbox" name="quickImages"'
		if QUICK_IMAGES:
			settingspage += ' checked'
		settingspage += '> Quick images<br><input type="checkbox" name="ctEncoding"'
		if CONTENT_TYPE_ENCODING:
			settingspage += ' checked'
		settingspage += '> Encoding in Content-Type</p><p><input type="submit" value="Save"></p></form></body></html>'
		self.request.send(settingspage.encode('utf8', 'ignore'))
		self.request.close()

	def sanitize_redirect(self, url):
		"""Sanitize an URL for client-side redirection."""
		if url[0] != '/' and '://' not in url:
			# Add protocol if the URL is absolute but missing a protocol.
			return 'http://' + url
		elif url[:8].lower() == 'https://':
			# Convert secure URLs to regular HTTP.
			return 'http://' + url[8:]
		else:
			# No changes required.
			return url

	def signature(self):
		"""Return the server signature."""
		return 'WaybackProxy on {0}'.format(socket.gethostname())

	def wayback_to_datetime(self, date):
		"""Convert a Wayback format date string to a datetime.datetime object."""
		date = str(date)
		fmt = '%Y%m%d%H%M%S'
		fmt_len = 14
		while fmt:
			try:
				return datetime.datetime.strptime(date[:fmt_len], fmt)
			except:
				fmt = fmt[:-2]
				fmt_len -= 2

print_lock = threading.Lock()
def _print(*args, **kwargs):
	"""Logging function."""
	if config["SILENT"]:
		return
	with print_lock:
		print(*args, **kwargs, flush=True)





def main():
	"""Starts the server."""        
	server = ThreadingTCPServer(('', config["LISTEN_PORT"]), Handler)
	_print('[-] Now listening on port', config["LISTEN_PORT"])
	_print('[-] Date set to', config["DATE"])
	try:
		server.serve_forever()
	except KeyboardInterrupt: # Ctrl+C to stop
		pass


def main():
    """Starts the server."""
    parser = argparse.ArgumentParser(description='Starts the server with optional configuration file.')
    parser.add_argument('-c', '--config', type=str, help='Path to the configuration file.')
    args = parser.parse_args()

    if args.config:
        if os.path.isfile(args.config):
            global config
            
            config = load_config(args.config)  # Load config from file
        else:
            print(f'Error: The specified configuration file does not exist: {args.config}')

    server = ThreadingTCPServer(('', config["LISTEN_PORT"]), Handler)
    _print('[-] Now listening on port', config["LISTEN_PORT"])
    _print('[-] Date set to', config["DATE"])
    try:
        server.serve_forever()
    except KeyboardInterrupt:  # Ctrl+C to stop
        print("Exiting...") 
        server.shutdown() #try to close connection gently but not sure if works correctly 
        server.server_close()
        pass

if __name__ == '__main__':
    main()
