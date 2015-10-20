#!/usr/bin/env python
import re, socket, SocketServer, urllib2, urlparse
from config import *

class ThreadingTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
	"""TCPServer with ThreadingMixIn added."""
	pass

class Handler(SocketServer.BaseRequestHandler):
	"""Main request handler."""
	def handle(self):
		"""Handle a request."""
		
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
		parsed = urlparse.urlparse(request_url)
		
		# make a path
		path = parsed.path
		if parsed.query != '': path += '?' + parsed.query
		if path == '': path == '/'
		
		# get the hostname for later
		host = parsed.netloc.split(':')
		hostname = host[0]
		
		# read out the headers
		while line.rstrip('\r\n') != '':
			line = f.readline()
		
		try:
			if hostname == 'web.archive.org':
				if path[:5] != '/web/':
					# launch settings
					return self.handle_settings(parsed.query)
				else:
					# pass-through requests to web.archive.org
					# required for QUICK_IMAGES
					print '[>] [QI] {0}'.format('/'.join(request_url.split('/')[5:]))
					conn = urllib2.urlopen(request_url)
			elif GEOCITIES_FIX and hostname == 'www.geocities.com':
				# apply GEOCITIES_FIX and pass it through
				split = request_url.split('/')
				hostname = split[2] = 'www.oocities.org'
				request_url = '/'.join(split)
				
				print '[>] {0}'.format(request_url)
				conn = urllib2.urlopen(request_url)
			else:
				# get from Wayback
				print '[>] {0}'.format(request_url)
				conn = urllib2.urlopen('http://web.archive.org/web/{0}/{1}'.format(DATE, request_url))
		except urllib2.HTTPError as e:
			# an error has been found
			print '[!] {0} {1}'.format(e.code, e.reason)
			return self.error_page(http_version, e.code, e.reason)
		
		# get content type
		content_type = conn.info().getheader('Content-Type')
		if not CONTENT_TYPE_ENCODING and content_type.find(';') > -1: content_type = content_type[:content_type.find(';')]
		
		# send headers		
		self.request.sendall('{0} 200 OK\r\nContent-Type: {1}\r\n\r\n'.format(http_version, content_type))
		
		# set the mode: [0]wayback [1]oocities
		mode = 0
		if GEOCITIES_FIX and hostname in ['www.oocities.org', 'www.oocities.com']: mode = 1
		
		if content_type[:9] == 'text/html' in content_type: # HTML
			toolbar = mode == 1 # oocities header starts without warning
			after_header = False
			redirect_page = False
			for line in conn:
				line = line.rstrip('\r\n')
				
				if mode == 0:
					if toolbar:
						if line == '<!-- END WAYBACK TOOLBAR INSERT -->':
							# toolbar is done - resume relaying on the next line
							toolbar = False
							after_header = True
						continue
					elif redirect_page:
						# this is a really bad way to deal with Wayback's 302
						# pages, but necessary with the way this proxy works
						match = re.search('<p class="impatient"><a href="/web/(?:[^/]+)/([^"]+)">Impatient\\?</a></p>', line)
						if match:
							line = '<title>WaybackProxy Redirect</title><meta http-equiv="refresh" content="0;url='
							line += match.group(1)
							line += '"></head><body>If you are not redirected, <a href="'
							line += match.group(1)
							line += '">click here</a>.</body></html>'
							self.request.sendall(line)
							break
						continue
					
					if not after_header:
						ll = line.lower()
						if line == '<script type="text/javascript" src="/static/js/analytics.js"></script>' or line == '<link type="text/css" rel="stylesheet" href="/static/css/banner-styles.css"/>' or line[:69] == '<script type="text/javascript">archive_analytics.values.server_name="':
							# remove the CSS and tracking scripts added to <head>
							continue
						elif ll[:6] == '<base ':
							# fix base
							line = re.sub('/web/([0-9]+)/', '', line)
					if line == '<!-- BEGIN WAYBACK TOOLBAR INSERT -->':
						# remove the toolbar - stop relaying from now on
						toolbar = True
						continue
					elif line == '\t\t<title>Internet Archive Wayback Machine</title>':
						# redirect 302s - see the redirect_page code above
						redirect_page = True
						continue
					
					if QUICK_IMAGES:
						# QUICK_IMAGES works by intercepting asset URLs (those
						# with a date code ending in im_, js_...) and letting the
						# proxy pass them through. This may reduce load time
						# because Wayback doesn't have to hunt down the closest
						# copy of that asset to DATE, as those URLs have specific
						# date codes. The only side effect is tainting the HTML
						# with web.archive.org URLs.
						line = re.sub('/web/([0-9]+)([a-z]+_)/',
							'http://web.archive.org/web/\\1\\2/', line)
						line = re.sub('/web/([0-9]+)/', '', line)
					else:
						line = re.sub('/web/([^/]+)/', '', line)
				elif mode == 1:
					# remove the geocities/oocities-added code, which is
					# conveniently wrapped around comments
					if toolbar:
						if line in ['<!-- text above generated by server. PLEASE REMOVE -->', '<!-- preceding code added by server. PLEASE REMOVE -->']:
							toolbar = False
						continue
					elif line == '<!-- following code added by server. PLEASE REMOVE -->' or line[:54] == '<!-- text below generated by server. PLEASE REMOVE -->':
						toolbar = True
						continue
					
					# taint? what taint?
					line = line.replace('http://oocities.com', 'http://geocities.com')
					line = line.replace('http://www.oocities.com', 'http://www.geocities.com')
				
				self.request.sendall(line)
				self.request.sendall('\r\n')
		else: # other data
			while True:
				data = conn.read(1024)
				if data == '': break
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
		
		errorpage += '</p><hr><i>{0}</i></body></html>'.format(self.signature())
		
		# send error page and stop
		self.request.sendall('{0} {1} {2}\r\nContent-Length: {3}\r\n\r\n'.format(http_version, code, reason, len(errorpage)))
		self.request.sendall(errorpage)
		self.request.close()
	
	def handle_settings(self, query):
		"""Generate the settings page."""
	
		global DATE, GEOCITIES_FIX, QUICK_IMAGES, CONTENT_TYPE_ENCODING
		
		if query != '': # handle any parameters that may have been sent
			parsed = urlparse.parse_qs(query)
			
			if 'date' in parsed: DATE = parsed['date'][0]
			GEOCITIES_FIX = 'gcFix' in parsed
			QUICK_IMAGES = 'quickImages' in parsed
			CONTENT_TYPE_ENCODING = 'ctEncoding' in parsed
		
		# send the page and stop
		self.request.sendall('HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n')
		self.request.sendall('<html><head><title>WaybackProxy Settings</title></head><body><p><b>')
		self.request.sendall(self.signature())
		self.request.sendall('</b></p><form method="get" action="/"><p>Date to get pages from: <input type="text" name="date" size="8" value="')
		self.request.sendall(DATE)
		self.request.sendall('"><br><input type="checkbox" name="gcFix"')
		if GEOCITIES_FIX: self.request.sendall(' checked')
		self.request.sendall('> Geocities Fix<br><input type="checkbox" name="quickImages"')
		if QUICK_IMAGES: self.request.sendall(' checked')
		self.request.sendall('> Quick images<br><input type="checkbox" name="ctEncoding"')
		if CONTENT_TYPE_ENCODING: self.request.sendall(' checked')
		self.request.sendall('> Encoding in Content-Type</p><p><input type="submit" value="Save"></p></form></body></html>')
		self.request.close()
	
	def signature(self):
		"""Return the server signature."""
		return 'WaybackProxy on {0}'.format(socket.gethostname())

def main():
	"""Starts the server."""
	server = ThreadingTCPServer(('', LISTEN_PORT), Handler)
	print '[-] Now listening on port {0}'.format(LISTEN_PORT)
	try:
		server.serve_forever()
	except KeyboardInterrupt: # Ctrl+C to stop
		pass

if __name__ == '__main__':
	main()