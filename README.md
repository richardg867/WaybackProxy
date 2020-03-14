# WaybackProxy

WaybackProxy is a HTTP proxy that sends all requests through the [Internet Archive Wayback Machine](http://web.archive.org) and [OoCities](http://www.oocities.org), returning the original antique-browser-friendly markup.

![1999 Google viewed on Internet Explorer 4.0 on Windows 95](http://i.imgur.com/tXsLc6O.png)

## Setup

1. Edit `config.py` to your liking
2. Start `waybackproxy.py`
3. Set up your antique browser:
	* If your browser supports proxy auto-configuration, set the auto-configuration URL to `http://ip:port/proxy.pac` where `ip` is the IP of the system running WaybackProxy and `port` is the proxy's port (8888 by default).
	* If proxy auto-configuration is not supported or fails to work, set the browser to use an HTTP proxy at that IP and port instead.
4. Try it out! You can edit most settings that are in `config.py` by browsing to http://web.archive.org while on the proxy, although you must edit `config.py` to make them permanent.
5. Press Ctrl+C to stop

## Known issues and limitations

* The Wayback Machine itself is not 100% reliable, especially when it comes to images on archived pages.
* Dates are not preserved on redirect, which can lead to 404 errors on a few websites.
* WaybackProxy is not a generic proxy. The POST and CONNECT methods are not implemented.
