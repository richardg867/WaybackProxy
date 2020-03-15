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

* The Wayback Machine itself is not 100% reliable. Known issues include:
  * Pages newer than the specified date (setting a specific YYYYMMDD date instead of a wider YYYYMM or YYYY helps with that);
  * Random broken images;
  * Strange 404 errors caused by bad server responses or incorrect URL capitalization at archival time;
  * Infinite redirect loops;
  * Server errors when it's having a bad day.
* WaybackProxy will work around some redirection scripts (example: `http://example.com/redirect?to=http://...`) which are not archived by the Wayback Machine, but the destination URLs might not be archived as well.
* WaybackProxy is not a generic proxy. The POST and CONNECT methods are not implemented.
