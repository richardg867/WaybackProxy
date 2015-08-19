# WaybackProxy

WaybackProxy is a HTTP proxy that sends all requests through the [Internet Archive Wayback Machine](http://web.archive.org) and [OoCities](http://www.oocities.org), returning the original antique-browser-friendly markup.

![1999 Google viewed on Internet Explorer 4.0 on Windows 95](http://i.imgur.com/tXsLc6O.png)

## Setup

1. Edit `settings.py` to your liking
2. Start `waybackproxy.py`
3. Set your antique browser to use a HTTP proxy at the IP and port WaybackProxy is listening on
4. Try it out! You can edit most settings that are in `settings.py` by browsing to http://web.archive.org while on the proxy, although you must edit `settings.py` to make them permanent.
5. Press Ctrl+C to stop

## Limitations

* The Wayback Machine itself. For one, sometimes archived pages lack random images for no reason at all.
* 302 redirects are handled using a meta refresh hack, as Wayback sends them as regular pages.
* WaybackProxy is not an all-around proxy. The POST and CONNECT methods are not implemented.
