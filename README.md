# WaybackProxy

WaybackProxy is a retro-friendly HTTP proxy which retrieves pages from the [Internet Archive Wayback Machine](http://web.archive.org) or [OoCities](http://www.oocities.org) and delivers them in their original form, without toolbars, scripts and other extraneous content that may confuse retro browsers.

![1999 Google viewed on Internet Explorer 4.0 on Windows 95](http://i.imgur.com/tXsLc6O.png)

## Setup

1. Edit `config.py` to your liking
2. Start `waybackproxy.py` (Python 3 is required)
3. Set up your retro browser:
	* If your browser supports proxy auto-configuration, set the auto-configuration URL to `http://ip:port/proxy.pac` where `ip` is the IP of the system running WaybackProxy and `port` is the proxy's port (8888 by default).
	* If proxy auto-configuration is not supported or fails to work, set the browser to use an HTTP proxy at that IP and port instead.
	* Transparent proxying is also supported for advanced users, with no configuration to WaybackProxy itself required.
		* The easiest way to set up a transparent WaybackProxy is to run it on port 80 ([this cannot be done on Linux without security implications](https://unix.stackexchange.com/questions/87348/capabilities-for-a-script-on-linux)\), set up a fake DNS server - such as `dnsmasq -A "/#/ip"` where `ip` is the IP of the system running WaybackProxy - to redirect all requests to the proxy, and point client machines at that DNS server.
4. Try it out! You can edit most settings that are in `config.py` by browsing to http://web.archive.org while on the proxy, although you must edit `config.py` to make them permanent.
5. Press Ctrl+C to stop the proxy

## Known issues and limitations

* The Wayback Machine itself is not 100% reliable. Known issues include:
  * Pages newer than the specified date (setting a specific YYYYMMDD date instead of a wider YYYYMM or YYYY helps with that);
  * Random broken images;
  * Strange 404 errors caused by bad server responses or incorrect URL capitalization at archival time;
  * Infinite redirect loops;
  * Server errors when it's having a bad day.
* WaybackProxy will work around some redirection scripts (example: `http://example.com/redirect?to=http://...`) which are not archived by the Wayback Machine, but the destination URLs are sometimes not archived either.
* WaybackProxy is not a generic proxy. The POST and CONNECT methods are not implemented.
* Transparent proxying mode requires HTTP/1.1 and therefore cannot be used with some really old (pre-1996) browsers. Use standard mode with such browsers.

## Docker Container

A Dockerfile is included that allows you to run WaybackProxy from a docker container. 

### Environment Variables

When deploying via Docker, the config.py script can be customized by specifying environment variables when creating the docker container. The environment variables match the example config.py script in this repository. Below is a complete list:

| Parameter        | Default | Description                            |
|------------------|----------------------------------------|
| `LISTEN_PORT` | 8888 | Listen port for the HTTP proxy |
| `DATE` | 20011025 | Date to get pages from Wayback. YYYYMMDD, YYYYMM and YYYY formats are accepted, the more specific the better.|
| `DATE_TOLERANCE` | 365 | Allow the client to load pages and assets up to X days after DATE. Set to None to disable this restriction.|
| `GEOCITIES_FIX` | True | Send Geocities requests to oocities.org if set to True. |
| `QUICK_IMAGES` | True | Use the original Wayback Machine URL as a shortcut when loading images. |
| `WAYBACK_API` | True | Use the Wayback Machine Availability API to find the closest available snapshot to the desired date, instead of directly requesting that date.|
| `CONTENT_TYPE_ENCODING` | True | Allow the Content-Type header to contain an encoding |
| `SILENT` | True | Disables logging to STDOUT if set to True |
| `SETTINGS_PAGE` | True | Enables the settings page on http://web.archive.org if set to True |

### Example docker commands

To build:

```bash
docker build --no-cache -t waybackproxy .
```
To run:

```bash
docker run --rm -it -e DATE=20011225 -p 8888:8888 waybackproxy
```

## Other links

* [Donate to the Internet Archive](https://archive.org/donate/), they need your help to keep the Wayback Machine and its petabytes upon petabytes of data available to everyone for free with no ads.
* [Check out 86Box](https://86box.github.io/), the emulator I use for testing WaybackProxy on older browsers.
