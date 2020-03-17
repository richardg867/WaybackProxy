# Listen port for the HTTP proxy.
LISTEN_PORT = 8888

# Date to get pages from Wayback. YYYYMMDD, YYYYMM and YYYY formats are
# accepted, the more specific the better.
DATE = '20011025' # <- Windows XP release date in case you're wondering

# Allow the client to load pages and assets up to X days after DATE.
# Set to None to disable this restriction.
DATE_TOLERANCE = 365

# Send Geocities requests to oocities.org
GEOCITIES_FIX = True

# Use the Wayback-tampered URL as a shortcut when loading images.
# May result in faster loads, but all images will point to 
# http://web.archive.org/... as a result. Set this value to 2 to enable an
# experimental mode using authentication on top of the original URLs instead
# (which is not supported by Internet Explorer and some other browsers).
QUICK_IMAGES = True

# Allow the Content-Type header to contain an encoding. Some old browsers
# (Mosaic?) don't understand that and fail to load anything - set this to
# False if you're using one of them.
CONTENT_TYPE_ENCODING = True

# Disables logging if set to True.
SILENT = False
