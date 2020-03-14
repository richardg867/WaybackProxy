# Listen port for the HTTP proxy
LISTEN_PORT = 8888

# Date to get pages from Wayback (YYYY, YYYYMM or YYYYMMDD)
DATE = '1998'

# Send Geocities requests to oocities.org
GEOCITIES_FIX = True

# Use the Wayback-tampered URL as a shortcut when loading images.
# May result in faster loads, but all images will point to 
# http://web.archive.org/... as a result.
QUICK_IMAGES = True

# Allow the Content-Type header to contain an encoding. Some old browsers
# (Mosaic?) don't understand that and fail to load anything - set this to
# False if you're using one of them.
CONTENT_TYPE_ENCODING = True

# Don't print log entries
SILENT = True
