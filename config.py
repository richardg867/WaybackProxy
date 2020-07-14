# Listen port for the HTTP proxy.
LISTEN_PORT = 8888

# Date to get pages from Wayback. YYYYMMDD, YYYYMM and YYYY formats are
# accepted, the more specific the better.
DATE = '20011025' # <- Windows XP release date in case you're wondering

# Allow the client to load pages and assets up to X days after DATE.
# Set to None to disable this restriction.
DATE_TOLERANCE = 365

# Send Geocities requests to oocities.org if set to True.
GEOCITIES_FIX = True

# Use the original Wayback Machine URL as a shortcut when loading images.
# May result in faster page loads, but all images will point to
# http://web.archive.org/... as a side effect. Set this value to 2 to enable an
# experimental mode using authentication on top of the original URLs instead
# (which is not supported by Internet Explorer and some other browsers).
QUICK_IMAGES = True

# Use the Wayback Machine Availability API to find the closest available
# snapshot to the desired date, instead of directly requesting that date. Helps
# in situations where an image returns a server error on the desired date, but
# is available at an earlier date. As a side effect, pages will take longer to
# load due to the added API call. If enabled, this option will disable the
# QUICK_IMAGES bypass mechanism built into the PAC file.
WAYBACK_API = True

# Allow the Content-Type header to contain an encoding. Some old browsers
# (Mosaic?) don't understand that and fail to load anything - set this to
# False if you're using one of them.
CONTENT_TYPE_ENCODING = True

# Disables logging if set to True.
SILENT = False

# Enables the settings page on http://web.archive.org if set to True.
SETTINGS_PAGE = True
