import json
import os

# # Listen port for the HTTP proxy.
# global LISTEN_PORT

# # Date to get pages from Wayback. YYYYMMDD, YYYYMM and YYYY formats are
# # accepted, the more specific the better.
# global DATE 

# # Allow the client to load pages and assets up to X days after DATE.
# # Set to None to disable this restriction.
# global DATE_TOLERANCE

# # Send Geocities requests to oocities.org if set to True.
# global GEOCITIES_FIX

# # Use the original Wayback Machine URL as a shortcut when loading images.
# # May result in faster page loads, but all images will point to
# # http://web.archive.org/... as a side effect. Set this value to 2 to enable an
# # experimental mode using authentication on top of the original URLs instead
# # (which is not supported by Internet Explorer and some other browsers).
# global QUICK_IMAGES

# # Use the Wayback Machine Availability API to find the closest available
# # snapshot to the desired date, instead of directly requesting that date. Helps
# # in situations where an image returns a server error on the desired date, but
# # is available at an earlier date. As a side effect, pages will take longer to
# # load due to the added API call. If enabled, this option will disable the
# # QUICK_IMAGES bypass mechanism built into the PAC file.
# global WAYBACK_API

# # Allow the Content-Type header to contain an encoding. Some old browsers
# # (Mosaic?) don't understand that and fail to load anything - set this to
# # False if you're using one of them.
# global CONTENT_TYPE_ENCODING

# # Disables logging if set to True.
# global SILENT

# # Enables the settings page on http://web.archive.org if set to True.
# global SETTINGS_PAGE

def load_config(file_name='config.json'):
    if not os.path.isabs(file_name):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        file_name = os.path.join(dir_path, file_name)
    
    with open(file_name, 'r', encoding='utf8', errors='ignore') as f:
        return json.loads(f.read())