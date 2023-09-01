# a dict that stores cached token, for example:
#
# CACHED_TOKEN: {
#         "<clientID>~<clientSecret>~<tenantID>": {
#             "token": "xxxxx",
#             "expiration": "xxxxxx"
#         },
#         "<clientID>~<clientSecret>~<tenantID>": {
#             "token": "xxxxx",
#             "expiration": "xxxxxx"
#         },
#         ......
#     }, 
CACHED_TOKEN = {}