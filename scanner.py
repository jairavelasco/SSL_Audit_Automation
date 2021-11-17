# References: 
# https://www.saltycrane.com/blog/2011/11/how-get-username-home-directory-and-hostname-python/
# https://docs.python.org/3/library/urllib.parse.html
# https://stackoverflow.com/questions/9530950/parsing-hostname-and-port-from-string-or-url
# https://github.com/nabla-c0d3/sslyze
# https://nabla-c0d3.github.io/sslyze/documentation/#installation
# https://pypi.org/project/sslyze/
# https://stackoverflow.com/questions/8370361/get-ip-address-of-url-in-python
# https://docs.python.org/3/library/urllib.parse.html
# https://intellipaat.com/community/19861/parsing-hostname-and-port-from-string-or-url
# https://pythonguides.com/python-get-an-ip-address/


from datetime import datetime
import socket 
from urllib.parse import urlparse


def get_port(parsed_url):
    if parsed_url.port != None:
        return parsed_url.port
    else:
        return socket.getservbyname(parsed_url.scheme)

hostname = socket.gethostname()
today = datetime.today().strftime("%d %B, %Y %I:%S %p")
url = "https://www.sait.ca"
parsed_url = urlparse(url)
port = get_port(parsed_url)
address = socket.gethostbyname(parsed_url.netloc)

print("\nWelcome to Jaira Velasco's Security Audit:\n")
    
print("THIS IS ALL ABOUT SSLYZE SECUIRTY AUDIT")
print()
print("----------------------------------------")
print()

print("By: " + hostname)
print("Date: " + today)

print()
print("URL: " + url)
print("Port: " + str(port))
print("Address: " + address)