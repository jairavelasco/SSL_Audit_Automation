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
print("\n----------------------------------------\n")

print("By: " + hostname)
print("Date: " + today)

print("\nURL: " + url)
print("Port: " + str(port))
print("Address: " + address)