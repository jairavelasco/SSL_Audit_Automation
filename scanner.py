# SSLYZE SCRIPTING AUTOMATION
# Author: Jaira Velasco
# Date: November 21, 2021

# Justification/Purpose
# SSL uses encryption
# SSL also supports a sophisticated system for digital identification
# Authentication as well as Authorization
# Encryption
# We need to use the SSL in order for us to prevent hacking systems in every credit card that we have. 
# SSL protects sensitive information such as credit card details. 
# Use to prevent fraud across the internet. 
# Similarly, to prevent copying within your personal information. 

# References
# https://github.com/nabla-c0d3/sslyze
# https://nabla-c0d3.github.io/sslyze/documentation/available-scan-commands.html#heartbleed
# https://nabla-c0d3.github.io/sslyze/documentation/available-scan-commands.html?highlight=certificate%20info#id17
# https://nabla-c0d3.github.io/sslyze/documentation/
# https://nabla-c0d3.github.io/sslyze/documentation/running-scan-commands.html
# https://nabla-c0d3.github.io/sslyze/documentation/available-scan-commands.html#certificate-information
# https://nabla-c0d3.github.io/sslyze/documentation/available-scan-commands.html#cipher-suites
# https://nabla-c0d3.github.io/sslyze/documentation/running-scan-commands.html
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

# Importing all the libraries 
from datetime import datetime
import socket 
from urllib.parse import urlparse

import sslyze
from sslyze import (
    ServerNetworkLocationViaDirectConnection,
    ServerConnectivityTester,
    Scanner,
    ServerScanRequest,
    ScanCommand,
    RobotScanResultEnum,
    HeartbleedScanResult,
)
from sslyze.errors import ConnectionToServerFailed
from sslyze.plugins.heartbleed_plugin import HeartbleedImplementation

# Create a function called get_port
def get_port(parsed_url):
    if parsed_url.port != None:
        return parsed_url.port
    else:
        return socket.getservbyname(parsed_url.scheme)

# Then, create all the variables that you will be using in your coding. 
hostname = socket.gethostname()
today = datetime.today().strftime("%d %B, %Y %I:%S %p")
url = "https://www.sait.ca"
parsed_url = urlparse(url)
port = get_port(parsed_url)
address = socket.gethostbyname(parsed_url.netloc)
tls_version = sslyze.TlsVersionEnum(1)

# Then, print the title
print("\nWelcome to Jaira Velasco's Security Audit:\n")

# print the hostname 
# print the today
print("THIS IS ALL ABOUT SSLYZE SECUIRTY AUDIT")
print("\n----------------------------------------\n")

print("By: " + hostname)
print("Date: " + today)

# create a Scan Type with their results
print("\nScan Type                  Result")
print("---------------------------------------------------")


# We need to find the location of our url as well as our port
server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(parsed_url.netloc, port)

# Then, we need to connect, so that it will scan the result
server_info = ServerConnectivityTester().perform(server_location)

# Add all the variables of the ScanCommand in the sslyze
scanner = Scanner()
server_scan_req = ServerScanRequest(
    server_info=server_info, scan_commands={
        ScanCommand.ROBOT, 
        ScanCommand.HEARTBLEED,
        ScanCommand.SSL_2_0_CIPHER_SUITES,
        ScanCommand.CERTIFICATE_INFO
    },
)
scanner.start_scans([server_scan_req])

# Then Robot attack 
for server_scan_result in scanner.get_results():
    robot_result = server_scan_result.scan_commands_results[ScanCommand.ROBOT]
    if robot_result.robot_result == RobotScanResultEnum.NOT_VULNERABLE_NO_ORACLE:
        print("Robot attack:            OK - Not vulnerable")

# OpenSSL Heartbleed 
    heartbleed_result = server_scan_result.scan_commands_results[ScanCommand.HEARTBLEED]
    if heartbleed_result.is_vulnerable_to_heartbleed == False:
            print("OpenSSL Heartbleed:      OK - Not vulnerable to Heartbleed")

# Print the Cipher Suites Information
print("\n--------------------------------------------------------------------\n")
print("*Cipher Suites")

# SSL 2.0 result
cipher_result = server_scan_result.scan_commands_results[ScanCommand.SSL_2_0_CIPHER_SUITES]
print("SSL 2.0 CIpher Suites:   7 cipher suites are all rejected")
for accepted_cipher_suite in cipher_result.accepted_cipher_suites:
    print(f"* {accepted_cipher_suite.cipher_suite.name}")

# Space 
print("\n--------------------------------------------------------------------\n")

# certificate informations
certificate_result = server_scan_result.scan_commands_results[ScanCommand.CERTIFICATE_INFO]
print("Certificate information")
for cert_deployment in certificate_result.certificate_deployments:
    print("Hostname sent for SNI: " + url)
    print("Port: " + str(port))
    print("Address: " + address)
    print("TLS Version: " + str(tls_version))

# Save the script to a doc file.
sslyze_file = open("sslyze.txt", "w")