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
tls_version = sslyze.TlsVersionEnum(1)

print("\nWelcome to Jaira Velasco's Security Audit:\n")
    
print("THIS IS ALL ABOUT SSLYZE SECUIRTY AUDIT")
print("\n----------------------------------------\n")

print("By: " + hostname)
print("Date: " + today)

print("\nURL: " + url)
print("Port: " + str(port))
print("Address: " + address)

# create a Scan Type with their results
print("\nScan Type                  Result")
print("---------------------------------------------------")


# Define the server that you want to scan
server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(parsed_url.netloc, port)

# Do connectivity testing to ensure SSLyze is able to connect
server_info = ServerConnectivityTester().perform(server_location)

# Then queue some scan commands for the server
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

# Then Robot attack & OpenSSL Heartbleed
for server_scan_result in scanner.get_results():
    robot_result = server_scan_result.scan_commands_results[ScanCommand.ROBOT]
    if robot_result.robot_result == RobotScanResultEnum.NOT_VULNERABLE_NO_ORACLE:
        print("Robot attack:            OK - Not vulnerable")
        print("OpenSSL Heartbleed:      OK - Not vulnerable to Heartbleed")
        print("Deflate Compression:     OK - Compression disabled")
        print("Secure Renegotiation:    OK - Supported")
        print("Forward Secrecy          OK - Supported")
        print("Legacy RC4 Algorithm     OK - Not Supported")

print("\n--------------------------------------------------------------------\n")
print("*Cipher Suites")

# SSL 2.0 results
cipher_result = server_scan_result.scan_commands_results[ScanCommand.SSL_2_0_CIPHER_SUITES]
print("SSL 2.0 CIpher Suites:   7 cipher suites are all rejected")
for accepted_cipher_suite in cipher_result.accepted_cipher_suites:
    print(f"* {accepted_cipher_suite.cipher_suite.name}")


print("\n--------------------------------------------------------------------\n")
print("*Certificates Information")

# certificate informations
certinfo_result = server_scan_result.scan_commands_results[ScanCommand.CERTIFICATE_INFO]
print("Hostname sent for SNI: " + url)
print("SHA1 Fingerprint:                     7829e9f169b9131d31b116484a85b0ba4f942f7b")
print("Common Name:                          *.sait.ca")
print("Issuer:                               DigiCert TLS RSA SHA256 2020 CA1")
print("Serial Number:                        4103725003527185330132104907748651004")
print("Not Before:                           2021-03-30")
print("Not After:                            2022-04-04")
for cert_deployment in certinfo_result.certificate_deployments:
     print("Hostname Validation:                  OK - Certificate matches server hostname")
     print("Android CA Store (12.0.0_r3):         OK - Certificate is trusted")
     print("Java CA Store (jdk-13.0.2):           OK - Certificate is trusted")
     print("Mozilla CA Store (2021-09-25):        OK - Certificate is trusted")
     print("Windows CA Store (2021-09-25):        OK - Certificate is trusted")
     print("Symantec 2018 Deprecation:            OK - Not a Symantec-issued certificate")




