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
        print("OpenSSL Heartbleed:        OK - Not vulnerable to Heartbleed")

# OpenSSL Heartbleed 
for server_scan_result in scanner.get_results():
    heartbleed_result = server_scan_result.scan_commands_results[ScanCommand.HEARTBLEED]       
    if heartbleed_result.heartbleed_result == HeartbleedScanResult.is_vulnerable_to_heartbleed:
        print("OpenSSL Heartbleed:        OK - Not vulnerable to Heartbleed")

# SSL 2.0 results
cipher_result = server_scan_result.scan_commands_results[ScanCommand.SSL_2_0_CIPHER_SUITES]
print("SSL 2.0 CIpher Suites:   7 cipher suites are all rejected")
for accepted_cipher_suite in cipher_result.accepted_cipher_suites:
    print(f"* {accepted_cipher_suite.cipher_suite.name}")

print("\n--------------------------------------------------------------------\n")
print("*Certificates Information")

# certificate informations
certinfo_result = server_scan_result.scan_commands_results[ScanCommand.CERTIFICATE_INFO]
print("\nCertificate info:")
for cert_deployment in certinfo_result.certificate_deployments:
     print(f"Leaf certificate: \n{cert_deployment.received_certificate_chain_as_pem[0]}")




