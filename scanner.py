from datetime import datetime
import socket 
from urllib.parse import urlparse
from sslyze import (
    ServerNetworkLocationViaDirectConnection,
    ServerConnectivityTester,
    Scanner,
    ServerScanRequest,
    ScanCommand,
    RobotScanResultEnum,
)
from sslyze.errors import ConnectionToServerFailed

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

# create a Scan Type with their results
print("\nScan Type              Result")
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
    },
)
scanner.start_scans([server_scan_req])

# Then retrieve the results
for server_scan_result in scanner.get_results():
    robot_result = server_scan_result.scan_commands_results[ScanCommand.ROBOT]
    if robot_result.robot_result == RobotScanResultEnum.NOT_VULNERABLE_NO_ORACLE:
        print("Robot attack:          OK - Not vulnerable")