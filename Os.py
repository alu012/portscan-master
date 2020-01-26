import sys
import os

halt = False
os.system('cls')

try:
    import nmap
    from datetime import datetime
except ImportError:

    print('\nMissing needed module: \n   nmap\n   datetime')
    halt = True
    if halt:
        sys.exit() 

os.system('cls')

nm_scanner=nmap.PortScanner()

print("Running...\n")
nm_scan = nm_scanner.scan(sys.argv[1], '80', arguments = '-O')

host_is_up = "The host is :" + nm_scan['scan'][sys.argv[1]]['status']['state']+".\n"
port_open = "Port 80 is :" + nm_scan['scan'][sys.argv[1]]['tcp'][80]['state']+".\n"
method_scan = "Scanning method is :" + nm_scan['scan'][sys.argv[1]]['tcp'][80]['reason']+".\n"
predicted_os = "Predicted Operating System is :" + nm_scan['scan'][sys.argv[1]]['osmatch'][0]['osclass'][0]['osfamily']+".\n"
prediction_per = "OS Prediction percentage is :" + nm_scan['scan'][sys.argv[1]]['osmatch'][0]['accuracy']+".\n"


with open("osinfo.txt",'w') as f:
    f.write( host_is_up+port_open+method_scan+predicted_os+prediction_per )
    now = datetime.now();
    f.write("\nTimestamp :" +now.strftime("%Y-%m-%d_%H:%M:%S"))

print("\nCompleted....")
