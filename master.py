import sys
import os

halt = False
os.system('cls')

try:
    import nmap

except ImportError:

    print('\nMissing needed module: \n   nmap')
    halt = True
    if halt:
        sys.exit() 

os.system('cls')

nm = nmap.PortScanner()

print('Welcome, this is a port13 scan tool')
print('<----------------------------------------------------->')

target = input('Please enter the IP address you want to scan: ')

resp = input('''\nPlease enter the type of scan you want to run
                1) SYN ACK Scan
                2) UDP Scan
                3) TCP NULL Scan
                4) FIN Scan
                5) Xmas Scan
                6) Comprehensive Scan \n''')

class Port13(object):

    def type_scan(num):        
# TCP Scan

        if num == '1':


            nm.scan(target, '1-1024', arguments = '-v -sS -F')
            for host in nm.all_hosts():
                print('<----------------------------------------------------->')
                print('Host : %s (%s)' %(host, nm[host].hostname()))
                print('State : %s' %host, nm[host].state())
                for proto in nm[host].all_protocols():
                    print('<----------------------->')
                    print('Protocol : %s' % proto)

                    lport = nm[host][proto].keys()
                    lport.sort()
                    for port in lport:
                        print('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))

            print('<----------------------------------------------------->')            
            print(nm.csv())         

# UDP Scan                    

        elif num == '2':

            nm.scan(target, '1-1024', arguments = '-v -sU')
            for host in nm.all_hosts():
                print('<----------------------------------------------------->')
                print('Host : %s (%s)' %(host, nm[host].hostname()))
                print('State : %s' %host, nm[host].state())
                for proto in nm[host].all_protocols():
                    print('<----------------------->')
                    print('Protocol : %s' % proto)

                    lport = nm[host][proto].keys()
                    lport.sort()
                    for port in lport:
                        print('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))

            print('<----------------------------------------------------->')            
            print(nm.csv())  

# TCP NULL Scan

        elif num == '3':

            nm.scan(target, '1-1024', arguments = '-v -sN')
            for host in nm.all_hosts():
                print('<----------------------------------------------------->')
                print('Host : %s (%s)' %(host, nm[host].hostname()))
                print('State : %s' %host, nm[host].state())
                for proto in nm[host].all_protocols():
                    print('<----------------------->')
                    print('Protocol : %s' % proto)

                    lport = nm[host][proto].keys()
                    lport.sort()
                    for port in lport:
                        print('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))

            print('<----------------------------------------------------->')            
            print(nm.csv())  

# FIN Scan

        elif num == '4':

            nm.scan(target, '1-1024', arguments = '-v -sF')
            for host in nm.all_hosts():
                print('<----------------------------------------------------->')
                print('Host : %s (%s)' %(host, nm[host].hostname()))
                print('State : %s' %host, nm[host].state())
                for proto in nm[host].all_protocols():
                    print('<----------------------->')
                    print('Protocol : %s' % proto)

                    lport = nm[host][proto].keys()
                    lport.sort()
                    for port in lport:
                        print('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))

            print('<----------------------------------------------------->')            
            print(nm.csv())  

# Xmas Scan

        elif num == '5':

            nm.scan(target, '1-1024', arguments = '-v -sX')
            for host in nm.all_hosts():
                print('<----------------------------------------------------->')
                print('Host : %s (%s)' %(host, nm[host].hostname()))
                print('State : %s' %host, nm[host].state())
                for proto in nm[host].all_protocols():
                    print('<----------------------->')
                    print('Protocol : %s' % proto)

                    lport = nm[host][proto].keys()
                    lport.sort()
                    for port in lport:
                        print('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))

            print('<----------------------------------------------------->')            
            print(nm.csv())  

# Comprehensive Scan

        elif num == '6':

            nm.scan(target, '1-1024', arguments = '-v -sS -sV -sC -A -O')
            for host in nm.all_hosts():

                predicted_os = 'Predicted Operating System is :' +nm[host]['osmatch'][0]['osclass'][0]['osfamily']+'.\n'
                prediction_per = 'OS Prediction percentage is :' +nm[host]['osmatch'][0]['accuracy']

                print('<----------------------------------------------------->')
                print('Host : %s (%s)' %(host, nm[host].hostname()))
                print('OS :' + predicted_os+prediction_per)
                print('State : %s' %host, nm[host].state())
                for proto in nm[host].all_protocols():
                    print('<----------------------->')
                    print('Protocol : %s' % proto)

                    lport = nm[host][proto].keys()
                    lport.sort()
                    for port in lport:
                        print('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))

            print('<----------------------------------------------------->')            
            print(nm.csv())  

        else :
            print('Please enter a valid option')

if __name__=='__main__':
    
    s = Port13()
    s.type_scan(resp)       