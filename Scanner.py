try:
    import os
    import socket
    import multiprocessing
    import subprocess
    import os
    from subprocess import Popen, PIPE
    import re
    import requests
    import nmap
    import xlwt
    import threading
    print("Library and Modules Loaded .......")
except:
    print("""No Library Found
     Please Make sure you have Following Library installed
      
    import os
    import socket
    import multiprocessing
    import subprocess
    import os
    from subprocess import Popen, PIPE
    import re
    
     """)

class Sniffer(object):

    def __init__(self):
        pass

    def __pinger(self, job_q, results_q):

        DEVNULL = open(os.devnull, 'w')
        while True:
            ip = job_q.get()
            if ip is None:
                break
            try:
                subprocess.check_call(['ping', '-c1', ip],
                                      stdout=DEVNULL)
                results_q.put(ip)
            except:
                pass

    def __get_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip

    def get_Mac_Address(self,IP = '192.168.1.1'):
        pid = Popen(["arp", "-n", IP], stdout=PIPE)
        s = pid.communicate()[0]
        s = s.decode('utf-8')
        mac = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", s).groups()[0]

        vendor_mac = mac.split(":")
        mac_vendor = ''.join(vendor_mac)[0:6]
        url = "https://macvendors.com/query/{}".format(mac_vendor)
        r = requests.get(url)
        vendor_mac_v = r.text

        if len(vendor_mac_v) > 20:
            mac_vendor_name = "Not Found"
        else:
            mac_vendor_name = r.text
        return mac, mac_vendor_name

    def get_host(self, pool_size=255):
        ip_list = list()

        # get my IP and compose a base like 192.168.1.xxx
        ip_parts = self.__get_ip()
        ip_parts = ip_parts.split(".")

        ip_parts = self.__get_ip().split('.')
        base_ip = ip_parts[0] + '.' + ip_parts[1] + '.' + ip_parts[2] + '.'

        # prepare the jobs queue
        jobs = multiprocessing.Queue()
        results = multiprocessing.Queue()

        pool = [multiprocessing.Process(target=self.__pinger, args=(jobs, results)) for i in range(pool_size)]

        for p in pool:
            p.start()

        # cue hte ping processes
        for i in range(1, 255):
            jobs.put(base_ip + '{0}'.format(i))

        for p in pool:
            jobs.put(None)

        for p in pool:
            p.join()

        # collect he results
        while not results.empty():
            ip = results.get()
            ip_list.append(ip)

        return ip_list

    def ip_scan(self,ip_address = "192.168.1.1"):
        try:
            scanner = nmap.PortScanner()
            scanner.scan(hosts=ip_address)
            ip_status = scanner[ip_address].state()

            for host in scanner.all_hosts():
                my_host = []
                my_protocol = []
                my_port =[]

                my_host.append(host)
                for proto in scanner[host].all_protocols():
                    my_protocol.append(proto)
                    lport = scanner[host][proto].keys()
                    for port in lport:
                        my_port.append(port)

            return my_port , my_protocol, ip_status
        except:
            pass

    def my_excel(self,x , my_port , my_protocol, ip_status,mac, mac_vendor_name,counter):
        print("Counter", counter)
        wb = xlwt.Workbook()

        ws = wb.add_sheet("Report")

        ws.write(0, 0, "IP Adress")
        ws.write(0, 1, "MAC Address")
        ws.write(0, 2, "Vendor")
        ws.write(0, 3, "Status")
        ws.write(0, 4, "Port ")

        str1 = ''
        str1 = ''.join(str(e) for e in my_port)

        ws.write(counter, 0, x)         # HOST

        ws.write(counter, 1, mac)        # Mac

        ws.write(counter, 2, mac_vendor_name)    # Vendor

        ws.write(counter, 3, ip_status)    # Vendor

        ws.write(counter, 4, str1)    # Vendor

        wb.save('Report.xls')


if __name__ == "__main__":
    counter = 1

    s = Sniffer()
    ip = s.get_host()

    for x in ip:
        try:
            counter = counter + 1

            mac, mac_vendor_name = s.get_Mac_Address(IP=x)

            my_port , my_protocol, ip_status = s.ip_scan(ip_address=x)

            s.my_excel(x , my_port , my_protocol, ip_status,mac, mac_vendor_name,counter)

            print(" Ip:\t{} \t MAC:\t{} \t\t vendor: \t {} \t\tStatus {} \t\t\t Port Open {} " .format(x,mac,mac_vendor_name,ip_status,my_port))
        except:
            pass