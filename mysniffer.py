import socket
from general import *
from networking.ethernet import Ethernet
from networking.ipv4 import IPv4
from networking.icmp import ICMP
from networking.tcp import TCP
from networking.udp import UDP
from networking.pcap import Pcap
from networking.http import HTTP
import time
import re
import logging
logging.basicConfig(filename='snort.log',level=logging.DEBUG)

loginIPs = {}

#Default credentials for the device
default_u = "hello"
default_p = "world"


class Ipinfo:
    def __init__(self,ip,user):
        self.ip = ip
        self.user = user
        self.count = 0
        self.firsttime = time.time()
        self.delete = 0
        self.latest = time.time()


def logdefaultcred(ip, uname):
    logging.warning("DEFAULT_CRED : Login attempt with default credentials from "+ip)
    return

def trackLogin(ip, uname):
    #print("in tracking "+ip+" "+uname)
    key = hash(ip+uname)
    if key in loginIPs.keys():
        x = loginIPs[key]
        x.count += 1
        count = x.count
        e1 = time.time() - x.firsttime
        del_min = e1 % 3600 // 60
        if (count > 8 and (time.time() - x.latest)%3600 // 60) > 1:
            x.count + 1
            #loginIPs.pop(key, None)
            return
        elif count > 8 and del_min<30:
            logging.error("MULTIPLE_LOGIN : More then 4 attempts in "+str(del_min)+"  minutes")
        elif count>8:
            logging.warning("MULTIPLE_LOGIN : More then 4 attempts in "+str(del_min)+"  minutes")
        x.latest = time.time()
    else:
        x=Ipinfo(ip, uname)
        x.count += 1
        x.latest = time.time()
        loginIPs[key] = x


TAB_3 = '\t\t\t   '


def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65535)
        eth = Ethernet(raw_data)
        # IPv4
        if eth.proto == 8:
            ipv4 = IPv4(eth.data)

            # ICMP
            if ipv4.proto == 1:
                icmp = ICMP(ipv4.data)

            # TCP
            elif ipv4.proto == 6:
                tcp = TCP(ipv4.data)

                if len(tcp.data) > 0:

                    # HTTP
                    if tcp.src_port == 9010 or tcp.dest_port == 9010:
                        try:
                            http = HTTP(tcp.data)
                            http_info = str(http.data).split('\n')
                            for line in http_info:
                                if 'Authorization' in line:
                                    #print(str(line))
                                    try:
                                        p = re.compile('Authorization: Basic (([A-Za-z0-9@#$%^&+=]+)):')
                                        if p.match(line):
                                            username = p.match(line).group(1)
                                            if (username == default_u):
                                                logdefaultcred(ipv4.src, username)
                                            trackLogin(ipv4.src, username)
                                    except Exception as ex:
                                        print("Regex exception")
                                        print(ex)
                        except:
                            print("HTTP exception")
                    else:
                        print('\t\tTCP Data:')
                        print(format_multi_line(TAB_3, tcp.data))

            # UDP
            elif ipv4.proto == 17:
                udp = UDP(ipv4.data)
            # Other IPv4
            else:
               pass

        else:
            pass

    pcap.close()


main()
