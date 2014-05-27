#CDP Information Gathering
#Programming By Farzin(Enddo)

import socket
import struct
import binascii
def show_result(pkt):
        #***********CDP VERSION*********
        version = struct.unpack('!B',pkt[0][22:23])
        #***********DEVICE ID*********

        id_len = binascii.hexlify(pkt[0][28:30])
        num = str(int(id_len,16) - 4)
        id = struct.unpack('!'+ num  +'s',pkt[0][30:30 + int(num)])
        #***********SOFTWARE INFORMATION*********
        software_len = binascii.hexlify(pkt[0][28 + int(id_len,16)  : 30 +
int(id_len,16)])
        num = str(int(software_len,16) - 4)
        software = struct.unpack('!' + num + 's' , pkt[0][30 + int(id_len,16)
:30 + int(id_len,16) + int(num)])
        print "CDP Version : " + str(version[0])
        print "Device ID : " + id[0]
        print "Software Information : " + software[0]
        print "****************************************"

cdp = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
try:
    while True:
            pkt = cdp.recvfrom(2048)
            if(len(pkt) > 0):
                    ether = pkt[0][0:14]
                    ether = struct.unpack('!6s6s2s', ether)
                    dst_mac = binascii.hexlify(ether[0])
                    src_mac = binascii.hexlify(ether[1])
                    if(dst_mac == '01000ccccccc'):
                            print "****************************************"
                            print "CISCO DEVICE FOUND - Source MAC : " + src_mac
                            show_result(pkt)
except:
    cdp.close()
