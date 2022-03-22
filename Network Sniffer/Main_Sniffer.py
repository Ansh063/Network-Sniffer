'''

    Sniffer to capture real time traffic and print the packet rate after every 2 seconds

'''

import socket
import struct
import textwrap
import termcolor
import math
from get_iot_ips import get_all_iot_ips
import time
import schedule
from multiprocessing import Process


TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '

# Return properly formatted mac address (human readable format i.e AA:BB:CC:DD:EE:FF)
def get_mac_address(byte_addr):
    byte_str = map('{:02x}'.format, byte_addr)
    mac_addr = ':'.join(byte_str).upper()
    return mac_addr

# Returns Properly Formatted IPv4 Address
def ipv4(addr):
    return '.'.join(map(str, addr))

# unpack ethernet frame
def ethernet_Frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_address(dest_mac), get_mac_address(src_mac), socket.htons(proto), data[14:]

# Unpack IPv4 Packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, ip_proto, src, target = struct.unpack('! 8x B B 2x 4s 4s',data[:20])
    return version, header_length, ttl, ip_proto, ipv4(src), ipv4(target), data[header_length:]

# Unpack ICMP Packets :

def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H',data[:4])
    return icmp_type, code, checksum, data[4:]

# Unpack TCP Segment :

def tcp_segment(data):
    (src_port, dst_port, sequence, acknowledgement, offset_reserved_flag) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flag >> 12) * 4
    flag_urg = (offset_reserved_flag & 32) >> 5
    flag_ack = (offset_reserved_flag & 16) >> 4
    flag_psh = (offset_reserved_flag & 8) >> 3
    flag_rst = (offset_reserved_flag & 4) >> 2
    flag_syn = (offset_reserved_flag & 2) >> 1
    flag_fin = offset_reserved_flag & 1
    return src_port, dst_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]


# Unpack UDP Segment :

def udp_segment(data):
    src_port, dst_port, size = struct.unpack('! H H 2x H',data[:8])
    return src_port, dst_port, size

# Formats Multiline Data :

def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string,bytes) :
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if (size % 2) :
            size-=1
    return '\n'.join([prefix + line for line in textwrap.wrap(string,size)])

'''
    Return all the average of all the packets in every 30 seconds: 
'''

#def average_packet_rate():

def test2():
    icmp_initial = 0
    tcp_initial = 0
    udp_initial = 0
    icmp_final,tcp_final,udp_final = Sniffer2()
    s = "icmp_initial:{}, tcp_initial:{}, udp_initial:{}, icmp_final:{}, tcp_final:{}, udp_final:{}, time:{}\n".format(icmp_initial,tcp_initial,udp_initial,icmp_final,tcp_final,udp_final,math.floor(time.time()))
    t = open('schedule_task','a')
    t.writelines(s)
    icmp_final = icmp_initial
    tcp_initial = tcp_final
    udp_initial = udp_final

def test():
    s = "I am called in every 2 min :{}\n".format(math.floor(time.time()))
    t = open('schedule_task','a')
    t.writelines(s)

def Sniffer1():
    schedule.every(1).seconds.do(test2)
    while True:
        schedule.run_pending()

def Sniffer2():
    icmp_initial_counter = 0
    tcp_initial_counter = 0
    udp_initial_counter = 0
    icmp_final_counter = 0
    tcp_final_counter = 0
    udp_final_counter = 0
    '''
        Fetching all the IP that are given to the IOT devices
        Sniffer get modified according to the list of IOT ip
    '''

    list_of_iot_ip = get_all_iot_ips()
    #print(list_of_iot_ip)

    time2 = time.time()

    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    time_list = []
    while True:
        #
        #raw_data, addr = conn.recvfrom(65536)
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_Frame(raw_data)
        #print('\nEthernet Frame:')
        #print(TAB_1 + 'Destination:{}, Source:{}, Protocol:{}'.format(dest_mac, src_mac, eth_proto))
        #print('Des:{}, Sou:{}, Proto:{}'.format(dest_mac, src_mac, eth_proto))
        #print("ICMP_Count :{}, UDP_Count:{}, TCP_Count:{}".format(icmp_initial_counter,udp_initial_counter,tcp_initial_counter))
        # 8 for IPv4 protocol
        if(eth_proto == 8):
            (version, header_length, ttl, ip_proto,src, target, data) = ipv4_packet(data)
            #print(TAB_1 + 'IPv4 Packet:')
            #print(TAB_2 + 'version :{}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
            #print(TAB_2 + 'Protocol :{}, Source: {}, Target: {}'.format(ip_proto,src, target))
            checking_flag = False
            #print("src:{}, target:{}".format(src,target))
            if(src not in list_of_iot_ip):
                checking_flag = True

            # Average function value :


            if (ip_proto == 1 and checking_flag):
                icmp_type, code, checksum, icmp_data = icmp_packet(data)
                #print(TAB_1 + 'ICMP Packet:')
                string = 'ICMP Packet, Dest_Mac:{}, Src_Mac:{}, Dest_IP:{}, Src_IP:{}, Proto:{}'.format(dest_mac, src_mac,target,src, eth_proto)
                print(termcolor.colored(string,color='red'))
                icmp_initial_counter  = icmp_initial_counter + 1
                #print('ICMP Packet, Des:{}, Sou:{}, Proto:{}'.format(dest_mac, src_mac, eth_proto))
                #print(', ICMP Packet:')
                #print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                #print(TAB_2 + 'Data:')
                #print(format_multi_line(DATA_TAB_3, icmp_data))
            # TCP :
            elif (ip_proto == 6 and checking_flag):
                src_port, dst_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin,tcp_data = tcp_segment(data)
                string2 = 'TCP Segment, Dest_Mac:{}, Src_Mac:{}, Dest_IP:{}, Src_IP:{}, Proto:{}, src_port:{}, dst_port:{}'.format(dest_mac, src_mac,target,src, eth_proto, src_port, dst_port)
                print(termcolor.colored(string2, color='green'))
                tcp_initial_counter += 1
                '''
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + 'SourcePort: {}, DestinationPort: {}'.format(src_port, dst_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgement: {}'.format(sequence, acknowledgement))
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, tcp_data))
                '''
            # UDP :
            elif (ip_proto == 17 and checking_flag):
                src_port, dst_port, size = udp_segment(data)
                string3 = 'UDP Segment, Dest_Mac:{}, Src_Mac:{}, Dest_IP:{}, Src_IP:{}, Proto:{}, src_port:{}, dst_port:{}'.format(dest_mac, src_mac,target, src, eth_proto,src_port,dst_port)
                print(termcolor.colored(string3, color='blue'))
                udp_initial_counter += 1
                '''
                print(TAB_1 + 'UDP Segment :')
                print(TAB_2 + 'Source port: {}, Destination: {}, Length: {}'.format(src_port, dst_port, size))
                '''
            '''
            else:
                print(TAB_1 + 'DATA : ')
                print(format_multi_line(DATA_TAB_2, data))
            '''
        t = open('schedule_task', 'a')
        time1 = math.floor(time.time())
        if(time1 % 4 == 0):
            if(time1 not in time_list):
                s = "ICMP:{}, TCP:{}, UDP:{}, time:{}\n".format(icmp_initial_counter, tcp_initial_counter, udp_initial_counter, math.floor(time.time()))
                t.writelines(s)
                time_list.clear()
                time_list.append(time1)
        #return icmp_initial_counter, tcp_initial_counter, udp_initial_counter
        # else:
        #     #print('DATA : ')
        #     #print(format_multi_line(DATA_TAB_1, data))
        #     continue

Process(target=Sniffer2).start()


