import time
match_list = []
filex = open('schedule_task','r')
file_to_dump = open('Final_values_to_plot', 'a')
linesx = filex.readlines()
#print(lines)
last_linex  = linesx[-2:]
match_list.append(last_linex[1])
def getPacketsPersecond():
    file = open('schedule_task','r')
    lines = file.readlines()
    #print(lines)
    last_line  = lines[-2:]
    if(last_line[1] != match_list[0]):
        line1 = last_line[0].split(',')
        icmp1 = int(line1[0].split(':')[1])
        tcp1 = int(line1[1].split(':')[1])
        udp1 = int(line1[2].split(':')[1])
        # print("icmp1:{}, tcp1:{}, ucp1:{}".format(icmp1,tcp1,udp1))

        line2 = last_line[1].split(',')
        icmp2 = int(line2[0].split(':')[1])
        tcp2 = int(line2[1].split(':')[1])
        udp2 = int(line2[2].split(':')[1])
        # print("icmp2:{}, tcp2:{}, ucp2:{}".format(icmp2,tcp2,udp2))

        # print("Increment in packets")
        str1 = "{} {} {}".format(max(0,(icmp2 - icmp1)), max(0,(tcp2 - tcp1)), max(0,(udp2 - udp1)))
        #print("{} {} {}".format(max(0,(icmp2 - icmp1)), max(0,(tcp2 - tcp1)), max(0,(udp2 - udp1))))
        file_to_dump.writelines(str1)
        match_list.clear()
        match_list.append(last_line[1])
        # yahan par data aa gaya
        return max(0,(icmp2 - icmp1)), max(0,(tcp2 - tcp1)), max(0,(udp2 - udp1))
    else:
        str2 = "{} {} {}".format(0,0,0)
        file_to_dump.writelines(str2)
        #print("{} {} {}".format(0,0,0))

        return 0,0,0
    #time.sleep(4)

getPacketsPersecond()