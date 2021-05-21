from scapy.all import *
import sys
import logging
import csv
import subprocess as sub
#from scapy.layers.inet import *

ipholder = []
pingresponceholder = []
ipIdholder = []
ipIdtcpholder = []
portscanholder = []
syncookieholder = []
ttlholder = []
ttlTypeholder = []


def checkResponsive(pkt):
    reply = sr1(pkt, timeout=5)
    if reply:
        print (reply.src, "is online\n")
        pingresponceholder.append("ON")
        print(reply.ttl, "is the TTL\n")
        ttlholder.append(reply.ttl)
        #print(reply.window, "is the Window size\n")


        return True
    else:
        print ("Timeout waiting for %s \n" % pkt[IP].dst)
        pingresponceholder.append("OFF")
        ttlholder.append("NULL")
        ipIdholder.append("NULL")
        ipIdtcpholder.append("NULL")
        syncookieholder.append("NULL")
        portscanholder.append("NULL")
        ttlTypeholder.append("NULL")
        return False


def ipID(pkt):
    ans, unans = srloop(pkt, count=8)
    val = [a[1].id for a in ans]
    #val = ans.filter(lambda x:x[1].id)
    print(val)

    if(len(val) >=3):
        if int(val[0])+1==int(val[1]) and int(val[1])+1==int(val[2]) :
            print("Its Incremental\n")
            ipIdholder.append("INCREMENTAL")
            
        ##elif val[0]==0 and val[1]==0 and val[2]==0:
        elif val[0]== val[1] and val[1]== val[2]:
            print("Its Zero\n")
            ipIdholder.append("ZERO")
        else:
            print("Its Random\n")
            ipIdholder.append("RANDOM")
    else:
        print("NULL\n")
        ipIdholder.append("NULL")
    

def port80Scan(pkt, ip):
    ans,unans = sr(pkt, timeout=10)
 

    if len(ans) > 0:
        if ans[0][1].haslayer(TCP)==1:
            ans.summary( lambda s,r : r.sprintf("%IP.src% is alive and port 80 is open\n") )
            portscanholder.append("OPEN")
            print(ans[0][0][0].window, 'is the window size\n')
            ttlTypeholder.append(ans[0][0][0].window)

            ans, unans = srloop(pkt, count=10)
            #ans.summary( lambda s,r: r.sprintf("%IP.src%\t{ICMP:%ICMP.type%}\t{TCP:%TCP.DI%}"))
            val = [a[1].id for a in ans]
            print(val)
                
            if(len(val) >=3):
                if int(val[0])+1==int(val[1]) and int(val[1])+1==int(val[2]) :
                    print("Its Incremental\n")
                    ipIdtcpholder.append("INCREMENTAL")
                elif val[0]==val[1] and val[1]==val[2]:
                    print("Its Zero\n")
                    ipIdtcpholder.append("ZERO")
                else:
                    print("Its Random\n")
                    ipIdtcpholder.append("RANDOM")
            else:
                print("NULL\n")
                ipIdtcpholder.append("NULL")


    #### FIX THIS I NEED TOOO GO OVER ANSD CHECK FOR SYN COOKIES IDK HOW TO DO IT THO I NEED TO FIND OTU
            pkt1 = IP(dst=ip)/TCP(dport=80, flags="S")
            #pkt = IP(dst="94.240.49.126")/TCP(dport=80, flags="S")
            ans= send(pkt1)

            pkts = sniff(prn=lambda x:x.summary(), timeout=60, filter="tcp and port 80 and host %s\n" % ip )
            countTCP = 0    

            for i in range(0,len(pkts)):

                pkt2 = pkts[0]
                if (TCP in pkt2):
                        countTCP+= 1
            #print(pkts)
            print(countTCP)

            if countTCP > 1:
                print("SYN-COOKIES ARE NOT DEPLOYED\n")
                syncookieholder.append("NOT-DEPLOYED")
            elif countTCP == 0:
                print("NO REPONCE! \n")
                syncookieholder.append("NO-RESPONCE")
            else:
                print("SYN-COOKIES DEPLOYED\n")
                syncookieholder.append("DEPLOYED")
        #31.43.161.190


        #94.240.49.126
            
        else:
            print("port 80 seems to be unresponsive\n")
            portscanholder.append("CLOSED")
            ipIdtcpholder.append("CLOSED-PORT")
            syncookieholder.append("CLOSED-PORT")
            ttlTypeholder.append("CLOSED-PORT")
    else:
        print("port 80 seems to be unresponsive\n")
        portscanholder.append("CLOSED")
        ipIdtcpholder.append("CLOSED-PORT")
        syncookieholder.append("CLOSED-PORT")
        ttlTypeholder.append("CLOSED-PORT")
    
typeofOS = []
typeofOSFAM = []

def chooseOS():
    for i in range(len(ttlholder)):
        #print(ipholder[i])
        #print(ttlTypeholder[i])
        #print(ttlholder[i])

        if ttlholder[i] == "NULL":
            typeofOS.append("NULL")
            typeofOSFAM.append("NULL")
            continue
        #if str(ttlTypeholder[i]) == "CLOSED-PORT" or str(ttlTypeholder[i])=="NULL"

        if ttlTypeholder[i] == "CLOSED-PORT":
            #print("@@@@@@@@@@@@@@@@@@@@ CLOSED PORT PART")
            if int(ttlholder[i]) <= 63:
                typeofOS.append("Linux Most likely")
                typeofOSFAM.append("LINUX")
                #print("Linux Most Likely")
            elif int(ttlholder[i]) <= 127 and int(ttlholder[i])>=64:
                typeofOS.append("Windows Most likely")
                typeofOSFAM.append("WINDOWS")
                #print("Windows Most Likely")
            elif int(ttlholder[i]) <= 254 and int(ttlholder[i])>=128:
                typeofOS.append("Cisco-Router Most likely")
                typeofOSFAM.append("CISCO")
                #print("Cisco Router Most Likely")
        else:
            #print("@@@@@@@@@@@@@@@@@@@@ NOT CLOSED PORT PART")
            if int(ttlholder[i]) <= 63 and int(ttlTypeholder[i]) == 5840:
                typeofOS.append("Linux 2.4 and 2.6")
                typeofOSFAM.append("LINUX")
                #print("Linux 2.4 and 2.6")
            elif int(ttlholder[i]) <= 63 and int(ttlTypeholder[i]) == 5720:
                typeofOS.append("Google Customized Linux")
                typeofOSFAM.append("LINUX")
                #print("Google Customized Linux")
            elif int(ttlholder[i]) <= 63 and int(ttlTypeholder[i]) == 32120:
                typeofOS.append("Linux kernal 2.2")
                typeofOSFAM.append("LINUX")
                #print("Linux kernal 2.2")
            elif int(ttlholder[i]) <= 63 and int(ttlTypeholder[i]) == 65535:
                typeofOS.append("FreeBSD or MAC")
                typeofOSFAM.append("LINUX")
                #print("FreeBSD or MAC") 
            elif int(ttlholder[i]) <= 63 and int(ttlTypeholder[i]) == 16384:
                typeofOS.append("OpenBSD, AIX 4.3")
                typeofOSFAM.append("LINUX")
                #print("OpenBSD, AIX 4.3")        
            elif int(ttlholder[i]) <= 127 and int(ttlholder[i])>=64 and int(ttlTypeholder[i]) == "16384":
                typeofOS.append("Windows 2000")
                typeofOSFAM.append("WINDOWS")
                #print("Windows 2000")
            elif int(ttlholder[i]) <= 127 and int(ttlholder[i])>=64 and int(ttlTypeholder[i]) == "65535":
                typeofOS.append("Windows XP")
                typeofOSFAM.append("WINDOWS")
                #print("Windows XP")
            elif int(ttlholder[i]) <= 127 and int(ttlholder[i])>=64 and int(ttlTypeholder[i]) == "8192":
                typeofOS.append("Windows 7, Vista, and Server 8")
                typeofOSFAM.append("WINDOWS")
                #print("Windows 7, Vista, and Server 8")
            elif int(ttlholder[i]) <= 254 and int(ttlholder[i])>=128 and int(ttlTypeholder[i]) == "4128":
                typeofOS.append("Cisco Router IOS 12.4")
                typeofOSFAM.append("CISCO")
               #print("Cisco Router IOS 12.4")
            elif int(ttlholder[i]) <= 254 and int(ttlholder[i])>=128 and int(ttlTypeholder[i]) == "8760":
                typeofOS.append("Solaris 7")
                typeofOSFAM.append("LINUX")
                #print("Solaris 7") 
            else:
                if int(ttlholder[i]) <= 63:
                    typeofOS.append("Linux Most likely")
                    typeofOSFAM.append("LINUX")
                elif int(ttlholder[i]) <= 127 and int(ttlholder[i])>=64:
                    typeofOS.append("Windows Most likely")
                    typeofOSFAM.append("WINDOWS")
                    #print("Windows Most Likely")
                elif int(ttlholder[i]) <= 254 and int(ttlholder[i])>=128:
                    typeofOS.append("Cisco-Router Most likely")
                    typeofOSFAM.append("CISCO")
                    #print("Cisco Router Most Likely")
            
        

def statCheck():
    reponceVal = 0
    ipIDICMP_ZERO = 0
    ipIDICMP_INCREMENTAL = 0
    ipIDICMP_RANDOM = 0
    portVal = 0
    ipIDTCP_ZERO = 0
    ipIDTCP_INCREMENTAL = 0
    ipIDTCP_RANDOM = 0
    cookiesVal = 0
    linuxDev = 0
    windowsDev = 0

    for i in range(len(ipholder)):
        if pingresponceholder[i] == "ON":
            reponceVal += 1
        if ipIdholder[i] == "INCREMENTAL":
            ipIDICMP_INCREMENTAL += 1
        if ipIdholder[i] == "ZERO":
            ipIDICMP_ZERO += 1    
        if ipIdholder[i] == "RANDOM":
            ipIDICMP_RANDOM += 1  
        if portscanholder[i] == "OPEN":
            portVal += 1
        if ipIdtcpholder[i] == "INCREMENTAL":
            ipIDTCP_INCREMENTAL += 1
        if ipIdtcpholder[i] == "ZERO":
            ipIDTCP_ZERO += 1    
        if ipIdtcpholder[i] == "RANDOM":
            ipIDTCP_RANDOM += 1  
        if syncookieholder[i] == "DEPLOYED":
            cookiesVal+=1
        if typeofOSFAM[i] == "LINUX":
            linuxDev+=1
        if typeofOSFAM == "WINDOWS":
            windowsDev+=1
    
    print(reponceVal/len(ipholder) * 100)
    print(ipIDICMP_ZERO/len(ipholder) * 100)
    print(ipIDICMP_INCREMENTAL/len(ipholder) * 100)
    print(ipIDICMP_RANDOM/len(ipholder) * 100)
    print(portVal/len(ipholder) * 100)
    print(ipIDTCP_ZERO/len(ipholder) * 100)
    print(ipIDTCP_INCREMENTAL/len(ipholder) * 100)
    print(ipIDTCP_RANDOM/len(ipholder) * 100)
    print(cookiesVal/len(ipholder) * 100)
    print(linuxDev/len(ipholder) * 100)
    print(windowsDev/len(ipholder) * 100)
    


    with open('shodanStatisitcs.csv', 'w', newline='') as file:
        fieldnames = ['IP-ADDRESS', 'PING-RESPONCE', 'IPID-ICMP', 'IPID-TCP', 'PORT-RESULT', 'COOKIES', 'TTL','WINDOW-SIZE','OS-TYPE','OS-FAMILY']

        otherfieldnames = ['RESPONCE%','ICMPID-ZERO%','ICMPID-INCREMENTAL%','ICMPID-RANDOM%','PORT-RESPONCE%','TCPID-ZERO%','TCPID-INCREMENTAL%','TCPID-RANDOM%','COOKIE-DEPLOYED%','LINUX%','WINDOWS%']
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        otherfie = [" "]

        writer.writeheader()
        for i in range(len(ipholder)):
            writer.writerow({'IP-ADDRESS': str(ipholder[i]), 'PING-RESPONCE': pingresponceholder[i], 'IPID-ICMP': ipIdholder[i], 'IPID-TCP':ipIdtcpholder[i], 'PORT-RESULT':portscanholder[i], 'COOKIES':syncookieholder[i], 'TTL':ttlholder[i],'WINDOW-SIZE':ttlTypeholder[i],'OS-TYPE':typeofOS[i],'OS-FAMILY':typeofOSFAM[i]})

        writer = csv.DictWriter(file, fieldnames=otherfie)
        writer.writeheader()

        writer = csv.DictWriter(file, fieldnames=otherfieldnames)
        writer.writeheader()
        writer.writerow({'RESPONCE%': reponceVal/len(ipholder) * 100, 'ICMPID-ZERO%': ipIDICMP_ZERO/len(ipholder) * 100, 'ICMPID-INCREMENTAL%': ipIDICMP_INCREMENTAL/len(ipholder) * 100, 'ICMPID-RANDOM%':ipIDICMP_RANDOM/len(ipholder) * 100, 'PORT-RESPONCE%':portVal/len(ipholder) * 100, 'TCPID-ZERO%':ipIDTCP_ZERO/len(ipholder) * 100,'TCPID-INCREMENTAL%':ipIDTCP_INCREMENTAL/len(ipholder) * 100, 'TCPID-RANDOM%':ipIDTCP_RANDOM/len(ipholder) * 100,'COOKIE-DEPLOYED%':cookiesVal/len(ipholder) * 100,'LINUX%':linuxDev/len(ipholder) * 100,'WINDOWS%':windowsDev/len(ipholder) * 100})

def main():
    with open('shodan_data.txt') as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        line_count = 0
        for row in csv_reader:
            row = row[0]

            # for i in ipholder:
            #     if row == i:
            #         print('G')
            #     else:
            #         continue
        
            x = False
            #print(str(row)[2:-2])
            #row = row[0]
            
            #print(row)

            #cahnge back to new IP IP 49
            #row = "80.6.205.21"
            ipholder.append(row)

            pkt = IP(dst=row)/ICMP()
            x=checkResponsive(pkt)
           
            if x == True:
                ipID(pkt)
                pkt = IP(dst=row)/TCP(dport=80, flags="S")
                port80Scan(pkt, row)
            else:
                continue

    
    chooseOS()       
    statCheck()
    #logging.getLogger("scapy").setLevel(logging.CRITICAL)
    #print(sys.argv[1])
    
# ipholder = []
# pingresponceholder = []
# ipIdholder = []
# portscanholder = []
# syncookieholder = []
# ttlholder = []

    # print("IP's")
    # print(ipholder)
    # print("Ping Reponce")
    # print(pingresponceholder)
    # print("IPID")
    # print(ipIdholder)
    # print("Tcp IPID")
    # print(ipIdtcpholder)
    # print("Port Results")
    # print(portscanholder)
    # print("Cookies")
    # print(syncookieholder)
    # print("TTL")
    # print(ttlholder)
    # print("Window Size")
    # print(ttlTypeholder)
    # print("Type of OS")
    # print(typeofOS)
    # print("Type of Family Of OS")
    # print(typeofOSFAM)


if __name__ == "__main__":
    main()








