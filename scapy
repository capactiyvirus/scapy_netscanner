from scapy.all import *
import sys
import logging
import csv
import subprocess as sub




def checkResponsive(pkt):
    reply = sr1(pkt, timeout=5)
    if reply:
        print (reply.src, "is online\n")
        return True
    else:
        print ("Timeout waiting for %s \n" % pkt[IP].dst)
        return False


def ipID(pkt):
    
    ans, unans = srloop(pkt, count=6)
    val = [a[1].id for a in ans]
    #val = ans.filter(lambda x:x[1].id)
    

    print(val)
    

    
    if int(val[0])+1==int(val[1]) and int(val[1])+1==int(val[2]) and int(val[2])+1==int(val[3]):
        print("Its Incremental\n")
    elif val[0]==0 and val[1]==0 and val[2]==0:
        print("Its Zero\n")
    else:
        print("Its Random\n")
    

def port80Scan(pkt):
    ans, unans = sr(pkt, timeout=10)
    #pkts = sniff(prn=lambda x:x.summary(), timeout=60, filter="tcp")
    #val = ans.filter(lambda x:x[1])

    ans.show()

    if ans:
        ans.summary( lambda s,r : r.sprintf("%IP.src% is alive and port 80 is open\n") )

        ans, unans = srloop(pkt, count=6)
        #ans.summary( lambda s,r: r.sprintf("%IP.src%\t{ICMP:%ICMP.type%}\t{TCP:%TCP.DI%}"))
        val = [a[1].id for a in ans]
        print(val)
            

        if int(val[0])+1==int(val[1]) and int(val[1])+1==int(val[2]) and int(val[2])+1==int(val[3]) :
            print("Its Incremental\n")
        elif val[0]==0 and val[1]==0 and val[2]==0:
            print("Its Zero\n")
        else:
            print("Its Random\n")


#### FIX THIS I NEED TOOO GO OVER ANSD CHECK FOR SYN COOKIES IDK HOW TO DO IT THO I NEED TO FIND OTU
        pkt1 = IP(dst="94.240.49.126")/TCP(dport=80, flags="S")
        #pkt = IP(dst="94.240.49.126")/TCP(dport=80, flags="S")
        ans= send(pkt1)
        
        pkts = sniff(prn=lambda x:x.summary(), timeout=60, filter="tcp")
        print(pkts)
    #31.43.161.190


    #94.240.49.126
        #p = sub.Popen(['tcpdump','-l', '-v', '(dst port 80)'], stdout=sub.PIPE)
        #subprocess.check_output(['tcpdump', '-n', '(dst port 80)'])
        #for row in iter(p.stdout.readline, b''):
            #print (row.rstrip() )  # process here

        #print(pkts)
        #val = [a for a in ans]
        #print(unans[15][0])
        #val1 = [a for a in ans]
        #print(ans)
        #Sans.summary()
          
     

    else:
        print("port 80 seems to be unresponsive\n")
    


   


def main():
    # with open('shodan_data.txt') as csv_file:
    #     csv_reader = csv.reader(csv_file, delimiter=',')
    #     line_count = 0
    #     for row in csv_reader:
            x = False
            pkt = IP(dst="94.240.49.126")/ICMP()
            x=checkResponsive(pkt)
            #print(x)
            #if x == True:
                #print("@@@@@@@@@@@@@")
            ipID(pkt)
            pkt = IP(dst="94.240.49.126")/TCP(dport=80, flags="S")
            port80Scan(pkt)
            #else:
                #continue
           
    
    #logging.getLogger("scapy").setLevel(logging.CRITICAL)
    #print(sys.argv[1])
    

if __name__ == "__main__":
    main()








