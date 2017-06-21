#!/usr/bin/python
#coding:utf-8
#Author:LSA
#Description:comprehensive scanner lsascan_v1
#Date:20170315

import sys,thread,time,platform,os,datetime
import optparse

from socket import *
import threading

from scapy.all import srp,Ether,ARP,conf

screenLock = threading.Semaphore(value=1)

global p
p = -1


def tcp_scan(target_ip,port):
    try:
        sock = socket(AF_INET,SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((target_ip,port))
        screenLock.acquire()
        print port
    except:
        screenLock.acquire()
    finally:
        screenLock.release()
        sock.close()

def connScan(tgtHost, port):

    try:
        
        connSkt = socket(AF_INET, SOCK_STREAM)
        connSkt.settimeout(1)
        connSkt.connect((tgtHost, port))
        screenLock.acquire()
            
        #connSkt.send('onlytest\r\n')
        #results = connSkt.recv(100)
            
        print '[+] %d/tcp open' % port
        #print '[+] ' + str(results)
              
    except:
        screenLock.acquire()
        
    finally:
        
        screenLock.release()
        connSkt.close()
        
   
class sniff(threading.Thread):
    def __init__(self,target_ip):
        threading.Thread.__init__(self)
        self.target_ip = target_ip

    def run(self):
        global mutex,portBegin,portEnd
        while True:
            mutex.acquire()
            portBegin += 1
            if portBegin > portEnd:
                mutex.release()
                break
            mutex.release()
            tcp_scan(self.target_ip,portBegin)
            

def portscan(tgtHost, ports):

    setdefaulttimeout(1)
    global p

    portnums = len(ports)
    while True:
        
        screenLock.acquire()
        p = p + 1
        if p >= portnums:
            screenLock.release()
            break
        screenLock.release()
        connScan(tgtHost,int(ports[p]))
        
        
        
      

def get_os():
    os = platform.system()
    if os == "Windows":
        return "n"
    else:
        return "c"

def ping_ip(ip_str):
    cmd = ["ping", "-{op}".format(op=get_os()),
           "1", ip_str]
    output = os.popen(" ".join(cmd)).readlines() 
    flag = False
    for line in list(output):
        if not line:
            continue
        if str(line).upper().find("TTL") >=0:
            flag = True
            break
    if flag:
        activeiplist.append(ip_str)

def find_ip(ip_prefix):
    for i in range(1,256):
        ip = '%s.%s'%(ip_prefix,i)
        thread.start_new_thread(ping_ip, (ip,))
        time.sleep(0.3)


if __name__=='__main__':
    global mutex,portBegin,portEnd,portslist,activeiplist
    portslist = []
    threadlist = []
    activeiplist = []
    
    parser = optparse.OptionParser('usage %prog '+\
      '-H <target host> -p <target port[s]> [-n] [<target network>]')
    parser.add_option('-H', dest='tgtHost', type='string',\
      help='specify target host')
    parser.add_option('-p', dest='port', type='string',\
      help='specify port range or separate port[s]',metavar='1-100[1,2,3]')
    parser.add_option('-n', dest='net', type='string',\
      help='specify target network',metavar='192.168.0')
    parser.add_option('-t', dest='threads', type='int',\
      help='specify thread nums,default 10',metavar='20',default=10)
    
    (options, args) = parser.parse_args()
    port = options.port
    tgthost = options.tgtHost
    threads = options.threads

    
    
    

    if (port) and (tgthost):

        try:
            tgtip = gethostbyname(tgthost)
        except:
            print "[-] Cannot resolve '%s': Unknown host" %tgthost
            sys.exit(1)

        try:
            tgtName = gethostbyaddr(tgtip)
            print '\n[+] Scan Results for: ' + tgtName[0]
        except:
            print '\n[+] Scan Results for: ' + tgtip

        if ',' not in port and '-' not in port:   #only one port
            ports = port.split('AAAAAAAAAAAAAAA')
            portscan(tgthost,ports)
            
        else:
            
            ports = port.split(',')   #ports---list
            if len(ports)==1:   #port list
                global mutex, portBegin, portEnd
            
                ports = ports[0].split('-')
                portBegin = int(ports[0]) - 1
                portEnd = int(ports[1])
                mutex = threading.Lock()
                start = time.clock()
                for th in range(threads):
                    thread = sniff(tgthost)
                    thread.start()
                    threadlist.append(thread)
                for t in threadlist:
                    t.join()
                end = time.clock()
                print end - start
                
            
            else:   #port set
                start = time.clock()
                for thread in range(threads):
                    t = threading.Thread(target=portscan,args=(tgthost,ports))
                    t.start()
                    threadlist.append(t)
                for thr in threadlist:
                    thr.join()
                end = time.clock()
                print end - start

            
            
        
    if options.net:   #must use root

        scanlan = options.net
        print "start time %s"%time.ctime()
        print "scanning %s.1-255:\n"%scanlan
    	print "--------------"
        starttime = datetime.datetime.now()
        #find_ip(scanlan)
        macscan = '%s.1/24' %scanlan
        try:
            ans,unans = srp(Ether(dst="FF:FF:FF:FF:FF:FF")/ARP(pdst=macscan),timeout=5,verbose=False)
        except Exception,e:
            print str(e)
        else:
        	for snd,rcv in ans:
                    list_mac = rcv.sprintf("%Ether.src% - %ARP.psrc%")
                    print list_mac
    #for activeip in activeiplist:
    #   print activeip
        endtime = datetime.datetime.now()
    	print "---------------"
        print "end time %s"%time.ctime()
        print "total use %s s"%(endtime - starttime).total_seconds()