import random
import matplotlib.pyplot as plt
import numpy as np
import math

sources = []                                         #PACKET GENERATING ENTITIES
dests=[]                                             #PACKET DESTINTION ADDRESSES
src="192.16.1."
dest = "16.23.127."
max_pktLen = 300             #maximum packet length
time = 0.0                      
tcp_mean = 10
max_src=20
max_dest=4
#poisson distribution variables
Lambda = 50                
k = 0

#Random gemeration of source and destination IP Addresses
for i in range(0,max_src):
   temp=src+str(random.randint(1,255))
   sources.append(temp);
   
for i in range(0,max_dest):
   temp=dest+str(random.randint(1,255))
   dests.append(temp);   

#MAPPING BETWEEN CURRENT PROTOCOL TO BE USED AND THE GENERATING USER
STAGE_OF_PACKETS = {}

user_limit=100
ID = 0
#LIST FOR PLOTTING PURPOSE
plot_data=[]
#maximum limit for poisson distribution
max_limit=1000       

#POISSON DISTRIBUTION ARRAY FOR EXPONENTIAL LENGTH
pdist=np.random.poisson(Lambda,max_limit)

"""
def poisson(Lambda,k):
   return (math.exp(-Lambda)*(Lambda**k))/math.factorial(k)

"""


#Packet Entity
class Packet:
  
  def __init__(self,pkt_len):
    global ID
    global time
    self.src_port = random.randint(30,65535)	
    self.dest_port = random.randint(30,65535); 	
    if self.dest_port == self.src_port :
       self.dest_port = self.dest_port + 1
    self.sIP = sources[random.randint(0,19)];
    self.dIP = dests[random.randint(0,3)]	
    self.pkt_len = pkt_len
    self.TTL = random.randint(2,8)                                      #Time To Live in milliseconds
    self.ID = ID
    ID += 1
    self.start_T = time                                                 #start time	
    self.end_T = time                                                   #end time

#def plotter():
      
#For setting status of sent packet
def set_status(pkt,Resp):
    STAGE_OF_PACKETS[pkt.ID]=(pkt,Resp)

#returns packet_length from poisson distribution
def poisson_dist():
   global k
   global max_limit
   global Lambda
   prob=pdist[k] 
   k=(k+1)%max_limit
   return prob

#Checks if TCP Packet can get through
def Int_TCP(packet):
    global tcp_mean
    rand=random.randint(0,14)
    print("\nTCP trying")
    var=np.random.poisson(5,15)[rand]                             #just random probability to get through  
    if(var > 5):                                              
      return 1
    else:
      return -1  

#Forwards the Packet for DNS Query        
def TCP(packet):
    global time
    print("\nDNS Query allowed!")
    time=time+random.uniform(0,1)
    packet.end_T=time
    

#Proviides NET Bios and service link     
def WINS(packet):
    global time
    time=time+random.uniform(0,1)
    packet.end_T=time
    set_status(packet,"WINS")
    print("Standard Query \"HEX_ADDR\" A isatap \n")
    packet=Packet(poisson_dist())
    hops=0
    ret=Int_TCP(packet)
    while ret <0 and hops<=5 :
       set_status(packet,"TCP Dump")
       hops+=1
       temp=packet
       time=time+random.uniform(0,1)
       packet=Packet(poisson_dist())
       packet.sIP=temp.sIP
       packet.dIP=temp.dIP
       packet.pkt_len=temp.pkt_len
       Int_TCP(packet) 
    if(ret<0 or hops>5):
       set_status(packet,"TCP Dump")
       return -1
    else:
       set_status(packet," TCP Done")        
       TCP(packet)
       return 1

#Pings(ICMP) to checck if the packet can be forwarded and gets router solicitation
def ping(packet):
    global time
    time=time+random.uniform(0,1)
    packet.end_T=time
    set_status(packet,"ICMP")
    print("Router SOlicitation\n")
    packet=Packet(poisson_dist())
    ret=WINS(packet)
    while ret < 0 and  (time-packet.start_T)<packet.TTL: 
       ret=WINS(packet) 
       time = time + pow(10,-1)
    if(ret<0 or (time-packet.start_T) > packet.TTL):
       return -1
    return 1

#Initiates the process of packet generation   
def generate_packet():
    global time
    packet=Packet(poisson_dist()) 
    ret=ping(packet)
    while ret < 0 and  (time-packet.start_T)<packet.TTL: 
       ret=ping(packet) 
       time = time + pow(10,-1)
    if(ret<0 or (time-packet.start_T) > packet.TTL):
       set_status(packet,"Ping Dumped")
      
for i in range(1,user_limit):
    generate_packet()

#Prints LIVE trace of traffic going through    
print ("ID \t sIP \t dIP \t src_port\tdest_port\t pkt_len \tTTL\tResp\n")
for i in STAGE_OF_PACKETS.keys():
    packet = STAGE_OF_PACKETS.get(i)[0];
    plot_data.append((packet.start_T,packet.pkt_len))
    resp = STAGE_OF_PACKETS.get(i)[1]
    print ("%d \t %s \t %s \t %d \t %d \t%d \t%d\t%s\n" %(packet.ID, packet.sIP, packet.dIP, packet.src_port, packet.dest_port,packet.pkt_len,packet.TTL,resp ))


plot_data=sorted(plot_data, key=lambda tup: tup[0])

#Plotting the data
x=[]
y=[]
for a in plot_data:
   x.append(a[0])
   y.append(a[1])  
plt.plot(x,y)
plt.show()

#For writing the data into trace file
fp=open("trace.txt","w")
fp.write("#PACKET TRACE:\n")
fp.write("\n\nData for Plotting\ntime  \t pkt_length  \n")
for a in plot_data:
  fp.write(str(a[0])+"\t"+str(a[1])+"\n")
fp.close()
