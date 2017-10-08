name: Hubert Hsiung  
email: hhsiung@ucsd.edu  
pid: A10795582  
George Varghese Espresso prize: No  

Note: I didn't change any of the base files, I just accidentally pushed
      them lol.

------------------------------------------------------------------
Design Decisions:

I manipulated 2 files for this project: sr_router and sr_arpcache

sr_router.h/sr_router.c:
sr_handlepacket deals with almost the entire part of the program
implemented by me. I broke the function further down to handleARP and
handleIP to isolate the code for dealing with ARP or IP/ICMP respectively.

For ARP packets, if it's a ARP request, we'll just simply send a ARP
reply back by changing the destination and source. If it's an ARP reply
we can cache the given MAC and forward all packets waiting for the reply.

For IP(ICMP) packets, we first check who the packet is for. If it's for
us, great, we check if it's a ping (echo request) or tcp/udp and if it's
a ping, we echo reply, if it's tcp/udp we send a ICMP type 3 port unreachable.
If it's not for us, however, it's a lot more complicated. We first 
check if the packet expires by checking the time to live. If it's 1 or 
below, we decrement it and send a ICMP type 11 time exceed. Else we do
a LPM chekc followed by a ARP cache lookup, if we can't find the address,
we can put it in a queue and send a ARP request for it. But if the LPM
fails with NULL from the routing table, we will send a ICMP type 3 network
unreachable. Finally, if the ARP cache lookup succeeded, we call handle_arpreq
mentioned below to properly manage everything.

sr_arpcache.h/sr_arpcache.c
sweep gets called every second to broadcast ARP requests. This is assisted
with handle_arpreq which does the actual work by sending every second upto
5 times, which then will just send an ICMP type 3 host unreachable.
  
  
------------------------------------------------------------------
Tradeoffs:

One major tradeoff I decided on was to make the data structures for 
ICMP type 0 and ICMP type 3 in addition to ICMP type 11. While I 
understand that it is possible to accomplish both data structures 
with some manipulation to type 11 ICMP, I thought all the memory 
manipulation involved in the process could potentially cause hardships 
during the debugging stage. To save the trouble, I just implemented 
type 0 and type 3 ICMP data structures as they are suppose to be 
constructed (type 0 has way less stuff, type 3 has next_mtu). The 
tradeoff is that, I made my code longer and requires a tiny bit of 
extra storage to store these data structures, but I believe simplifying 
my code has a very great benefit especially in a relatively big project 
like this.


------------------------------------------------------------------
Last words:

Thank you Professor Snoeren, Shreeja, Brajesh, and Victor for a 
great quarter. :)
