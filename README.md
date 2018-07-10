# scapy-mitm

Small python script using Scapy to do ARP poisoning and redirection of IP addresses using Linux's 
built in Iptables to perform a MITM attack. Currently, this has had *limited testing*, meaning beware 
if it doesn't work. Also, this messes up  rules for your Iptable config, so be careful if you care about 
that sort of thing. FOR EDUCATIONAL PURPOSES ONLY. The author takes no responsibility for any use of 
this software, and it is most likely illegal to use this on networks you do not own. Cheers, Maxwell. 
Let me know if anything is broken though mbland@eng.ucsd.edu or an issue posted to this repo.

## Usage

Since TCP is a serial protocol, managing when messages from point to point are *done*, or the two sides 
are finished communicating, is dependent on the types of messages being passed. I've defined a DATA_MESSAGE_END
and a DATA_TRANSMIT_END  in tcp_MITM.py, but you will most likely need to tweak this so the tcp connection closes when it needs to.

## TODO
- Clean up code 
- Terminate threads gracefully with KeyboadInterrupt
- Adjust startup of tcp_MITM to include a manual mode, which doesn't try to dynamically set up a server 
*after* the first SYN packet

Version 0.2.0b
