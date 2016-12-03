# ostware-services\Software_Engineer

got a task 18-06-2015;
completed and sent 23-06-2015;

Test Task 2

Platform	Linux (kernel 2.6) – Ubuntu 10.04 
           		Linux (kernel 3.2) – Ubuntu 12.04

tcpdump utility (wireshark, ethereal) – to learn to use; based on libpcap.

Objective: using C, write an analogue of tcpdump (console application) which analyzes all packages that meet the specified criteria (like source/ destination MAC, source/ destination IP address, source/destination port), and keeps the following statistics:
	
·	List of all MAC addresses of the packages; quantity of packages sent to/from a specified MAC address.
·	List of all IP addresses of the packages; quantity of TCP and UDP packages sent.

Demand: Possibility of binding to a specified network interface (eth0).
Tip: Without binding to a specified network interface(ethX) it might be impossible to obtain all the packages that pass through the network. Linux may have different interfaces not only ethX!

To use:
gcc, make, libpcaps sources, ifconfig command.
